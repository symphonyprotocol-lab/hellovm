from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Iterator, Mapping
from types import TracebackType
from typing import Any, Literal

from . import _retry
from ._http import Abort, AbortedError, Response, Transport
from ._model import (
    ExecResult,
    ExecStatus,
    ExposedPort,
    Ingress,
    OmittedEvent,
    OutputEvent,
    Poll,
    ResultEvent,
    SandboxInfo,
    StreamEvent,
    Template,
    TenantUsage,
    parse_ingress,
    parse_json,
    parse_poll,
    parse_result,
    parse_sandbox,
    parse_status,
    parse_template,
    parse_usage,
)
from .errors import (
    APIError,
    HellovmError,
    LimitError,
    NotFoundError,
    ResponseError,
    SandboxEndedError,
    TransportError,
    api_error,
    retry_after,
)

#: The API's limits the SDK checks before sending (so that a 17 MiB upload
#: is refused without sending it).
MAX_FILE = 16 << 20
#: The API's default exec timeout, seconds.
DEFAULT_EXEC_TIMEOUT = 60.0
#: How much longer than the exec's own timeout a request waits for its
#: answer (the node allows the exec its timeout plus 10 s).
EXEC_MARGIN = 30.0
#: Longest a poll waits on the server (the API's limit is 30 s).
POLL_WAIT = 25.0
POLL_MARGIN = 15.0

_SEGMENT = re.compile(r"[A-Za-z0-9._~-]{1,128}")
BusyPolicy = Literal["wait", "raise"]


def _segment(value: str, what: str) -> str:
    if not isinstance(value, str) or not _SEGMENT.fullmatch(value):
        raise ValueError(f"malformed {what}: {value!r}")
    return value


class Client:
    """A client of one hellovm API with one tenant's token.

    ``timeout`` bounds every request that does not run an exec (seconds;
    the whole exchange). ``busy`` says what a request does when its
    sandbox is busy with another one (``409 busy``): ``"wait"`` (the
    default) tries again with backoff until ``busy_timeout`` seconds have
    passed, ``"raise"`` raises :class:`BusyError` at once.
    ``max_response_bytes`` bounds every answer. Thread-safe.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 60.0,
        busy: BusyPolicy = "wait",
        busy_timeout: float = 120.0,
        retries: int = 2,
        max_response_bytes: int = 32 << 20,
    ) -> None:
        if not isinstance(token, str) or not token or any(not (0x21 <= ord(c) <= 0x7E) for c in token):
            raise ValueError("the token must be printable ASCII without spaces")
        if busy not in ("wait", "raise"):
            raise ValueError('busy must be "wait" or "raise"')
        if not (timeout > 0 and busy_timeout >= 0 and retries >= 0 and max_response_bytes >= 1024):
            raise ValueError("timeouts, retries and max_response_bytes must be positive")
        self._transport = Transport(base_url, max_response_bytes)
        self._auth = f"Bearer {token}"
        self.base_url = base_url
        self.timeout = timeout
        self.busy: BusyPolicy = busy
        self.busy_timeout = busy_timeout
        self.retries = retries

    @classmethod
    def from_env(cls, **options: Any) -> Client:
        """A client from ``HELLOVM_URL`` and ``HELLOVM_TOKEN``."""
        url = os.environ.get("HELLOVM_URL")
        token = os.environ.get("HELLOVM_TOKEN")
        if not url or not token:
            raise ValueError("set HELLOVM_URL and HELLOVM_TOKEN")
        return cls(url, token, **options)

    def __repr__(self) -> str:  # never the token
        return f"Client({self.base_url!r})"

    def close(self) -> None:
        """Closes the kept-alive connections."""
        self._transport.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- requests ------------------------------------------------------

    def _request(
        self,
        method: str,
        target: str,
        *,
        body: bytes = b"",
        json_body: Any = None,
        expect: tuple[int, ...] = (200,),
        timeout: float | None = None,
        idempotent: bool,
        poll: bool = False,
        abort: Abort | None = None,
        gone_after_retry_ok: bool = False,
    ) -> Response:
        headers = {"Authorization": self._auth, "Accept": "application/json", "User-Agent": "hellovm-python/0.0.1"}
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif method == "PUT":
            headers["Content-Type"] = "application/octet-stream"
        started = time.monotonic()
        failures = 0
        waits = 0
        while True:
            try:
                response = self._transport.request(
                    method, target, headers=headers, body=body, timeout=timeout or self.timeout, abort=abort
                )
            except AbortedError:
                raise
            except TransportError as e:
                if failures >= self.retries or not _retry.transport_retry(e, idempotent):
                    raise
                failures += 1
                _sleep(_retry.delay(failures - 1), abort)
                continue
            if response.status in expect:
                return response
            if gone_after_retry_ok and failures and response.status == 404:
                # A retried DELETE whose first try was carried out.
                return response
            error = api_error(response.status, response.body, retry_after(response.headers.get("retry-after")))
            if _retry.status_retry(error.status, error.code, busy_wait=self.busy == "wait", poll=poll):
                pause = max(_retry.delay(waits), error.retry_after or 0.0)
                if time.monotonic() + pause - started <= self.busy_timeout:
                    waits += 1
                    _sleep(pause, abort)
                    continue
            raise error

    def _json(self, response: Response) -> Any:
        return parse_json(response.body)

    # -- templates and sandboxes ---------------------------------------

    def templates(self) -> list[Template]:
        d = self._json(self._request("GET", "/v1/templates", idempotent=True))
        items = d.get("templates") if isinstance(d, dict) else None
        if not isinstance(items, list):
            raise ResponseError("templates: expected a list")
        return [parse_template(t) for t in items]

    def create(
        self,
        template: str = "python",
        *,
        idle_timeout: float | None = None,
        lifetime: float | None = None,
    ) -> Sandbox:
        """Makes a sandbox from a template. Use it as a context manager to
        delete it at the end of the block. Not retried after an ambiguous
        failure (it could make a second sandbox)."""
        request: dict[str, Any] = {"template": template}
        if idle_timeout is not None:
            request["idle_timeout"] = idle_timeout
        if lifetime is not None:
            request["lifetime"] = lifetime
        r = self._request("POST", "/v1/sandboxes", json_body=request, expect=(201,), idempotent=False)
        info = parse_sandbox(self._json(r))
        _segment(info.id, "sandbox id")
        return Sandbox(self, info.id, info)

    def list(self) -> list[SandboxInfo]:
        d = self._json(self._request("GET", "/v1/sandboxes", idempotent=True))
        items = d.get("sandboxes") if isinstance(d, dict) else None
        if not isinstance(items, list):
            raise ResponseError("sandboxes: expected a list")
        return [parse_sandbox(s) for s in items]

    def usage(self) -> TenantUsage:
        """This tenant's usage in the current metering period, its quotas,
        and the budgets it used up."""
        return parse_usage(self._json(self._request("GET", "/v1/usage", idempotent=True)))

    def get(self, sandbox_id: str) -> Sandbox:
        """The sandbox, with its description fetched now."""
        sandbox = self.sandbox(sandbox_id)
        sandbox.refresh()
        return sandbox

    def sandbox(self, sandbox_id: str) -> Sandbox:
        """A handle on a sandbox by id, without a request."""
        return Sandbox(self, _segment(sandbox_id, "sandbox id"), None)

    def delete(self, sandbox_id: str) -> None:
        """Deletes a sandbox. A retry of a delete whose first answer was
        lost may find it gone already: that is success. When its node does
        not answer, the API accepts the delete (``202``) and does it on the
        node later; the sandbox is gone for this tenant at once."""
        target = f"/v1/sandboxes/{_segment(sandbox_id, 'sandbox id')}"
        self._request("DELETE", target, expect=(204, 202, 200), idempotent=True, gone_after_retry_ok=True)


def _sleep(seconds: float, abort: Abort | None) -> None:
    if abort is not None and abort.aborted:
        raise AbortedError("aborted", maybe_sent=False)
    time.sleep(seconds)
    if abort is not None and abort.aborted:
        raise AbortedError("aborted", maybe_sent=False)


class Sandbox:
    """One sandbox. A context manager: the sandbox is deleted when the
    block ends, also when it raises."""

    def __init__(self, client: Client, sandbox_id: str, info: SandboxInfo | None) -> None:
        self.client = client
        self.id = sandbox_id
        #: The description as last fetched (``None`` for a bare handle).
        self.info = info

    def __repr__(self) -> str:
        return f"Sandbox({self.id!r})"

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.delete()
        except (NotFoundError, SandboxEndedError):
            pass
        except HellovmError:
            if exc is None:
                raise
            # The block's own exception matters more; this one stays
            # attached as its __context__.

    def _path(self, rest: str = "") -> str:
        return f"/v1/sandboxes/{self.id}{rest}"

    def refresh(self) -> SandboxInfo:
        """Fetches the description again (``410`` once it ended)."""
        r = self.client._request("GET", self._path(), idempotent=True)
        self.info = parse_sandbox(parse_json(r.body))
        return self.info

    def delete(self) -> None:
        self.client.delete(self.id)

    # -- execs ---------------------------------------------------------

    @staticmethod
    def _exec_request(
        *,
        command: str | None = None,
        python: str | None = None,
        stateful: bool = False,
        timeout: float | None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | None = None,
        max_output: int | None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {}
        if command is not None:
            request["command"] = command
        if python is not None:
            request["python"] = python
        if stateful:
            request["stateful"] = True
        if timeout is not None:
            request["timeout"] = timeout
        if cwd is not None:
            request["cwd"] = cwd
        if env is not None:
            request["env"] = dict(env)
        if stdin is not None:
            request["stdin"] = stdin
        if max_output is not None:
            request["max_output"] = max_output
        return request

    def _exec(self, request: dict[str, Any]) -> ExecResult:
        timeout = float(request.get("timeout", DEFAULT_EXEC_TIMEOUT)) + EXEC_MARGIN
        r = self.client._request("POST", self._path("/exec"), json_body=request, timeout=timeout, idempotent=False)
        return parse_result(parse_json(r.body))

    def exec(
        self,
        command: str,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | None = None,
        max_output: int | None = None,
    ) -> ExecResult:
        """Runs ``command`` with ``/bin/sh -c`` and returns when it ended.
        ``timeout`` (seconds, default 60, at most 3600) kills it; each
        output stream keeps ``max_output`` bytes (default 64 KiB). Never
        sent twice: after a failure without an answer it may or may not
        have run (:class:`TransportError` with ``maybe_sent``)."""
        return self._exec(
            self._exec_request(command=command, timeout=timeout, cwd=cwd, env=env, stdin=stdin, max_output=max_output)
        )

    def python(
        self,
        code: str,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | None = None,
        max_output: int | None = None,
    ) -> ExecResult:
        """Runs Python source in a fresh fork of the sandbox's warm
        interpreter (nothing is kept afterwards)."""
        return self._exec(
            self._exec_request(python=code, timeout=timeout, cwd=cwd, env=env, stdin=stdin, max_output=max_output)
        )

    def run(
        self,
        code: str,
        *,
        timeout: float | None = None,
        stdin: str | None = None,
        max_output: int | None = None,
    ) -> ExecResult:
        """Runs Python source in the sandbox's stateful interpreter, whose
        variables, imports and objects persist between calls. ``value`` is
        the ``repr`` of the last expression (if not None), ``error`` the
        exception raised, ``state_lost`` whether the state was lost."""
        return self._exec(
            self._exec_request(python=code, stateful=True, timeout=timeout, stdin=stdin, max_output=max_output)
        )

    def stream(
        self,
        command: str,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | None = None,
        max_output: int | None = None,
        poll_bytes: int | None = None,
    ) -> Execution:
        """Starts ``command`` and returns an :class:`Execution` to iterate
        over: its output events as they come, then a :class:`ResultEvent`."""
        request = self._exec_request(
            command=command, timeout=timeout, cwd=cwd, env=env, stdin=stdin, max_output=max_output
        )
        return self._start(request, poll_bytes)

    def stream_python(
        self,
        code: str,
        *,
        stateful: bool = False,
        timeout: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | None = None,
        max_output: int | None = None,
        poll_bytes: int | None = None,
    ) -> Execution:
        """Starts Python source (in a fresh fork, or with ``stateful`` in
        the stateful interpreter) as an :class:`Execution`."""
        request = self._exec_request(
            python=code, stateful=stateful, timeout=timeout, cwd=cwd, env=env, stdin=stdin, max_output=max_output
        )
        return self._start(request, poll_bytes)

    def _start(self, request: dict[str, Any], poll_bytes: int | None) -> Execution:
        if poll_bytes is not None and not (1024 <= poll_bytes <= 1 << 20):
            raise ValueError("poll_bytes must be 1024 to 1048576")
        r = self.client._request("POST", self._path("/execs"), json_body=request, expect=(201,), idempotent=False)
        status = parse_status(parse_json(r.body))
        return Execution(self, _segment(status.exec_id, "exec id"), poll_bytes)

    def latest_exec(self) -> ExecStatus | None:
        """The sandbox's latest exec (the only one it keeps), if any."""
        r = self.client._request("GET", self._path("/execs"), idempotent=True)
        d = parse_json(r.body)
        items = d.get("execs") if isinstance(d, dict) else None
        if not isinstance(items, list):
            raise ResponseError("execs: expected a list")
        return parse_status(items[0]) if items else None

    def reset_python(self) -> bool:
        """Discards the stateful interpreter; whether there was one."""
        r = self.client._request("POST", self._path("/python/reset"), idempotent=False)
        d = parse_json(r.body)
        if not isinstance(d, dict) or not isinstance(d.get("had_state"), bool):
            raise ResponseError("reset: expected had_state")
        return bool(d["had_state"])

    # -- ingress -------------------------------------------------------

    @staticmethod
    def _port(port: int) -> int:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("a port is 1 to 65535")
        return port

    def ingress(self) -> Ingress:
        """The sandbox's ingress token and exposed ports (with their URLs)."""
        r = self.client._request("GET", self._path("/ingress"), idempotent=True)
        return parse_ingress(parse_json(r.body))

    def expose(self, port: int, *, public: bool = False) -> ExposedPort:
        """Makes ``port`` reachable from outside (a server in the sandbox
        must listen on it, on ``0.0.0.0``); it needs the ingress token
        unless ``public``. Calling it again changes ``public``. Returns
        the port with its URL."""
        port = self._port(port)
        r = self.client._request(
            "PUT",
            self._path(f"/ingress/ports/{port}"),
            json_body={"public": bool(public)},
            idempotent=True,
        )
        for p in parse_ingress(parse_json(r.body)).ports:
            if p.port == port:
                return p
        raise ResponseError("expose: the port is not in the answer")

    def unexpose(self, port: int) -> None:
        """Makes ``port`` unreachable from outside again (connections
        already made go on)."""
        port = self._port(port)
        self.client._request("DELETE", self._path(f"/ingress/ports/{port}"), idempotent=True)

    def rotate_ingress_token(self) -> str:
        """Replaces the ingress token with a new one, at once; returns it."""
        r = self.client._request("POST", self._path("/ingress/token"), idempotent=False)
        return parse_ingress(parse_json(r.body)).token

    # -- files ---------------------------------------------------------

    @staticmethod
    def _check_path(path: str) -> str:
        if not isinstance(path, str) or not path or "\0" in path or len(path.encode()) > 4096:
            raise ValueError("a path must be 1 to 4096 bytes without NUL bytes")
        return urllib.parse.quote(path, safe="")

    def read_file(self, path: str) -> bytes:
        """The file's bytes (at most 16 MiB). Relative paths are relative
        to the sandbox's home."""
        r = self.client._request("GET", self._path(f"/files?path={self._check_path(path)}"), idempotent=True)
        return r.body

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read_file(path).decode(encoding)

    def write_file(self, path: str, data: bytes | str) -> int:
        """Writes the file (creating parent directories), replacing it
        whole; returns the bytes written. Never sent twice."""
        raw = data.encode() if isinstance(data, str) else bytes(data)
        if len(raw) > MAX_FILE:
            raise LimitError(413, "too_large", f"a file is at most {MAX_FILE} bytes")
        r = self.client._request(
            "PUT", self._path(f"/files?path={self._check_path(path)}"), body=raw, idempotent=False
        )
        d = parse_json(r.body)
        if not isinstance(d, dict) or isinstance(d.get("bytes"), bool) or not isinstance(d.get("bytes"), int):
            raise ResponseError("write: expected bytes")
        return int(d["bytes"])

    def edit_file(self, path: str, old: str, new: str, *, replace_all: bool = False) -> int:
        """Replaces the one occurrence of ``old`` by ``new`` in a UTF-8 file
        (every one with ``replace_all``); returns how many. Raises
        :class:`EditError` (``no_match``, ``ambiguous``). Never sent twice."""
        self._check_path(path)
        r = self.client._request(
            "POST",
            self._path("/files/edit"),
            json_body={"path": path, "old": old, "new": new, "replace_all": replace_all},
            idempotent=False,
        )
        d = parse_json(r.body)
        if not isinstance(d, dict) or isinstance(d.get("replacements"), bool) or not isinstance(d.get("replacements"), int):
            raise ResponseError("edit: expected replacements")
        return int(d["replacements"])


class Execution:
    """A streamed exec. Iterate over it for its output as it comes
    (:class:`OutputEvent`, :class:`OmittedEvent`), ending with one
    :class:`ResultEvent`; the result is then also :attr:`result`.

    It follows the exec by long polls with a byte cursor, so a dropped
    connection loses nothing: the next poll resumes at :attr:`cursor`
    (for up to ``resume_timeout`` seconds of failing polls). A loop that
    stops early can be followed by another, which goes on with the next
    event. Iterate from one thread; :meth:`cancel` and :meth:`close` may be called from any.

    As a context manager it cancels the exec if it has not ended when the
    block is left, so that a block that stops early does not leave it
    holding the sandbox."""

    def __init__(
        self,
        sandbox: Sandbox,
        exec_id: str,
        poll_bytes: int | None = None,
        *,
        poll_wait: float = POLL_WAIT,
        resume_timeout: float = 60.0,
    ) -> None:
        self.sandbox = sandbox
        self.id = exec_id
        self.cursor = 0
        self.result: ExecResult | None = None
        self.poll_wait = poll_wait
        self.resume_timeout = resume_timeout
        self._poll_bytes = poll_bytes
        self._abort = Abort()
        #: Events of the last poll not yet given to the loop (it may stop
        #: between two of them; the next loop goes on with these).
        self._pending: deque[StreamEvent] = deque()
        self._iterating = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"Execution({self.sandbox.id!r}, {self.id!r})"

    @property
    def done(self) -> bool:
        return self.result is not None

    def __iter__(self) -> Iterator[StreamEvent]:
        with self._lock:
            if self._iterating:
                raise RuntimeError("an execution is iterated by one loop at a time")
            self._iterating = True
        try:
            while True:
                while self._pending:
                    yield self._pending.popleft()
                if self.result is not None or self._abort.aborted:
                    return
                try:
                    poll = self._poll()
                except AbortedError:
                    return
                self._pending.extend(poll.events)
                if poll.eof:
                    assert poll.result is not None
                    self.result = poll.result
                    self._pending.append(ResultEvent(poll.result))
        finally:
            with self._lock:
                self._iterating = False

    def _poll(self) -> Poll:
        query = f"cursor={self.cursor}&wait={self.poll_wait:g}"
        if self._poll_bytes is not None:
            query += f"&max_bytes={self._poll_bytes}"
        target = self.sandbox._path(f"/execs/{self.id}?{query}")
        failing_since: float | None = None
        attempt = 0
        while True:
            try:
                r = self.sandbox.client._request(
                    "GET",
                    target,
                    timeout=self.poll_wait + POLL_MARGIN,
                    idempotent=True,
                    poll=True,
                    abort=self._abort,
                )
                poll = parse_poll(parse_json(r.body))
                break
            except AbortedError:
                raise
            except TransportError:
                # A dropped connection or a stalled poll: resume from the
                # same cursor, which loses nothing.
                now = time.monotonic()
                failing_since = failing_since or now
                if now - failing_since > self.resume_timeout:
                    raise
                _sleep(_retry.delay(attempt), self._abort)
                attempt += 1
        if poll.exec_id != self.id:
            raise ResponseError("a poll answered for another exec")
        if poll.next_cursor < self.cursor:
            raise ResponseError("a poll moved the cursor backwards")
        if not poll.eof and not poll.events and poll.next_cursor != self.cursor:
            raise ResponseError("a poll moved the cursor without output")
        self.cursor = poll.next_cursor
        return poll

    def wait(self) -> ExecResult:
        """Reads the rest of the output (discarding it) and returns the
        result."""
        for _ in self:
            pass
        if self.result is None:
            raise HellovmError("the execution was closed before it ended")
        return self.result

    def cancel(self) -> ExecResult | None:
        """Cancels the exec (its process group is killed; a stateful call
        is interrupted first). Answers once it ended, or after 5 s: the
        result if it ended. A loop iterating over it is woken and ends with
        the result as usual. Safe from any thread; a second cancel, or one
        after the end, changes nothing."""
        r = self.sandbox.client._request(
            "POST", self.sandbox._path(f"/execs/{self.id}/cancel"), timeout=30.0, idempotent=True
        )
        return parse_status(parse_json(r.body)).result

    def close(self) -> None:
        """Stops following the exec here (a poll in flight is cut off and
        the loop ends) without cancelling it."""
        self._abort.abort()

    def __enter__(self) -> Execution:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.result is None:
            try:
                self.cancel()
            except (APIError, TransportError, ResponseError):
                if exc is None:
                    self.close()
                    raise
        self.close()


__all__ = [
    "Client",
    "Sandbox",
    "Execution",
    "OutputEvent",
    "OmittedEvent",
    "ResultEvent",
]
