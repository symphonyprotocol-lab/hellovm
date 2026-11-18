"""What the API answers, as typed objects, parsed defensively: every field
the SDK uses is checked for its type, unknown fields are ignored (so a
newer API still works), and anything else is a :class:`ResponseError`."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal, Union

from .errors import ResponseError


@dataclass(frozen=True)
class Template:
    name: str
    ready: bool


@dataclass(frozen=True)
class SandboxInfo:
    id: str
    tenant: str
    template: str
    node: str
    egress_id: str
    #: Unix milliseconds.
    created_at: int
    last_used_at: int
    expires_at: int
    #: Seconds.
    idle_timeout: float
    memory_bytes: int
    memory_limit_bytes: int
    ready_ms: float


@dataclass(frozen=True)
class PythonError:
    """The exception a stateful call raised."""

    type: str
    message: str
    traceback: str


@dataclass(frozen=True)
class ExecResult:
    """What an exec did. Output is UTF-8 with invalid bytes replaced; a
    stream longer than ``max_output`` keeps its first and last half with
    ``[... N bytes omitted ...]`` between them (``*_truncated`` is then
    true and ``*_bytes`` says how much there was)."""

    exec_id: str
    exit_code: int | None
    signal: int | None
    timed_out: bool
    cancelled: bool
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes: int
    stderr_bytes: int
    duration_ms: float
    #: Stateful calls: the ``repr`` of the last expression's value, if not None.
    value: str | None = None
    #: Stateful calls: the exception raised.
    error: PythonError | None = None
    #: Stateful calls: whether the interpreter's state was lost (killed or
    #: ended) by this call or since the last one; ``None`` for other execs.
    state_lost: bool | None = None

    @property
    def ok(self) -> bool:
        """Exited with status 0, raised nothing, neither timed out nor was
        cancelled."""
        return (
            self.exit_code == 0
            and self.error is None
            and not self.timed_out
            and not self.cancelled
        )


@dataclass(frozen=True)
class OutputEvent:
    """Output of a streamed exec, in the order it was produced."""

    type: Literal["stdout", "stderr"]
    data: str


@dataclass(frozen=True)
class OmittedEvent:
    """Output the node did not keep (it was not read while held and more
    came after it): this many bytes."""

    bytes: int
    type: Literal["omitted"] = "omitted"


@dataclass(frozen=True)
class ResultEvent:
    """The last event of a stream: the exec ended."""

    result: ExecResult
    type: Literal["result"] = "result"


StreamEvent = Union[OutputEvent, OmittedEvent, ResultEvent]


@dataclass(frozen=True)
class ExecStatus:
    exec_id: str
    kind: str
    state: str
    started_at: int
    cancel_requested: bool
    result: ExecResult | None


@dataclass(frozen=True)
class Poll:
    exec_id: str
    state: str
    events: list[OutputEvent | OmittedEvent]
    next_cursor: int
    eof: bool
    result: ExecResult | None


# -- parsing -------------------------------------------------------------


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ResponseError("the answer is not JSON") from None


def _obj(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseError(f"{what}: expected an object")
    return value


def _str(d: dict[str, Any], key: str, what: str) -> str:
    v = d.get(key)
    if not isinstance(v, str):
        raise ResponseError(f"{what}: `{key}` is not a string")
    return v


def _bool(d: dict[str, Any], key: str, what: str, default: bool | None = None) -> bool:
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise ResponseError(f"{what}: `{key}` is not a boolean")
    return v


def _int(d: dict[str, Any], key: str, what: str) -> int:
    v = d.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ResponseError(f"{what}: `{key}` is not an integer")
    return v


def _opt_int(d: dict[str, Any], key: str, what: str) -> int | None:
    v = d.get(key)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ResponseError(f"{what}: `{key}` is not an integer")
    return v


def _num(d: dict[str, Any], key: str, what: str) -> float:
    v = d.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ResponseError(f"{what}: `{key}` is not a number")
    return float(v)


def _count(d: dict[str, Any], key: str, what: str) -> int:
    v = _int(d, key, what)
    if v < 0:
        raise ResponseError(f"{what}: `{key}` is negative")
    return v


def parse_template(value: Any) -> Template:
    d = _obj(value, "template")
    return Template(name=_str(d, "name", "template"), ready=_bool(d, "ready", "template"))


def parse_sandbox(value: Any) -> SandboxInfo:
    w = "sandbox"
    d = _obj(value, w)
    return SandboxInfo(
        id=_str(d, "id", w),
        tenant=_str(d, "tenant", w),
        template=_str(d, "template", w),
        node=_str(d, "node", w),
        egress_id=_str(d, "egress_id", w),
        created_at=_count(d, "created_at", w),
        last_used_at=_count(d, "last_used_at", w),
        expires_at=_count(d, "expires_at", w),
        idle_timeout=_num(d, "idle_timeout", w),
        memory_bytes=_count(d, "memory_bytes", w),
        memory_limit_bytes=_count(d, "memory_limit_bytes", w),
        ready_ms=_num(d, "ready_ms", w),
    )


def parse_result(value: Any) -> ExecResult:
    w = "exec result"
    d = _obj(value, w)
    error = None
    if d.get("error") is not None:
        e = _obj(d["error"], "exec error")
        error = PythonError(
            type=_str(e, "type", "exec error"),
            message=_str(e, "message", "exec error"),
            traceback=_str(e, "traceback", "exec error"),
        )
    value_repr = d.get("value")
    if value_repr is not None and not isinstance(value_repr, str):
        raise ResponseError(f"{w}: `value` is not a string")
    state_lost = d.get("state_lost")
    if state_lost is not None and not isinstance(state_lost, bool):
        raise ResponseError(f"{w}: `state_lost` is not a boolean")
    return ExecResult(
        exec_id=d.get("exec_id", "") if isinstance(d.get("exec_id", ""), str) else "",
        exit_code=_opt_int(d, "exit_code", w),
        signal=_opt_int(d, "signal", w),
        timed_out=_bool(d, "timed_out", w),
        cancelled=_bool(d, "cancelled", w, False),
        stdout=_str(d, "stdout", w),
        stderr=_str(d, "stderr", w),
        stdout_truncated=_bool(d, "stdout_truncated", w),
        stderr_truncated=_bool(d, "stderr_truncated", w),
        stdout_bytes=_count(d, "stdout_bytes", w),
        stderr_bytes=_count(d, "stderr_bytes", w),
        duration_ms=_num(d, "duration_ms", w),
        value=value_repr,
        error=error,
        state_lost=state_lost,
    )


def parse_status(value: Any) -> ExecStatus:
    w = "exec"
    d = _obj(value, w)
    result = d.get("result")
    return ExecStatus(
        exec_id=_str(d, "exec_id", w),
        kind=_str(d, "kind", w),
        state=_str(d, "state", w),
        started_at=_count(d, "started_at", w),
        cancel_requested=_bool(d, "cancel_requested", w),
        result=None if result is None else parse_result(result),
    )


def parse_event(value: Any) -> OutputEvent | OmittedEvent:
    d = _obj(value, "output event")
    kind = d.get("type")
    if kind == "stdout" or kind == "stderr":
        return OutputEvent(type=kind, data=_str(d, "data", "output event"))
    if kind == "omitted":
        return OmittedEvent(bytes=_count(d, "bytes", "output event"))
    raise ResponseError(f"unknown output event type {str(kind)[:32]!r}")


def parse_poll(value: Any) -> Poll:
    w = "poll"
    d = _obj(value, w)
    events = d.get("events")
    if not isinstance(events, list):
        raise ResponseError(f"{w}: `events` is not a list")
    result = d.get("result")
    eof = _bool(d, "eof", w)
    if eof and result is None:
        raise ResponseError(f"{w}: the end without a result")
    return Poll(
        exec_id=_str(d, "exec_id", w),
        state=_str(d, "state", w),
        events=[parse_event(e) for e in events],
        next_cursor=_count(d, "next_cursor", w),
        eof=eof,
        result=None if result is None else parse_result(result),
    )
