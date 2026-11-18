"""A small, strict HTTP/1.1 client on the standard library's sockets.

Why not ``http.client`` or ``urllib``: their timeouts apply to each socket
operation, so a server that sends one byte every few seconds holds a
request forever, and a request in flight cannot be stopped from another
thread. Here every request has one deadline for the whole exchange
(connect, send, head and body: each socket operation waits at most for
what is left of it), a response is refused past a size bound before it is
read, and :class:`Abort` shuts the socket of a request in flight down from
any thread.

Connections are kept alive and reused (a few, last in first out). A
connection is reused only while it is younger than ``MAX_IDLE`` seconds
of idleness (the API closes idle ones after 30 s) and if it has not been
closed by the server in the meantime (checked with a non-blocking peek),
so that a failure on a reused connection means what it would on a new
one.
"""

from __future__ import annotations

import select
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

from .errors import RequestTimeoutError, ResponseError, TransportError

MAX_HEAD = 16 * 1024
MAX_HEADERS = 64
#: Interim (1xx) responses skipped before the final one.
MAX_INTERIM = 8
MAX_IDLE = 10.0
MAX_POOL = 8


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class Abort:
    """Stops the requests that carry it: the one in flight (its socket is
    shut down) and every later one (they fail at once)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._aborted = False
        self._socks: set[socket.socket] = set()

    @property
    def aborted(self) -> bool:
        return self._aborted

    def abort(self) -> None:
        with self._lock:
            self._aborted = True
            socks = list(self._socks)
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _register(self, sock: socket.socket) -> bool:
        with self._lock:
            if self._aborted:
                return False
            self._socks.add(sock)
            return True

    def _unregister(self, sock: socket.socket) -> None:
        with self._lock:
            self._socks.discard(sock)


class AbortedError(TransportError):
    """The request was stopped by its :class:`Abort`."""


@dataclass
class _Conn:
    sock: socket.socket
    idle_since: float = field(default_factory=time.monotonic)
    reused: bool = False


class Transport:
    def __init__(self, base_url: str, max_response_bytes: int) -> None:
        url = urllib.parse.urlsplit(base_url)
        if url.scheme not in ("http", "https"):
            raise ValueError("the base URL must start with http:// or https://")
        if not url.hostname:
            raise ValueError("the base URL has no host")
        if url.query or url.fragment or url.username or url.password:
            raise ValueError("the base URL must not have a query, fragment or user")
        self.scheme = url.scheme
        self.host = url.hostname
        self.port = url.port or (443 if url.scheme == "https" else 80)
        self.prefix = url.path.rstrip("/")
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if url.scheme == "https" else 80
        self.host_header = host if self.port == default else f"{host}:{self.port}"
        self.max_response_bytes = max_response_bytes
        self._tls = ssl.create_default_context() if url.scheme == "https" else None
        self._pool: list[_Conn] = []
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, []
        for conn in pool:
            _close(conn.sock)

    # -- connections ---------------------------------------------------

    def _take(self) -> _Conn | None:
        now = time.monotonic()
        while True:
            with self._lock:
                if not self._pool:
                    return None
                conn = self._pool.pop()
            if now - conn.idle_since < MAX_IDLE and _alive(conn.sock):
                conn.reused = True
                return conn
            _close(conn.sock)

    def _give_back(self, conn: _Conn) -> None:
        conn.idle_since = time.monotonic()
        with self._lock:
            if len(self._pool) < MAX_POOL:
                self._pool.append(conn)
                return
        _close(conn.sock)

    def _connect(self, deadline: float) -> _Conn:
        left = deadline - time.monotonic()
        if left <= 0:
            raise RequestTimeoutError("timed out before connecting", maybe_sent=False)
        try:
            sock = socket.create_connection((self.host, self.port), timeout=left)
        except socket.timeout as e:
            raise RequestTimeoutError(f"timed out connecting to the API: {e}", maybe_sent=False) from None
        except OSError as e:
            raise TransportError(f"cannot connect to the API: {e}", maybe_sent=False) from None
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self._tls is not None:
                sock.settimeout(max(deadline - time.monotonic(), 0.001))
                sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except socket.timeout:
            _close(sock)
            raise RequestTimeoutError("timed out in the TLS handshake", maybe_sent=False) from None
        except OSError as e:
            _close(sock)
            raise TransportError(f"TLS handshake failed: {e}", maybe_sent=False) from None
        return _Conn(sock)

    # -- one exchange --------------------------------------------------

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str],
        body: bytes = b"",
        timeout: float,
        abort: Abort | None = None,
    ) -> Response:
        """One request and its response. Raises :class:`TransportError`
        (``maybe_sent`` tells whether the server may have received it) or
        :class:`ResponseError`."""
        deadline = time.monotonic() + timeout
        if abort is not None and abort.aborted:
            raise AbortedError("aborted", maybe_sent=False)
        conn = self._take() or self._connect(deadline)
        if abort is not None and not abort._register(conn.sock):
            _close(conn.sock)
            raise AbortedError("aborted", maybe_sent=False)
        keep = False
        try:
            head = [f"{method} {self.prefix}{target} HTTP/1.1", f"Host: {self.host_header}"]
            for name, value in headers.items():
                head.append(f"{name}: {value}")
            if body or method in ("POST", "PUT"):
                head.append(f"Content-Length: {len(body)}")
            data = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body
            try:
                _settimeout(conn.sock, deadline)
                conn.sock.sendall(data)
                response, keep = self._read(conn.sock, method, deadline)
            except socket.timeout:
                raise RequestTimeoutError(
                    f"no complete answer within {timeout:g} s", maybe_sent=True
                ) from None
            except (OSError, ssl.SSLError) as e:
                if abort is not None and abort.aborted:
                    raise AbortedError("aborted", maybe_sent=True) from None
                raise TransportError(f"connection failed: {e}", maybe_sent=True) from None
            return response
        finally:
            if abort is not None:
                abort._unregister(conn.sock)
            if keep and not (abort is not None and abort.aborted):
                self._give_back(conn)
            else:
                _close(conn.sock)

    def _read(self, sock: socket.socket, method: str, deadline: float) -> tuple[Response, bool]:
        buf = bytearray()
        for _ in range(MAX_INTERIM + 1):
            status, keep, headers, buf = _read_head(sock, buf, deadline)
            if status == 101:
                raise ResponseError("the server switched protocols")
            if not 100 <= status < 200:
                break
            # An interim response (100 Continue, 103 Early Hints from a
            # proxy): the final one follows on the same connection.
        else:
            raise ResponseError("too many interim responses")
        rest = bytes(buf)
        limit = self.max_response_bytes
        if method == "HEAD" or status in (204, 304):
            return Response(status, headers, b""), keep and not rest
        if "transfer-encoding" in headers:
            if headers["transfer-encoding"].lower() != "chunked":
                raise ResponseError("unsupported transfer encoding")
            body, rest = _read_chunked(sock, rest, deadline, limit)
            return Response(status, headers, body), keep and not rest
        length_text = headers.get("content-length")
        if length_text is None:
            stream = bytearray(rest)
            while True:
                if len(stream) > limit:
                    raise ResponseError(f"the response is larger than {limit} bytes")
                chunk = _recv(sock, deadline, 65536)
                if not chunk:
                    return Response(status, headers, bytes(stream)), False
                stream += chunk
        if not _digits(length_text) or len(length_text) > 18:
            raise ResponseError("malformed Content-Length")
        length = int(length_text)
        if length > limit:
            raise ResponseError(f"the response is larger than {limit} bytes ({length})")
        got = bytearray(rest[:length])
        extra = len(rest) > length
        while len(got) < length:
            chunk = _recv(sock, deadline, min(length - len(got), 1 << 20))
            if not chunk:
                raise TransportError("the connection closed inside the response body", maybe_sent=True)
            got += chunk
        return Response(status, headers, bytes(got)), keep and not extra


def _digits(text: str) -> bool:
    """ASCII digits only (``str.isdigit`` also accepts digits ``int``
    refuses, like ``\u00b2``)."""
    return text.isascii() and text.isdigit()


def _read_head(
    sock: socket.socket, buf: bytearray, deadline: float
) -> tuple[int, bool, dict[str, str], bytearray]:
    """One response head, from ``buf`` and then the socket: its status,
    whether the connection may be kept, its headers, and the bytes read
    past it."""
    while True:
        end = buf.find(b"\r\n\r\n")
        if end >= 0:
            break
        if len(buf) > MAX_HEAD:
            raise ResponseError("the response head is too large")
        chunk = _recv(sock, deadline, 65536)
        if not chunk:
            raise TransportError("the connection closed before the response", maybe_sent=True)
        buf += chunk
    lines = bytes(buf[:end]).split(b"\r\n")
    status_line = lines[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or len(parts[1]) != 3 or not _digits(parts[1]):
        raise ResponseError("malformed status line")
    status = int(parts[1])
    if len(lines) - 1 > MAX_HEADERS:
        raise ResponseError("too many response headers")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep or not name or name != name.strip():
            raise ResponseError("malformed response header")
        key = name.lower()
        value = value.strip()
        if key in headers and key in ("content-length", "transfer-encoding"):
            raise ResponseError(f"repeated {key} header")
        headers[key] = value
    keep = headers.get("connection", "").lower() != "close" and parts[0] == "HTTP/1.1"
    return status, keep, headers, buf[end + 4 :]


def _read_chunked(sock: socket.socket, buf: bytes, deadline: float, limit: int) -> tuple[bytes, bytes]:
    data = bytearray(buf)
    body = bytearray()

    def line() -> bytes:
        nonlocal data
        while True:
            at = data.find(b"\r\n")
            if at >= 0:
                out = bytes(data[:at])
                del data[: at + 2]
                return out
            if len(data) > 4096:
                raise ResponseError("malformed chunked body")
            more = _recv(sock, deadline, 65536)
            if not more:
                raise TransportError("the connection closed inside the response body", maybe_sent=True)
            data += more

    while True:
        size_text = line().split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ResponseError("malformed chunk size") from None
        if size < 0 or len(body) + size > limit:
            raise ResponseError(f"the response is larger than {limit} bytes")
        if size == 0:
            while line():
                pass
            return bytes(body), bytes(data)
        while len(data) < size + 2:
            more = _recv(sock, deadline, 1 << 20)
            if not more:
                raise TransportError("the connection closed inside the response body", maybe_sent=True)
            data += more
        if data[size : size + 2] != b"\r\n":
            raise ResponseError("malformed chunk")
        body += data[:size]
        del data[: size + 2]


def _settimeout(sock: socket.socket, deadline: float) -> None:
    left = deadline - time.monotonic()
    if left <= 0:
        raise socket.timeout("deadline passed")
    sock.settimeout(left)


def _recv(sock: socket.socket, deadline: float, n: int) -> bytes:
    _settimeout(sock, deadline)
    return sock.recv(n)


def _alive(sock: socket.socket) -> bool:
    """Whether an idle kept-alive connection is still open: a server sends
    nothing between responses, so anything readable (its end of file, or
    stray bytes) means the connection cannot be used again."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return False
    return not readable


def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
