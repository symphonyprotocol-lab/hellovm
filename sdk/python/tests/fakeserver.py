"""A scripted HTTP/1.1 server on loopback for the unit tests: each request
goes to a handler that may answer, stall, trickle, drop the connection or
send too much, which is what the SDK must survive."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Request:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query(self) -> dict[str, str]:
        from urllib.parse import parse_qsl

        return dict(parse_qsl(self.target.split("?", 1)[1])) if "?" in self.target else {}

    def json(self) -> Any:
        return json.loads(self.body)


class Conn:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.closed = False

    def send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        head = [f"HTTP/1.1 {status} X"]
        hs = {"Content-Length": str(len(body))}
        hs.update(headers or {})
        head += [f"{k}: {v}" for k, v in hs.items()]
        self.sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)

    def json(self, status: int, value: Any) -> None:
        self.send(status, json.dumps(value).encode(), {"Content-Type": "application/json"})

    def error(self, status: int, code: str, message: str = "m") -> None:
        self.json(status, {"error": {"code": code, "message": message}})

    def drop(self) -> None:
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


Handler = Callable[[Request, Conn], None]


@dataclass
class FakeServer:
    handler: Handler
    requests: list[Request] = field(default_factory=list)
    connections: int = 0

    def __post_init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.lock = threading.Lock()
        self.stopped = False
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self.stopped = True
        self.listener.close()

    def __enter__(self) -> FakeServer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _accept(self) -> None:
        while not self.stopped:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            with self.lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock: socket.socket) -> None:
        conn = Conn(sock)
        buf = b""
        try:
            while not conn.closed:
                while b"\r\n\r\n" not in buf:
                    data = sock.recv(65536)
                    if not data:
                        return
                    buf += data
                head, buf = buf.split(b"\r\n\r\n", 1)
                lines = head.decode("latin-1").split("\r\n")
                method, target, _ = lines[0].split(" ", 2)
                headers = {}
                for line in lines[1:]:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
                length = int(headers.get("content-length", "0"))
                while len(buf) < length:
                    data = sock.recv(65536)
                    if not data:
                        return
                    buf += data
                body, buf = buf[:length], buf[length:]
                request = Request(method, target, headers, body)
                with self.lock:
                    self.requests.append(request)
                self.handler(request, conn)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass


def stall(conn: Conn, seconds: float) -> None:
    time.sleep(seconds)
