"""Unit tests: parsing, the retry rules, and the client against a local
fake server that answers, stalls, trickles, drops connections or sends too
much. No sandbox is needed."""

from __future__ import annotations

import json
import random
import socket
import threading
import time
import unittest
from typing import Any

from hellovm import (
    APIError,
    AuthenticationError,
    BudgetExceededError,
    BusyError,
    Client,
    EditError,
    LimitError,
    NotFoundError,
    OmittedEvent,
    OutputEvent,
    RateLimitError,
    RequestTimeoutError,
    ResponseError,
    ResultEvent,
    SandboxEndedError,
    TransportError,
)
from hellovm import _model, _retry
from hellovm.errors import api_error, retry_after

from fakeserver import Conn, FakeServer, Request

SB = "sb-" + "ab" * 16
TOKEN = "unit-token-0123456789abcdef"


def result(**over: Any) -> dict[str, Any]:
    r: dict[str, Any] = {
        "exec_id": "ex-1",
        "exit_code": 0,
        "signal": None,
        "timed_out": False,
        "cancelled": False,
        "stdout": "hi\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_bytes": 3,
        "stderr_bytes": 0,
        "duration_ms": 1.5,
    }
    r.update(over)
    return r


def counters(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "run_ms": 10,
        "cpu_ms": 3,
        "memory_byte_seconds": 4,
        "egress_sent_bytes": 1,
        "egress_received_bytes": 5,
    }
    d.update(over)
    return d


def tenant_usage(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "tenant": "acme",
        "period": {"start": 1000, "end": 2000, "seconds": 1},
        "usage": counters(),
        "sandboxes": 1,
        "memory_limit_bytes": 1 << 30,
        "quotas": {
            "max_sandboxes": 3,
            "max_memory_bytes": None,
            "requests_per_second": 2.5,
            "request_burst": 10,
            "cpu_seconds_per_period": 1.5,
            "egress_bytes_per_period": None,
        },
        "exceeded": ["cpu"],
    }
    d.update(over)
    return d


def info(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": SB,
        "tenant": "acme",
        "template": "python",
        "node": "node-1",
        "egress_id": "abababababababab",
        "created_at": 1,
        "last_used_at": 2,
        "expires_at": 3,
        "idle_timeout": 600.0,
        "memory_bytes": 10,
        "memory_limit_bytes": 20,
        "ready_ms": 7.5,
    }
    d.update(over)
    return d


class Parsing(unittest.TestCase):
    def test_result(self) -> None:
        r = _model.parse_result(result(future_field=1))
        self.assertTrue(r.ok)
        self.assertEqual((r.stdout, r.exit_code, r.state_lost, r.value), ("hi\n", 0, None, None))
        s = _model.parse_result(
            result(
                exit_code=1,
                value=None,
                error={"type": "ZeroDivisionError", "message": "division by zero", "traceback": "Traceback..."},
                state_lost=False,
            )
        )
        self.assertFalse(s.ok)
        assert s.error is not None
        self.assertEqual(s.error.type, "ZeroDivisionError")
        self.assertIs(s.state_lost, False)
        self.assertFalse(_model.parse_result(result(timed_out=True, exit_code=None, signal=9)).ok)

    def test_bad_results(self) -> None:
        bad: Any
        for bad in (
            result(exit_code="0"),
            result(exit_code=True),
            result(stdout=None),
            result(stdout_bytes=-1),
            result(timed_out=1),
            result(value=3),
            result(error={"type": "X"}),
            result(state_lost="no"),
            [],
            "x",
        ):
            with self.assertRaises(ResponseError, msg=repr(bad)):
                _model.parse_result(bad)

    def test_poll_and_events(self) -> None:
        p = _model.parse_poll(
            {
                "exec_id": "ex-2",
                "state": "done",
                "events": [
                    {"type": "stdout", "data": "a"},
                    {"type": "omitted", "bytes": 5},
                    {"type": "stderr", "data": "b"},
                ],
                "next_cursor": 9,
                "eof": True,
                "result": result(),
            }
        )
        self.assertEqual(p.events, [OutputEvent("stdout", "a"), OmittedEvent(5), OutputEvent("stderr", "b")])
        with self.assertRaises(ResponseError):
            _model.parse_event({"type": "stdin", "data": "x"})
        with self.assertRaises(ResponseError):
            _model.parse_poll({"exec_id": "ex-2", "state": "done", "events": [], "next_cursor": 0, "eof": True, "result": None})
        with self.assertRaises(ResponseError):
            _model.parse_json(b"{not json")

    def test_sandbox(self) -> None:
        self.assertEqual(_model.parse_sandbox(info()).ready_ms, 7.5)
        self.assertIsNone(_model.parse_sandbox(info()).usage)
        with self.assertRaises(ResponseError):
            _model.parse_sandbox(info(created_at="1"))
        u = _model.parse_sandbox(info(usage=counters(cpu_ms=7))).usage
        assert u is not None
        self.assertEqual((u.cpu_ms, u.egress_received_bytes), (7, 5))
        self.assertEqual(u.ingress_sent_bytes, 0, "absent from an older API")
        u = _model.parse_sandbox(info(usage=counters(ingress_sent_bytes=9))).usage
        assert u is not None
        self.assertEqual(u.ingress_sent_bytes, 9)
        with self.assertRaises(ResponseError):
            _model.parse_sandbox(info(usage=counters(cpu_ms=-1)))

    def test_usage(self) -> None:
        u = _model.parse_usage(tenant_usage())
        self.assertEqual((u.tenant, u.period_start, u.usage.cpu_ms, u.exceeded), ("acme", 1000, 3, ["cpu"]))
        self.assertEqual((u.quotas.max_memory_bytes, u.quotas.requests_per_second), (None, 2.5))
        for bad in (tenant_usage(exceeded="cpu"), tenant_usage(period=None), tenant_usage(usage={})):
            with self.assertRaises(ResponseError):
                _model.parse_usage(bad)

    def test_errors(self) -> None:
        e = api_error(409, b'{"error": {"code": "busy", "message": "the sandbox is busy"}}')
        self.assertIsInstance(e, BusyError)
        self.assertEqual((e.status, e.code, e.message), (409, "busy", "the sandbox is busy"))
        ended = api_error(410, b'{"error": {"code": "sandbox_ended", "message": "the sandbox ended: idle"}}')
        assert isinstance(ended, SandboxEndedError)
        self.assertEqual(ended.reason, "idle")
        self.assertIsInstance(api_error(401, b'{"error":{"code":"unauthorized","message":"x"}}'), AuthenticationError)
        self.assertIsInstance(api_error(422, b'{"error":{"code":"no_match","message":"x"}}'), EditError)
        self.assertIsInstance(api_error(429, b'{"error":{"code":"tenant_limit","message":"x"}}'), LimitError)
        rate = api_error(429, b'{"error":{"code":"rate_limited","message":"x"}}', 2.0)
        self.assertIsInstance(rate, RateLimitError)
        self.assertEqual(rate.retry_after, 2.0)
        budget = api_error(429, b'{"error":{"code":"budget_exceeded","message":"x"}}', 60.0)
        self.assertIsInstance(budget, BudgetExceededError)
        self.assertIsInstance(budget, LimitError)
        self.assertIsInstance(api_error(429, b'{"error":{"code":"memory_limit","message":"x"}}'), LimitError)
        self.assertEqual((retry_after("3"), retry_after(" 10 "), retry_after(None)), (3.0, 10.0, None))
        for bad in ("-1", "1.5", "Wed, 21 Oct 2015 07:28:00 GMT", "9999999999"):
            self.assertIsNone(retry_after(bad), bad)
        proxy = api_error(502, b"<html>bad gateway</html>" * 100)
        self.assertEqual(type(proxy), APIError)
        self.assertEqual(proxy.code, "http_error")
        self.assertLessEqual(len(proxy.message), 600)


class Retry(unittest.TestCase):
    def test_delay(self) -> None:
        rng = random.Random(1)
        for attempt in range(40):
            d = _retry.delay(attempt, rng)
            full = min(_retry.MAX_DELAY, _retry.BASE_DELAY * 2**attempt)
            self.assertTrue(full / 2 <= d <= full, (attempt, d))

    def test_rules(self) -> None:
        sent = TransportError("x", maybe_sent=True)
        unsent = TransportError("x", maybe_sent=False)
        self.assertTrue(_retry.transport_retry(unsent, idempotent=False))
        self.assertFalse(_retry.transport_retry(sent, idempotent=False))
        self.assertTrue(_retry.transport_retry(sent, idempotent=True))
        self.assertTrue(_retry.status_retry(409, "busy", busy_wait=True, poll=False))
        self.assertFalse(_retry.status_retry(409, "busy", busy_wait=False, poll=False))
        self.assertTrue(_retry.status_retry(503, "template_not_ready", busy_wait=False, poll=False))
        self.assertTrue(_retry.status_retry(429, "too_many_polls", busy_wait=False, poll=True))
        self.assertFalse(_retry.status_retry(429, "too_many_polls", busy_wait=True, poll=False))
        self.assertFalse(_retry.status_retry(429, "tenant_limit", busy_wait=True, poll=True))
        self.assertTrue(_retry.status_retry(429, "rate_limited", busy_wait=False, poll=False))
        self.assertFalse(_retry.status_retry(429, "budget_exceeded", busy_wait=True, poll=True))
        self.assertFalse(_retry.status_retry(500, "internal", busy_wait=True, poll=True))


class Config(unittest.TestCase):
    def test_arguments(self) -> None:
        for token in ("", "a b", "x\r\nHost: evil", "é"):
            with self.assertRaises(ValueError):
                Client("http://127.0.0.1:1", token)
        for url in ("ftp://x", "http://", "http://h/?q=1", "http://u:p@h/"):
            with self.assertRaises(ValueError):
                Client(url, TOKEN)
        client = Client("http://127.0.0.1:1", TOKEN)
        self.assertNotIn(TOKEN, repr(client))
        with self.assertRaises(ValueError):
            client.sandbox("../etc")
        with self.assertRaises(ValueError):
            client.sandbox("sb-1?x=1")


class AgainstFake(unittest.TestCase):
    def serve(self, handler: Any) -> FakeServer:
        server = FakeServer(handler)
        self.addCleanup(server.close)
        return server

    def client(self, server: FakeServer, **options: Any) -> Client:
        client = Client(server.url, TOKEN, **options)
        self.addCleanup(client.close)
        return client

    def test_token_and_keep_alive(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            self.assertEqual(req.headers["authorization"], f"Bearer {TOKEN}")
            conn.json(200, {"templates": [{"name": "python", "ready": True}]})

        server = self.serve(handler)
        client = self.client(server)
        for _ in range(3):
            self.assertEqual(client.templates()[0].name, "python")
        self.assertEqual(server.connections, 1)

    def test_errors_carry_status_code_message_and_not_the_token(self) -> None:
        server = self.serve(lambda req, conn: conn.error(401, "unauthorized", "unknown token"))
        with self.assertRaises(AuthenticationError) as cm:
            self.client(server).list()
        self.assertEqual((cm.exception.status, cm.exception.code), (401, "unauthorized"))
        self.assertNotIn(TOKEN, str(cm.exception))

    def test_busy_waits_then_succeeds(self) -> None:
        calls = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(req.path)
            if len(calls) <= 2:
                conn.error(409, "busy", "the sandbox is busy")
            else:
                conn.json(200, result())

        client = self.client(self.serve(handler))
        self.assertEqual(client.sandbox(SB).exec("echo hi").stdout, "hi\n")
        self.assertEqual(len(calls), 3)

    def test_busy_raise_and_deadline(self) -> None:
        calls = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(1)
            conn.error(409, "busy", "the sandbox is busy")

        server = self.serve(handler)
        with self.assertRaises(BusyError):
            self.client(server, busy="raise").sandbox(SB).exec("true")
        self.assertEqual(len(calls), 1)
        started = time.monotonic()
        with self.assertRaises(BusyError):
            self.client(server, busy_timeout=0.4).sandbox(SB).write_file("a", b"x")
        self.assertLess(time.monotonic() - started, 3)
        self.assertGreater(len(calls), 2)

    def test_rate_limited_waits_retry_after(self) -> None:
        calls: list[float] = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(time.monotonic())
            if len(calls) == 1:
                conn.send(
                    429,
                    b'{"error": {"code": "rate_limited", "message": "slow down"}}',
                    {"Retry-After": "1", "Content-Type": "application/json"},
                )
            else:
                conn.json(200, {"templates": []})

        client = self.client(self.serve(handler))
        self.assertEqual(client.templates(), [])
        self.assertEqual(len(calls), 2)
        self.assertGreaterEqual(calls[1] - calls[0], 0.9)
        # Past the deadline: raised, with when to try again.
        server = self.serve(
            lambda req, conn: conn.send(
                429, b'{"error": {"code": "rate_limited", "message": "x"}}', {"Retry-After": "5"}
            )
        )
        with self.assertRaises(RateLimitError) as cm:
            self.client(server, busy_timeout=1).templates()
        self.assertEqual(cm.exception.retry_after, 5.0)

    def test_budget_exceeded_is_raised_at_once(self) -> None:
        calls = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(1)
            conn.send(
                429,
                b'{"error": {"code": "budget_exceeded", "message": "the cpu budget is used up"}}',
                {"Retry-After": "3600"},
            )

        with self.assertRaises(BudgetExceededError) as cm:
            self.client(self.serve(handler)).create()
        self.assertEqual((cm.exception.retry_after, len(calls)), (3600.0, 1))

    def test_ingress(self) -> None:
        state = {"token": "t" * 64, "ports": [{"port": 8000, "public": False, "url": "https://8000-x.sb/"}]}
        calls: list[tuple[str, str, bytes]] = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append((req.method, req.path, req.body))
            if req.path.endswith("/ingress/ports/8001") and req.method == "PUT":
                conn.json(409, {"error": {"code": "too_many_ports", "message": "at most 16"}})
            elif req.path.endswith("/ingress/token"):
                conn.json(200, dict(state, token="n" * 64))
            else:
                conn.json(200, state)

        sandbox = self.client(self.serve(handler)).sandbox(SB)
        ingress = sandbox.ingress()
        self.assertEqual((ingress.token, ingress.ports[0].port, ingress.ports[0].public), ("t" * 64, 8000, False))
        self.assertNotIn("t" * 64, repr(ingress))
        p = sandbox.expose(8000, public=False)
        self.assertEqual(p.url, "https://8000-x.sb/")
        self.assertEqual(calls[-1][:2], ("PUT", f"/v1/sandboxes/{SB}/ingress/ports/8000"))
        self.assertEqual(json.loads(calls[-1][2]), {"public": False})
        with self.assertRaises(LimitError) as cm:
            sandbox.expose(8001)
        self.assertEqual(cm.exception.code, "too_many_ports")
        sandbox.unexpose(8000)
        self.assertEqual(calls[-1][:2], ("DELETE", f"/v1/sandboxes/{SB}/ingress/ports/8000"))
        self.assertEqual(sandbox.rotate_ingress_token(), "n" * 64)
        for bad in (0, 65536, -1, True, "80"):
            with self.assertRaises(ValueError):
                sandbox.expose(bad)  # type: ignore[arg-type]
        n = len(calls)
        with self.assertRaises(ValueError):
            sandbox.unexpose(0)
        self.assertEqual(len(calls), n, "nothing was sent")

    def test_ingress_answers_are_checked(self) -> None:
        good = {"token": "t" * 64, "ports": [{"port": 1, "public": True, "url": "u"}]}
        self.assertEqual(_model.parse_ingress(good).ports[0].public, True)
        bads: list[dict[str, Any]] = [
            {"ports": []},
            {"token": "t", "ports": None},
            {"token": "t", "ports": [{"port": 0, "public": True, "url": "u"}]},
            {"token": "t", "ports": [{"port": 70000, "public": True, "url": "u"}]},
            {"token": "t", "ports": [{"port": 1, "public": "yes", "url": "u"}]},
        ]
        for bad in bads:
            with self.assertRaises(ResponseError):
                _model.parse_ingress(bad)

    def test_usage_and_an_accepted_delete(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            if req.path == "/v1/usage":
                conn.json(200, tenant_usage())
            else:
                self.assertEqual(req.method, "DELETE")
                conn.send(202)

        client = self.client(self.serve(handler))
        self.assertEqual(client.usage().quotas.cpu_seconds_per_period, 1.5)
        client.delete(SB)

    def test_503_is_retried(self) -> None:
        calls = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(1)
            if len(calls) == 1:
                conn.error(503, "template_not_ready", "try again")
            else:
                conn.json(201, info())

        sandbox = self.client(self.serve(handler)).create()
        self.assertEqual(sandbox.id, SB)
        assert sandbox.info is not None
        self.assertEqual(sandbox.info.template, "python")

    def test_ambiguous_failures_never_repeat_execs_or_writes(self) -> None:
        calls: list[str] = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(f"{req.method} {req.path}")
            conn.drop()

        client = self.client(self.serve(handler), retries=3)
        sandbox = client.sandbox(SB)
        for call in (
            lambda: sandbox.exec("rm -rf /tmp/x"),
            lambda: sandbox.write_file("a", b"x"),
            lambda: sandbox.edit_file("a", "x", "y"),
            lambda: sandbox.reset_python(),
            lambda: sandbox.stream("true"),
            lambda: client.create(),
        ):
            calls.clear()
            with self.assertRaises(TransportError) as cm:
                call()
            self.assertTrue(cm.exception.maybe_sent)
            self.assertEqual(len(calls), 1, calls)

    def test_idempotent_requests_are_retried(self) -> None:
        calls: list[str] = []

        def handler(req: Request, conn: Conn) -> None:
            calls.append(req.method)
            if len(calls) % 2 == 1:
                conn.drop()
            elif req.method == "DELETE":
                # The first try was carried out: now it is gone.
                conn.error(404, "sandbox_not_found", "no such sandbox")
            else:
                conn.send(200, b"\x00\xff", {"Content-Type": "application/octet-stream"})

        client = self.client(self.serve(handler))
        self.assertEqual(client.sandbox(SB).read_file("/bin/x"), b"\x00\xff")
        client.delete(SB)
        self.assertEqual(calls, ["GET", "GET", "DELETE", "DELETE"])

    def test_a_delete_of_a_missing_sandbox_raises(self) -> None:
        server = self.serve(lambda req, conn: conn.error(404, "sandbox_not_found", "no such sandbox"))
        with self.assertRaises(NotFoundError):
            self.client(server).delete(SB)

    def test_refused_connection(self) -> None:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with self.assertRaises(TransportError) as cm:
            Client(f"http://127.0.0.1:{port}", TOKEN, retries=1).sandbox(SB).exec("true")
        self.assertFalse(cm.exception.maybe_sent)

    def test_a_stalled_server_times_out(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)
        server = self.serve(lambda req, conn: release.wait(30))
        started = time.monotonic()
        with self.assertRaises(RequestTimeoutError):
            self.client(server, timeout=0.5, retries=0).list()
        self.assertLess(time.monotonic() - started, 5)

    def test_a_trickling_server_times_out_at_the_deadline(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)

        def handler(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\n")
            while not release.wait(0.1):
                try:
                    conn.sock.sendall(b"X-A: b\r\n")
                except OSError:
                    return

        started = time.monotonic()
        with self.assertRaises((RequestTimeoutError, ResponseError)):
            self.client(self.serve(handler), timeout=1.0, retries=0).list()
        self.assertLess(time.monotonic() - started, 5)

        def body(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            while not release.wait(0.1):
                try:
                    conn.sock.sendall(b"x")
                except OSError:
                    return

        started = time.monotonic()
        with self.assertRaises(RequestTimeoutError):
            self.client(self.serve(body), timeout=1.0, retries=0).list()
        self.assertLess(time.monotonic() - started, 5)

    def test_bounded_responses(self) -> None:
        def huge_length(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n")
            time.sleep(1)

        with self.assertRaises(ResponseError):
            self.client(self.serve(huge_length), max_response_bytes=1 << 20).list()

        def endless(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            try:
                while True:
                    conn.sock.sendall(b"x" * 65536)
            except OSError:
                pass

        with self.assertRaises(ResponseError):
            self.client(self.serve(endless), max_response_bytes=1 << 20).sandbox(SB).read_file("f")

        def endless_head(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\n")
            try:
                while True:
                    conn.sock.sendall(b"X-Pad: " + b"y" * 1000 + b"\r\n")
            except OSError:
                pass

        with self.assertRaises(ResponseError):
            self.client(self.serve(endless_head)).list()

        def chunked(req: Request, conn: Conn) -> None:
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            while True:
                try:
                    conn.sock.sendall(b"10000\r\n" + b"z" * 65536 + b"\r\n")
                except OSError:
                    return

        with self.assertRaises(ResponseError):
            self.client(self.serve(chunked), max_response_bytes=1 << 20).sandbox(SB).read_file("f")

    def test_chunked_answers_are_read(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            body = json.dumps({"sandboxes": [info()]}).encode()
            conn.sock.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(body[:10]):x}\r\n".encode() + body[:10] + b"\r\n"
                + f"{len(body[10:]):x};ext=1\r\n".encode() + body[10:] + b"\r\n0\r\n\r\n"
            )

        client = self.client(self.serve(handler))
        self.assertEqual([s.id for s in client.list()], [SB])
        self.assertEqual([s.id for s in client.list()], [SB])

    def test_malformed_answers(self) -> None:
        for raw in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{bad}",
            b"HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            # Digits to str.isdigit, not to int.
            b"HTTP/1.1 200 OK\r\nContent-Length: \xb2\r\n\r\n",
            b"HTTP/1.1 \xb2\xb2\xb2 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            b"HTTP/1.1 103 Early Hints\r\n\r\n" * 9 + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        ):
            server = self.serve(lambda req, conn, raw=raw: (conn.sock.sendall(raw), conn.drop()))
            with self.assertRaises(ResponseError, msg=repr(raw)):
                self.client(server).list()

    def test_interim_responses_are_skipped(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            body = json.dumps({"sandboxes": [info()]}).encode()
            conn.sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n")
            time.sleep(0.05)
            conn.sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

        server = self.serve(handler)
        client = self.client(server)
        self.assertEqual([s.id for s in client.list()], [SB])
        self.assertEqual([s.id for s in client.list()], [SB])
        self.assertEqual(server.connections, 1)

    def test_large_writes_are_refused_before_sending(self) -> None:
        server = self.serve(lambda req, conn: conn.json(200, {"bytes": 0}))
        with self.assertRaises(LimitError) as cm:
            self.client(server).sandbox(SB).write_file("big", b"x" * ((16 << 20) + 1))
        self.assertEqual(cm.exception.code, "too_large")
        self.assertEqual(server.requests, [])

    def test_paths_are_encoded(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            conn.json(200, {"bytes": len(req.body)})

        server = self.serve(handler)
        self.client(server).sandbox(SB).write_file("/tmp/a b&c?d#e%", "é")
        req = server.requests[0]
        self.assertEqual(req.query["path"], "/tmp/a b&c?d#e%")
        self.assertEqual(req.body, "é".encode())
        self.assertEqual(req.method, "PUT")

    def test_context_manager_deletes_even_when_the_block_raises(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            if req.method == "POST":
                conn.json(201, info())
            elif req.method == "DELETE":
                conn.send(204)

        server = self.serve(handler)
        client = self.client(server)
        with self.assertRaises(ZeroDivisionError):
            with client.create():
                1 / 0
        self.assertEqual([r.method for r in server.requests], ["POST", "DELETE"])

        gone = self.serve(lambda req, conn: conn.json(201, info()) if req.method == "POST" else conn.error(410, "sandbox_ended", "the sandbox ended: idle"))
        with self.client(gone).create():
            pass


class Streams(unittest.TestCase):
    """The long poll behind `Execution`, against a scripted exec."""

    def setUp(self) -> None:
        self.output = ["one\n", "two\n", "three\n"]
        self.cancelled = threading.Event()
        self.drop_next_poll = False
        self.polls: list[dict[str, str]] = []
        self.server = FakeServer(self.handle)
        self.addCleanup(self.server.close)
        self.client = Client(self.server.url, TOKEN)
        self.addCleanup(self.client.close)

    def text_until(self, cursor: int) -> str:
        return "".join(self.output)[:cursor]

    def handle(self, req: Request, conn: Conn) -> None:
        if req.method == "POST" and req.path.endswith("/execs"):
            conn.json(201, {"exec_id": "ex-7", "kind": "command", "state": "running", "started_at": 1, "cancel_requested": False, "result": None})
        elif req.method == "POST" and req.path.endswith("/cancel"):
            self.cancelled.set()
            conn.json(200, {"exec_id": "ex-7", "kind": "command", "state": "done", "started_at": 1, "cancel_requested": True, "result": result(exec_id="ex-7", cancelled=True, signal=9, exit_code=None)})
        elif req.method == "GET":
            q = req.query
            self.polls.append(q)
            if self.drop_next_poll:
                self.drop_next_poll = False
                conn.drop()
                return
            cursor = int(q["cursor"])
            full = "".join(self.output)
            if self.together and cursor == 0:
                events = [{"type": "stdout", "data": s} for s in self.output]
                conn.json(200, {"exec_id": "ex-7", "state": "running", "events": events, "next_cursor": len(full), "eof": False, "result": None})
                return
            if cursor < len(full):
                # One piece per poll.
                for piece_end in range(1, len(full) + 1):
                    if piece_end > cursor and full[:piece_end] in {"".join(self.output[: i + 1]) for i in range(len(self.output))}:
                        break
                events = [{"type": "stdout", "data": full[cursor:piece_end]}]
                conn.json(200, {"exec_id": "ex-7", "state": "running", "events": events, "next_cursor": piece_end, "eof": False, "result": None})
                return
            if self.finish or self.cancelled.wait(float(q["wait"])):
                cancelled = self.cancelled.is_set()
                conn.json(200, {"exec_id": "ex-7", "state": "done", "events": [], "next_cursor": cursor, "eof": True, "result": result(exec_id="ex-7", stdout=full, cancelled=cancelled)})
            else:
                conn.json(200, {"exec_id": "ex-7", "state": "running", "events": [], "next_cursor": cursor, "eof": False, "result": None})

    finish = True
    #: Whether the first poll answers with all the output, as three events.
    together = False

    def test_events_in_order_then_the_result(self) -> None:
        ex = self.client.sandbox(SB).stream("x")
        events = list(ex)
        self.assertEqual(events[:3], [OutputEvent("stdout", s) for s in self.output])
        last = events[-1]
        assert isinstance(last, ResultEvent)
        self.assertEqual(last.result.stdout, "one\ntwo\nthree\n")
        self.assertIs(ex.result, last.result)
        self.assertEqual([p["cursor"] for p in self.polls], ["0", "4", "8", "14"])

    def test_resumes_after_a_dropped_connection(self) -> None:
        ex = self.client.sandbox(SB).stream("x")
        it = iter(ex)
        self.assertEqual(next(it), OutputEvent("stdout", "one\n"))
        self.drop_next_poll = True
        rest = list(it)
        self.assertEqual([e for e in rest if isinstance(e, OutputEvent)], [OutputEvent("stdout", s) for s in self.output[1:]])
        # The dropped poll and its retry asked for the same cursor.
        self.assertEqual([p["cursor"] for p in self.polls][1:3], ["4", "4"])

    def test_a_loop_that_stops_early_loses_no_event(self) -> None:
        self.together = True
        ex = self.client.sandbox(SB).stream("x")
        seen: list[Any] = []
        for event in ex:
            seen.append(event)
            break
        seen.extend(ex)
        self.assertEqual(seen[:3], [OutputEvent("stdout", s) for s in self.output])
        self.assertIsInstance(seen[-1], ResultEvent)
        self.assertEqual(len(seen), 4)

    def test_cancel_from_another_thread_wakes_the_poll(self) -> None:
        self.finish = False
        ex = self.client.sandbox(SB).stream("sleep 100")
        seen: list[Any] = []
        t = threading.Thread(target=lambda: seen.extend(ex))
        t.start()
        time.sleep(0.3)
        started = time.monotonic()
        cancelled = ex.cancel()
        assert cancelled is not None
        self.assertTrue(cancelled.cancelled)
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertLess(time.monotonic() - started, 5)
        assert ex.result is not None
        self.assertTrue(ex.result.cancelled)
        self.assertIsInstance(seen[-1], ResultEvent)

    def test_close_cuts_a_poll_off(self) -> None:
        self.finish = False
        ex = self.client.sandbox(SB).stream("sleep 100")
        done = threading.Event()

        def follow() -> None:
            for _ in ex:
                pass
            done.set()

        threading.Thread(target=follow, daemon=True).start()
        time.sleep(0.3)
        ex.close()
        self.assertTrue(done.wait(5))
        self.assertIsNone(ex.result)
        self.assertFalse(self.cancelled.is_set())

    def test_context_manager_cancels_what_is_left(self) -> None:
        self.finish = False
        with self.client.sandbox(SB).stream("sleep 100") as ex:
            for event in ex:
                break
        self.assertTrue(self.cancelled.is_set())

    def test_a_cursor_moving_backwards_is_refused(self) -> None:
        def handler(req: Request, conn: Conn) -> None:
            if req.method == "POST":
                conn.json(201, {"exec_id": "ex-1", "kind": "command", "state": "running", "started_at": 1, "cancel_requested": False, "result": None})
            elif req.query["cursor"] == "0":
                conn.json(200, {"exec_id": "ex-1", "state": "running", "events": [{"type": "stdout", "data": "abc"}], "next_cursor": 3, "eof": False, "result": None})
            else:
                conn.json(200, {"exec_id": "ex-1", "state": "running", "events": [{"type": "stdout", "data": "abc"}], "next_cursor": 1, "eof": False, "result": None})

        server = FakeServer(handler)
        self.addCleanup(server.close)
        with self.assertRaises(ResponseError):
            client = Client(server.url, TOKEN)
            self.addCleanup(client.close)
            list(client.sandbox(SB).stream("x"))

    def test_too_many_polls_is_waited_out(self) -> None:
        count: list[int] = []

        def handler(req: Request, conn: Conn) -> None:
            if req.method == "POST":
                conn.json(201, {"exec_id": "ex-1", "kind": "command", "state": "running", "started_at": 1, "cancel_requested": False, "result": None})
            elif not count:
                count.append(1)
                conn.error(429, "too_many_polls", "four polls wait already")
            else:
                conn.json(200, {"exec_id": "ex-1", "state": "done", "events": [], "next_cursor": 0, "eof": True, "result": result(exec_id="ex-1")})

        server = FakeServer(handler)
        self.addCleanup(server.close)
        client = Client(server.url, TOKEN)
        self.addCleanup(client.close)
        self.assertEqual(client.sandbox(SB).stream("x").wait().exit_code, 0)


if __name__ == "__main__":
    unittest.main()
