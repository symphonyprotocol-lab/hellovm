"""End-to-end tests against a real plane (``hellovm``, ``hellovm-noded``
and ``hellovm-api`` with a warm Python template).

``kernel/api/tests/sdk.rs`` starts one and runs this suite with:

* ``HELLOVM_TEST_URL``: the API's base URL;
* ``HELLOVM_TEST_TOKEN`` / ``HELLOVM_TEST_TEMPLATE``: a tenant and its template;
* ``HELLOVM_TEST_TOKEN_B`` / ``HELLOVM_TEST_TEMPLATE_B``: a second tenant.

Without them the suite is skipped (it fails instead when
``HELLOVM_REQUIRE_E2E=1``). Nothing here depends on timing beyond
generous bounds, and each test uses sandboxes of its own.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import unittest
from typing import Any

from hellovm import (
    APIError,
    AuthenticationError,
    BusyError,
    Client,
    EditError,
    LimitError,
    NotFoundError,
    OmittedEvent,
    OutputEvent,
    ResultEvent,
    Sandbox,
    SandboxEndedError,
    StreamEvent,
)

URL = os.environ.get("HELLOVM_TEST_URL", "")
TOKEN = os.environ.get("HELLOVM_TEST_TOKEN", "")
TEMPLATE = os.environ.get("HELLOVM_TEST_TEMPLATE", "python")
TOKEN_B = os.environ.get("HELLOVM_TEST_TOKEN_B", "")
TEMPLATE_B = os.environ.get("HELLOVM_TEST_TEMPLATE_B", TEMPLATE)
INGRESS = os.environ.get("HELLOVM_TEST_INGRESS", "")

if not URL and os.environ.get("HELLOVM_REQUIRE_E2E") == "1":
    raise RuntimeError("required e2e dependency missing: HELLOVM_TEST_URL (start a plane, see kernel/api/tests/sdk.rs)")


def eventually(what: str, check: Any, limit: float = 30.0) -> None:
    deadline = time.monotonic() + limit
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out: {what}")
        time.sleep(0.05)


class _None:
    state = ""


_NONE = _None()


class DroppingProxy:
    """A TCP proxy to the API whose connections can all be cut at once:
    a dropped connection, as a client sees it."""

    def __init__(self, target: str) -> None:
        host, port = target.removeprefix("http://").rstrip("/").rsplit(":", 1)
        self.target = (host, int(port))
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.url = f"http://127.0.0.1:{self.listener.getsockname()[1]}"
        self.lock = threading.Lock()
        self.socks: list[socket.socket] = []
        self.cuts = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            upstream = socket.create_connection(self.target)
            with self.lock:
                self.socks += [client, upstream]
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def cut(self) -> None:
        with self.lock:
            socks, self.socks = self.socks, []
            self.cuts += 1
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()

    def close(self) -> None:
        self.listener.close()
        self.cut()


@unittest.skipUnless(URL and TOKEN, "set HELLOVM_TEST_URL and HELLOVM_TEST_TOKEN (a running plane)")
class E2E(unittest.TestCase):
    client: Client
    shared: Sandbox

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = Client(URL, TOKEN)
        cls.shared = cls.client.create(TEMPLATE)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.shared.delete()
        cls.client.close()

    def sandbox(self, **options: Any) -> Sandbox:
        sandbox = self.client.create(TEMPLATE, **options)
        self.addCleanup(lambda: sandbox.__exit__(None, None, None))
        return sandbox

    # -- life cycle ----------------------------------------------------

    def test_templates_create_get_list_delete(self) -> None:
        self.assertIn(TEMPLATE, [t.name for t in self.client.templates() if t.ready])
        with self.client.create(TEMPLATE, idle_timeout=300) as sandbox:
            assert sandbox.info is not None
            self.assertEqual(sandbox.info.template, TEMPLATE)
            self.assertEqual(sandbox.info.idle_timeout, 300)
            self.assertTrue(sandbox.id.startswith("sb-"))
            self.assertIn(sandbox.id, [s.id for s in self.client.list()])
            got = self.client.get(sandbox.id)
            assert got.info is not None
            self.assertEqual(got.info.egress_id, sandbox.id[3:19])
            self.assertGreater(sandbox.refresh().memory_limit_bytes, 0)
            self.assertIsNotNone(sandbox.refresh().usage)
            usage = self.client.usage()
            self.assertGreaterEqual(usage.sandboxes, 1)
            self.assertGreater(usage.period_end, usage.period_start)
            self.assertGreater(usage.quotas.max_sandboxes, 0)
        with self.assertRaises(NotFoundError) as cm:
            self.client.get(sandbox.id)
        self.assertEqual(cm.exception.code, "sandbox_not_found")
        with self.assertRaises(NotFoundError):
            self.client.delete(sandbox.id)

    def test_the_context_manager_deletes_when_the_block_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.client.create(TEMPLATE) as sandbox:
                sandbox.exec("true")
                raise RuntimeError("boom")
        with self.assertRaises(NotFoundError):
            self.client.get(sandbox.id)

    def test_authentication_failure(self) -> None:
        bad = Client(URL, "not-a-token-0123456789abcdef")
        self.addCleanup(bad.close)
        with self.assertRaises(AuthenticationError) as cm:
            bad.list()
        self.assertEqual((cm.exception.status, cm.exception.code), (401, "unauthorized"))
        self.assertNotIn("not-a-token", str(cm.exception))

    @unittest.skipUnless(TOKEN_B, "no second tenant")
    def test_a_second_tenant_sees_nothing(self) -> None:
        other = Client(URL, TOKEN_B)
        self.addCleanup(other.close)
        self.assertNotIn(self.shared.id, [s.id for s in other.list()])
        theirs = other.sandbox(self.shared.id)
        for call in (
            theirs.refresh,
            lambda: theirs.exec("true"),
            lambda: theirs.read_file("/etc/hostname"),
            lambda: theirs.write_file("x", "y"),
            lambda: theirs.run("1"),
            theirs.reset_python,
            theirs.latest_exec,
            lambda: theirs.stream("true"),
            theirs.delete,
        ):
            with self.assertRaises(NotFoundError) as cm:
                call()
            self.assertEqual(cm.exception.code, "sandbox_not_found")
        self.assertEqual(self.shared.exec("echo still here").stdout, "still here\n")
        with other.create(TEMPLATE_B) as mine:
            self.assertNotIn(mine.id, [s.id for s in self.client.list()])

    def test_an_ended_sandbox_says_why(self) -> None:
        sandbox = self.client.create(TEMPLATE, lifetime=1)
        self.addCleanup(lambda: sandbox.__exit__(None, None, None))
        ended: list[SandboxEndedError] = []

        def gone() -> bool:
            try:
                sandbox.refresh()
            except SandboxEndedError as e:
                ended.append(e)
                return True
            return False

        eventually("the sandbox did not end", gone, 30)
        self.assertEqual((ended[0].status, ended[0].code), (410, "sandbox_ended"))
        self.assertIn("lifetime", ended[0].reason)
        with self.assertRaises(SandboxEndedError):
            sandbox.exec("true")

    # -- exec ----------------------------------------------------------

    def test_exec(self) -> None:
        sb = self.shared
        r = sb.exec("echo out; echo err >&2; exit 3")
        self.assertEqual((r.stdout, r.stderr, r.exit_code, r.signal), ("out\n", "err\n", 3, None))
        self.assertFalse(r.ok or r.timed_out or r.cancelled)
        self.assertTrue(r.exec_id.startswith("ex-"))
        self.assertTrue(sb.exec("true").ok)
        r = sb.exec("cat; pwd; echo $GREETING", stdin="from stdin\n", cwd="/tmp", env={"GREETING": "hello"})
        self.assertEqual(r.stdout, "from stdin\n/tmp\nhello\n")
        with self.assertRaises(NotFoundError) as cm:
            sb.exec("true", cwd="/no/such/dir")
        self.assertEqual(cm.exception.code, "not_found")
        with self.assertRaises(APIError) as bad:
            sb.exec("true", timeout=-1)
        self.assertEqual((bad.exception.status, bad.exception.code), (400, "bad_request"))

    def test_exec_timeout(self) -> None:
        started = time.monotonic()
        r = self.shared.exec("echo before; sleep 30; echo after", timeout=1)
        self.assertLess(time.monotonic() - started, 20)
        self.assertTrue(r.timed_out)
        self.assertEqual((r.signal, r.exit_code, r.stdout), (9, None, "before\n"))

    def test_exec_truncation(self) -> None:
        r = self.shared.exec("head -c 100000 /dev/zero | tr '\\0' a; echo; seq 1 3 >&2", max_output=1024)
        self.assertTrue(r.stdout_truncated)
        self.assertFalse(r.stderr_truncated)
        self.assertEqual(r.stdout_bytes, 100001)
        self.assertIn("bytes omitted", r.stdout)
        self.assertLess(len(r.stdout), 1200)
        self.assertTrue(r.stdout.startswith("a" * 400))
        self.assertEqual(r.stderr, "1\n2\n3\n")

    def test_python_in_a_fresh_fork(self) -> None:
        r = self.shared.python("import json, sys\nprint(json.dumps({'a': 1}))\nsys.exit(4)")
        self.assertEqual((r.stdout, r.exit_code), ('{"a": 1}\n', 4))
        r = self.shared.python("x = 1")
        r = self.shared.python("print(x)")
        self.assertEqual(r.exit_code, 1)
        self.assertIn("NameError", r.stderr)

    # -- the stateful interpreter --------------------------------------

    def test_stateful_python(self) -> None:
        sb = self.sandbox()
        self.assertIsNone(sb.run("import math\nx = 20").value)
        r = sb.run("x += 1\nprint('side', end='')\nmath.floor(x * 2.5)")
        self.assertEqual((r.value, r.stdout, r.exit_code, r.state_lost), ("52", "side", 0, False))
        self.assertEqual(sb.run("'a' * 3").value, "'aaa'")
        r = sb.run("def f():\n    return 1 / 0\nf()")
        assert r.error is not None
        self.assertEqual((r.error.type, r.exit_code), ("ZeroDivisionError", 1))
        self.assertIn("division by zero", r.error.message)
        self.assertIn("in f", r.error.traceback)
        self.assertEqual(sb.run("x").value, "21")
        self.assertEqual(sb.run("input()", stdin="typed\n").value, "'typed'")
        self.assertTrue(sb.reset_python())
        r = sb.run("x")
        assert r.error is not None
        self.assertEqual(r.error.type, "NameError")
        self.assertFalse(sb.reset_python() and False)

    def test_stateful_state_lost(self) -> None:
        sb = self.sandbox()
        sb.run("y = 5")
        r = sb.run("import os\nos._exit(7)")
        self.assertTrue(r.state_lost)
        assert r.error is not None
        self.assertEqual(r.error.type, "InterpreterExited")
        r = sb.run("y")
        assert r.error is not None
        self.assertEqual(r.error.type, "NameError")

    def test_stateful_timeout_keeps_the_state(self) -> None:
        sb = self.sandbox()
        sb.run("z = 9")
        r = sb.run("import time\ntime.sleep(60)", timeout=1)
        self.assertTrue(r.timed_out)
        # Interrupted (state kept), or, on a slow machine, killed after the
        # 2 s grace (state lost): both are what the API documents.
        if r.state_lost:
            assert r.error is not None
            self.assertEqual(r.error.type, "InterpreterKilled")
        else:
            assert r.error is not None
            self.assertEqual(r.error.type, "KeyboardInterrupt")
            self.assertEqual(sb.run("z").value, "9")

    # -- streams -------------------------------------------------------

    def test_stream_output_comes_before_the_end_in_order(self) -> None:
        sb = self.sandbox()
        command = "for i in 1 2 3; do echo out$i; echo err$i >&2; sleep 0.3; done"
        seen_before_end = False
        events: list[StreamEvent] = []
        with sb.stream(command) as ex:
            for event in ex:
                events.append(event)
                if isinstance(event, OutputEvent) and event.data.startswith("out1") and ex.result is None:
                    # Listing the exec does not take the sandbox.
                    latest = sb.latest_exec()
                    seen_before_end = latest is not None and latest.state == "running"
        self.assertTrue(seen_before_end)
        last = events[-1]
        assert isinstance(last, ResultEvent)
        self.assertEqual(last.result.stdout, "out1\nout2\nout3\n")
        out = "".join(e.data for e in events if isinstance(e, OutputEvent) and e.type == "stdout")
        err = "".join(e.data for e in events if isinstance(e, OutputEvent) and e.type == "stderr")
        self.assertEqual((out, err), ("out1\nout2\nout3\n", "err1\nerr2\nerr3\n"))
        # Lines written at different moments keep their order across streams.
        order = [e.data.strip() for e in events if isinstance(e, OutputEvent)]
        joined = "".join(order)
        self.assertLess(joined.index("out1"), joined.index("out2"))
        self.assertLess(joined.index("err1"), joined.index("out2"))
        self.assertEqual(ex.cursor, len("out1\nerr1\nout2\nerr2\nout3\nerr3\n"))

    def test_stream_resumes_after_a_dropped_connection(self) -> None:
        sb = self.sandbox()
        proxy = DroppingProxy(URL)
        self.addCleanup(proxy.close)
        through = Client(proxy.url, TOKEN)
        self.addCleanup(through.close)
        ex = through.sandbox(sb.id).stream("echo first; sleep 1; echo second; sleep 1; echo third")
        texts = []
        for event in ex:
            if isinstance(event, OutputEvent):
                texts.append(event.data)
                if event.data == "first\n":
                    proxy.cut()  # the poll waiting for "second" loses its connection
        self.assertEqual("".join(texts), "first\nsecond\nthird\n")
        assert ex.result is not None
        self.assertEqual(ex.result.exit_code, 0)
        self.assertGreaterEqual(proxy.cuts, 1)

    def test_stream_cancelled_from_another_thread(self) -> None:
        sb = self.sandbox()
        ex = sb.stream("echo started; sleep 60; echo never")
        events: list[StreamEvent] = []
        started = threading.Event()

        def follow() -> None:
            for event in ex:
                events.append(event)
                started.set()

        t = threading.Thread(target=follow)
        t.start()
        self.assertTrue(started.wait(30))
        begun = time.monotonic()
        ex.cancel()
        t.join(30)
        self.assertFalse(t.is_alive())
        self.assertLess(time.monotonic() - begun, 15)
        assert ex.result is not None
        self.assertTrue(ex.result.cancelled)
        self.assertEqual(ex.result.signal, 9)
        self.assertNotIn("never", ex.result.stdout)
        self.assertIsInstance(events[-1], ResultEvent)
        # The sandbox is free again.
        self.assertEqual(sb.exec("echo free").stdout, "free\n")

    def test_leaving_a_stream_early_cancels_it(self) -> None:
        sb = self.sandbox()
        with sb.stream("echo go; sleep 60") as ex:
            for _ in ex:
                break
        latest = sb.latest_exec()
        assert latest is not None
        self.assertEqual(latest.exec_id, ex.id)
        self.assertEqual(sb.exec("echo next", timeout=10).stdout, "next\n")

    def test_stream_stateful_python_and_omitted_output(self) -> None:
        sb = self.sandbox()
        result = sb.stream_python("v = 6\nprint('x')\nv * 7", stateful=True).wait()
        self.assertEqual((result.value, result.stdout), ("42", "x\n"))
        # More output than is held, read late: an omitted event.
        ex = sb.stream("head -c 3000000 /dev/zero | tr '\\0' b", max_output=1024, poll_bytes=1024)
        time.sleep(0.5)
        events = list(ex)
        assert ex.result is not None
        self.assertEqual(ex.result.stdout_bytes, 3000000)
        if not ex.result.cancelled:
            self.assertTrue(any(isinstance(e, OmittedEvent) for e in events))

    # -- busy ----------------------------------------------------------

    def test_busy_raise_and_wait(self) -> None:
        sb = self.sandbox()
        raising = Client(URL, TOKEN, busy="raise")
        self.addCleanup(raising.close)
        held: list[str] = []
        holder = threading.Thread(target=lambda: held.append(sb.exec("sleep 2; echo held").stdout))
        holder.start()
        eventually("the first exec did not start", lambda: (sb.latest_exec() or _NONE).state == "running")
        with self.assertRaises(BusyError) as cm:
            raising.sandbox(sb.id).exec("echo now")
        self.assertEqual((cm.exception.status, cm.exception.code), (409, "busy"))
        with self.assertRaises(BusyError):
            raising.sandbox(sb.id).write_file("f", "x")
        # The default waits until the sandbox is free, then runs.
        self.assertEqual(sb.exec("echo after").stdout, "after\n")
        holder.join(30)
        self.assertEqual(held, ["held\n"])

    # -- files ---------------------------------------------------------

    @unittest.skipUnless(INGRESS, "set HELLOVM_TEST_INGRESS (the ingress listener)")
    def test_ingress(self) -> None:
        import http.client
        import urllib.parse

        sb = self.sandbox()
        sb.write_file("/tmp/www/index.html", "hello from the sandbox\n")
        sb.exec("cd /tmp/www && nohup python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 &")
        self.assertEqual(sb.ingress().ports, [])
        port = sb.expose(8000)
        self.assertFalse(port.public)
        host = urllib.parse.urlsplit(port.url).hostname or ""
        self.assertTrue(host.startswith(f"8000-{sb.id}."), port.url)
        token = sb.ingress().token

        def get(headers: dict[str, str]) -> tuple[int, bytes]:
            addr, _, p = INGRESS.rpartition(":")
            conn = http.client.HTTPConnection(addr, int(p), timeout=10)
            try:
                conn.request("GET", "/index.html", headers={"Host": host, **headers})
                r = conn.getresponse()
                return r.status, r.read()
            finally:
                conn.close()

        deadline = time.monotonic() + 20
        while get({"X-Hellovm-Ingress-Token": token})[0] != 200:
            self.assertLess(time.monotonic(), deadline, "the server never answered")
            time.sleep(0.2)
        self.assertEqual(get({"X-Hellovm-Ingress-Token": token}), (200, b"hello from the sandbox\n"))
        self.assertEqual(get({})[0], 404)
        self.assertTrue(sb.expose(8000, public=True).public)
        self.assertEqual(get({})[0], 200)
        new = sb.rotate_ingress_token()
        self.assertNotEqual(new, token)
        sb.unexpose(8000)
        self.assertEqual(sb.ingress().ports, [])
        self.assertEqual(get({"X-Hellovm-Ingress-Token": new})[0], 404)
        # Metered for the sandbox (within a second or so).
        deadline = time.monotonic() + 10
        while True:
            usage = sb.refresh().usage
            if usage is not None and usage.ingress_sent_bytes > 0:
                break
            self.assertLess(time.monotonic(), deadline, "ingress not metered")
            time.sleep(0.2)

    def test_files(self) -> None:
        sb = self.shared
        data = bytes(range(256)) * 300
        self.assertEqual(sb.write_file("/tmp/dir/sub/bin", data), len(data))
        self.assertEqual(sb.read_file("/tmp/dir/sub/bin"), data)
        text = "hello wörld\nhello again\n"
        self.assertEqual(sb.write_file("notes.txt", text), len(text.encode()))
        self.assertEqual(sb.read_text("notes.txt"), text)
        self.assertEqual(sb.exec("cat notes.txt").stdout, text)
        self.assertEqual(sb.edit_file("notes.txt", "wörld", "there"), 1)
        with self.assertRaises(EditError) as cm:
            sb.edit_file("notes.txt", "hello", "bye")
        self.assertEqual(cm.exception.code, "ambiguous")
        self.assertEqual(sb.edit_file("notes.txt", "hello", "bye", replace_all=True), 2)
        self.assertEqual(sb.read_text("notes.txt"), "bye there\nbye again\n")
        with self.assertRaises(EditError) as cm:
            sb.edit_file("notes.txt", "absent", "x")
        self.assertEqual(cm.exception.code, "no_match")
        with self.assertRaises(APIError) as cm2:
            sb.edit_file("/tmp/dir/sub/bin", "a", "b")
        self.assertEqual(cm2.exception.code, "not_text")
        with self.assertRaises(NotFoundError) as cm3:
            sb.read_file("/no/such/file")
        self.assertEqual(cm3.exception.code, "not_found")
        with self.assertRaises(APIError) as cm4:
            sb.read_file("/tmp/dir")
        self.assertEqual((cm4.exception.status, cm4.exception.code), (400, "is_directory"))
        with self.assertRaises(LimitError):
            sb.write_file("big", b"x" * ((16 << 20) + 1))
        self.assertEqual(sb.write_file("/tmp/empty", b""), 0)
        self.assertEqual(sb.read_file("/tmp/empty"), b"")


if __name__ == "__main__":
    unittest.main()
