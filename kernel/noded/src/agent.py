# The hellovm sandbox agent. hellovm-noded runs it as a warm-clone
# template (`python3 -I -c AGENT MODULE...`): it imports MODULE..., waits at
# the clone point, and in each clone serves requests from the node daemon
# on its console: stdin carries requests, stdout answers, stderr is the
# agent's log. A frame is
#
#     [header length u32 BE][body length u32 BE][header: JSON][body]
#
# One request at a time. An exec is answered `started` at once, then its
# output follows as `output` frames (body: the bytes; `stream` 1 or 2) as
# it comes, then its final answer (the status; no output). While it runs,
# noded may send `cancel` (never answered).
#
# Everything the guest does runs as the guest, so nothing here is trusted
# by noded: it bounds and checks every frame it reads from here.
import errno
import json
import os
import random
import select
import signal
import stat
import subprocess
import sys
import time
import traceback

VERSION = 2
MAX_HEADER = 16 << 20
MAX_BODY = 32 << 20
# Output goes to noded in frames of at most this many bytes.
OUTPUT_CHUNK = 1 << 16
# How long output is still taken after a command ended, from what it left
# running in the background holding its pipes.
LINGER = 0.1
# How long an interrupted stateful call has to stop before the
# interpreter is killed.
INTERRUPT_GRACE = 2.0
MAX_VALUE = 16 * 1024
MAX_TRACEBACK = 16 * 1024
MAX_TYPE = 200
MAX_WORKER_ANSWER = 1 << 20
HOME = os.environ.get("HOME") or "/root"

for _name in sys.argv[1:]:
    __import__(_name)
PRELOADED = sorted(sys.argv[1:])
os.makedirs(HOME, exist_ok=True)

# SIGCHLD wakes the exec loop's poll through this pipe.
_wake_r, _wake_w = os.pipe()
os.set_blocking(_wake_r, False)
os.set_blocking(_wake_w, False)
signal.signal(signal.SIGCHLD, lambda *_: None)
signal.set_wakeup_fd(_wake_w)

# The children whose end matters (an exec's process, the interpreter
# worker), and the status of those that ended.
_watched = set()
_exited = {}


def read_exact(n, fd=0):
    chunks = []
    while n:
        data = os.read(fd, min(n, 1 << 20))
        if not data:
            if fd == 0:
                # noded closed the console: nothing more to serve.
                os._exit(0)
            raise EOFError
        chunks.append(data)
        n -= len(data)
    return b"".join(chunks)


def read_frame():
    """One frame from noded: its header (a JSON object) and body."""
    lengths = read_exact(8)
    head_len = int.from_bytes(lengths[:4], "big")
    body_len = int.from_bytes(lengths[4:], "big")
    if head_len > MAX_HEADER or body_len > MAX_BODY:
        print("agent: frame too large; stopping", file=sys.stderr, flush=True)
        os._exit(2)
    head = read_exact(head_len)
    body = read_exact(body_len)
    request = json.loads(head)
    if not isinstance(request, dict):
        raise ValueError("a request header is not an object")
    return request, body


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def send(header, body=b""):
    head = json.dumps(header, separators=(",", ":")).encode()
    write_all(1, len(head).to_bytes(4, "big") + len(body).to_bytes(4, "big") + head + body)


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


ERRNO_CODES = {
    errno.ENOENT: "not_found",
    errno.ENOTDIR: "not_found",
    errno.EISDIR: "is_directory",
    errno.EACCES: "permission_denied",
    errno.EPERM: "permission_denied",
    errno.ENOSPC: "no_space",
    errno.EFBIG: "too_large",
    errno.ELOOP: "bad_path",
    errno.ENAMETOOLONG: "bad_path",
}


def os_failure(err, what):
    return Failure(ERRNO_CODES.get(err.errno, "io_error"), f"{what}: {os.strerror(err.errno or 0)}")


def resolve(path):
    if not isinstance(path, str) or not path or "\0" in path:
        raise Failure("bad_request", "malformed path")
    return os.path.join(HOME, path)


def bounded(text, limit):
    """`text` if it has at most `limit` characters, else its start and
    end with a line saying how much was left out."""
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return f"{text[:head]}\n[... {len(text) - limit} characters omitted ...]\n{text[-tail:]}"


def reap():
    """Reaps every ended child (the agent is the sandbox's init, so
    orphans become its children), keeping the status of the watched ones."""
    while True:
        try:
            pid, st = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        if pid in _watched:
            _watched.discard(pid)
            _exited[pid] = st


def kill_wait(pid):
    """Kills process group `pid` and the process itself, and waits for
    it. (A forked Python run may not have made its own group yet; then
    only the second kill reaches it.)"""
    for kill, target in ((os.killpg, pid), (os.kill, pid)):
        try:
            kill(target, signal.SIGKILL)
        except OSError:
            pass
    if pid in _watched:
        try:
            _, st = os.waitpid(pid, 0)
        except ChildProcessError:
            return
        _watched.discard(pid)
        _exited[pid] = st


def close_other_fds(keep=2):
    # One close per open fd: a brute-force close of every possible fd
    # would be tens of thousands of emulated syscalls.
    try:
        fds = [int(name) for name in os.listdir("/proc/self/fd")]
    except OSError:
        fds = range(keep + 1, 1024)
    for fd in fds:
        if fd > keep:
            try:
                os.close(fd)
            except OSError:
                pass


def drain_wake():
    try:
        while os.read(_wake_r, 512):
            pass
    except BlockingIOError:
        pass


def forward(rid, stream, fd):
    """Passes what `fd` has to noded; False at end of file."""
    try:
        data = os.read(fd, OUTPUT_CHUNK)
    except BlockingIOError:
        return True
    except OSError:
        return False
    if not data:
        return False
    send({"op": "output", "id": rid, "stream": stream}, data)
    return True


def readable(fd):
    try:
        return bool(select.select([fd], [], [], 0)[0])
    except (OSError, ValueError):
        return False


def follow(rid, timeout, streams, ended, stop, in_fd=None, stdin=b"", extra=(), linger=LINGER):
    """Follows one exec until `ended()`: passes the output of `streams`
    ({fd: 1 or 2}) to noded as it comes, feeds `stdin` to `in_fd`, and
    takes a cancel from noded. At the timeout or on a cancel it calls
    `stop()`, which returns when to call it again (or None). `extra` are
    more fds whose readiness may end it. Returns (timed_out, cancelled)."""
    deadline = time.monotonic() + timeout
    open_fds = dict(streams)
    poller = select.poll()
    for fd in open_fds:
        os.set_blocking(fd, False)
        poller.register(fd, select.POLLIN)
    poller.register(_wake_r, select.POLLIN)
    poller.register(0, select.POLLIN)
    for fd in extra:
        poller.register(fd, select.POLLIN)
    pending = memoryview(stdin)
    if in_fd is not None:
        os.set_blocking(in_fd, False)
        if pending:
            poller.register(in_fd, select.POLLOUT)
        else:
            os.close(in_fd)
            in_fd = None
    timed_out = cancelled = stopping = False
    ended_at = None
    while True:
        now = time.monotonic()
        if ended_at is None and ended():
            ended_at = now
            for fd in extra:
                poller.unregister(fd)
        if ended_at is not None and (not open_fds or now - ended_at >= linger):
            break
        if ended_at is None and deadline is not None and now >= deadline:
            if not stopping and not cancelled:
                timed_out = True
            stopping = True
            deadline = stop()
            continue
        if ended_at is not None:
            wait = linger - (now - ended_at)
        elif deadline is not None:
            wait = deadline - now
        else:
            wait = 1.0
        for fd, _ in poller.poll(max(1, min(int(wait * 1000) + 1, 1000))):
            if fd == _wake_r:
                drain_wake()
            elif fd == 0:
                request, _ = read_frame()
                if request.get("op") == "cancel":
                    if request.get("target") == rid and ended_at is None and not stopping:
                        cancelled = True
                        deadline = time.monotonic()
                else:
                    send({"id": request.get("id"), "ok": False, "code": "busy",
                          "message": "an exec is running"})
            elif fd == in_fd:
                try:
                    n = os.write(in_fd, pending[: 1 << 16])
                    pending = pending[n:]
                except BlockingIOError:
                    continue
                except OSError:
                    pending = pending[:0]
                if not pending:
                    poller.unregister(in_fd)
                    os.close(in_fd)
                    in_fd = None
            elif fd in open_fds:
                if not forward(rid, open_fds[fd], fd):
                    poller.unregister(fd)
                    del open_fds[fd]
    # What is still in the pipes (bounded: a background writer may never
    # stop).
    for fd, stream in open_fds.items():
        for _ in range(64):
            if not readable(fd) or not forward(rid, stream, fd):
                break
    if in_fd is not None:
        os.close(in_fd)
    return timed_out, cancelled


def exec_env(request):
    env = dict(os.environ)
    env.update(request.get("env") or {})
    return env


def status_fields(status):
    return {
        "exit_code": os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
        "signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
    }


def op_exec(request, body):
    if request.get("stateful"):
        return run_stateful(request, body)
    rid = request["id"]
    timeout = float(request["timeout"])
    cwd = resolve(request.get("cwd") or HOME)
    if not os.path.isdir(cwd):
        raise Failure("not_found", f"working directory {cwd} does not exist")
    env = exec_env(request)
    stdin = body if request.get("has_stdin") else None
    start = time.monotonic()
    if request.get("command") is not None:
        try:
            proc = subprocess.Popen(
                ["/bin/sh", "-c", request["command"]],
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                start_new_session=True,
            )
        except OSError as err:
            raise os_failure(err, "starting /bin/sh")
        pid = proc.pid
        _watched.add(pid)
        in_fd = os.dup(proc.stdin.fileno()) if proc.stdin else None
        out_fd, err_fd = os.dup(proc.stdout.fileno()), os.dup(proc.stderr.fileno())
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f:
                f.close()
        # Reaped here; keep Popen from waiting for it again.
        proc.returncode = 0
    else:
        pid, out_fd, err_fd, in_fd = fork_python(request["python"], cwd, env, stdin)
    send({"id": rid, "ok": True, "op": "started"})

    def ended():
        reap()
        return pid in _exited

    def stop():
        kill_wait(pid)
        return None

    timed_out, cancelled = follow(rid, timeout, {out_fd: 1, err_fd: 2}, ended, stop, in_fd, stdin or b"")
    for fd in (out_fd, err_fd):
        try:
            os.close(fd)
        except OSError:
            pass
    header = status_fields(_exited.pop(pid))
    header.update(
        timed_out=timed_out,
        cancelled=cancelled,
        duration_ms=(time.monotonic() - start) * 1000.0,
    )
    return header, b""


def fork_python(source, cwd, env, stdin):
    """Runs `source` in a fork of this warm interpreter: every preloaded
    module is already imported. Nothing it defines outlives it."""
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    in_r, in_w = os.pipe() if stdin is not None else (None, None)
    pid = os.fork()
    if pid == 0:
        try:
            signal.set_wakeup_fd(-1)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            os.setsid()
            os.dup2(in_r if in_r is not None else os.open(os.devnull, os.O_RDONLY), 0)
            os.dup2(out_w, 1)
            os.dup2(err_w, 2)
            close_other_fds()
            # Lines reach a reader as they are printed.
            sys.stdout.reconfigure(line_buffering=True)
            random.seed()
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(env)
            sys.argv = ["-c"]
            code = compile(source, "<exec>", "exec")
            scope = {"__name__": "__main__", "__builtins__": __builtins__}
            exec(code, scope)
            status = 0
        except SystemExit as exit:
            if exit.code is None:
                status = 0
            elif isinstance(exit.code, int):
                status = exit.code & 0xFF
            else:
                print(exit.code, file=sys.stderr)
                status = 1
        except BaseException:
            traceback.print_exc()
            status = 1
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(status)
    _watched.add(pid)
    for fd in (out_w, err_w, in_r):
        if fd is not None:
            os.close(fd)
    return pid, out_r, err_r, in_w


# The stateful interpreter: a long-lived fork of this warm interpreter
# whose namespace persists between calls. It reads calls on fd 3 and
# answers on fd 4 ([length u32 BE][JSON]); its stdout and stderr are pipes
# the agent reads during a call. It runs in a process group of its own;
# SIGINT interrupts the code of a call (KeyboardInterrupt) and nothing
# else.


class Worker:
    def __init__(self):
        req_r, self.req_w = os.pipe()
        self.res_r, res_w = os.pipe()
        self.out_r, out_w = os.pipe()
        self.err_r, err_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                signal.set_wakeup_fd(-1)
                signal.signal(signal.SIGCHLD, signal.SIG_DFL)
                os.setsid()
                os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.dup2(req_r, 3)
                os.dup2(res_w, 4)
                close_other_fds(keep=4)
                random.seed()
                os.chdir(HOME)
                sys.argv = [""]
                worker_main()
            except BaseException:
                traceback.print_exc()
            os._exit(1)
        self.pid = pid
        _watched.add(pid)
        for fd in (req_r, res_w, out_w, err_w):
            os.close(fd)
        for fd in (self.req_w, self.res_r, self.out_r, self.err_r):
            os.set_blocking(fd, False)

    def ended(self):
        return self.pid not in _watched

    def kill(self):
        kill_wait(self.pid)
        _exited.pop(self.pid, None)
        for fd in (self.req_w, self.res_r, self.out_r, self.err_r):
            try:
                os.close(fd)
            except OSError:
                pass

    def discard_output(self):
        """Drops what code of earlier calls left running wrote since."""
        for fd in (self.out_r, self.err_r):
            for _ in range(256):
                try:
                    if not os.read(fd, 1 << 16):
                        break
                except OSError:
                    break

    def send(self, data, deadline):
        view = memoryview(data)
        while view:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([], [self.req_w], [], left)[1]:
                return False
            try:
                view = view[os.write(self.req_w, view[: 1 << 16]) :]
            except BlockingIOError:
                continue
            except OSError:
                return False
        return True


_worker = None
# The worker ended since the last call (not by a reset): its state is lost.
_worker_lost = False


def worker_main():
    import ast
    import io
    import linecache

    sys.stdout.reconfigure(line_buffering=True)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    namespace = {"__name__": "__main__", "__builtins__": __builtins__}
    real_stdin = sys.stdin
    cells = []
    count = 0
    while True:
        try:
            length = int.from_bytes(read_exact(4, 3), "big")
            call = json.loads(read_exact(length, 3))
        except EOFError:
            os._exit(0)
        # An interrupt meant for the last call that came too late.
        if signal.SIGINT in signal.sigpending():
            signal.sigwait({signal.SIGINT})
        count += 1
        name = f"<cell-{count}>"
        code = call["code"]
        # Tracebacks show the lines of the cells (the last 256 of them).
        linecache.cache[name] = (len(code), None, code.splitlines(True), name)
        cells.append(name)
        if len(cells) > 256:
            linecache.cache.pop(cells.pop(0), None)
        sys.stdin = io.StringIO(call.get("stdin") or "")
        answer = {"value": None, "error": None}
        try:
            try:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
                tree = ast.parse(code, name, "exec")
                last = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last = ast.Expression(tree.body.pop().value)
                exec(compile(tree, name, "exec"), namespace)
                if last is not None:
                    value = eval(compile(last, name, "eval"), namespace)
                    if value is not None:
                        namespace["_"] = value
                        answer["value"] = bounded(repr(value), MAX_VALUE)
            finally:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        except BaseException as err:
            tb = err.__traceback__
            while tb is not None and not tb.tb_frame.f_code.co_filename.startswith("<cell-"):
                tb = tb.tb_next
            try:
                text = "".join(traceback.format_exception(type(err), err, tb))
                message = str(err)
            except BaseException:
                text, message = f"{type(err).__name__}\n", ""
            answer["error"] = {
                "type": bounded(type(err).__name__, MAX_TYPE),
                "message": bounded(message, MAX_VALUE),
                "traceback": bounded(text, MAX_TRACEBACK),
            }
        sys.stdin = real_stdin
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except BaseException:
                pass
        data = json.dumps(answer).encode()
        write_all(4, len(data).to_bytes(4, "big") + data)


def run_stateful(request, body):
    """A call in the stateful interpreter, which starts on first use."""
    global _worker, _worker_lost
    rid = request["id"]
    timeout = float(request["timeout"])
    start = time.monotonic()
    reap()
    lost = _worker_lost
    _worker_lost = False
    if _worker is not None and _worker.ended():
        _worker.kill()
        _worker = None
        lost = True
    if _worker is None:
        _worker = Worker()
    worker = _worker
    worker.discard_output()
    call = {"code": request["python"]}
    if request.get("has_stdin"):
        call["stdin"] = body.decode("utf-8", "replace")
    data = json.dumps(call).encode()
    send({"id": rid, "ok": True, "op": "started"})
    sent = worker.send(len(data).to_bytes(4, "big") + data, start + timeout)
    answers = []
    buf = bytearray()
    closed = [not sent]

    def ended():
        reap()
        while not closed[0] and not answers:
            try:
                data = os.read(worker.res_r, 1 << 16)
            except BlockingIOError:
                break
            except OSError:
                data = b""
            if not data:
                closed[0] = True
                break
            buf.extend(data)
            if len(buf) >= 4:
                need = int.from_bytes(buf[:4], "big")
                if need > MAX_WORKER_ANSWER:
                    closed[0] = True
                elif len(buf) >= 4 + need:
                    try:
                        answers.append(json.loads(buf[4 : 4 + need]))
                    except ValueError:
                        closed[0] = True
        return bool(answers) or closed[0] or worker.ended()

    stops = []

    def stop():
        if not stops:
            stops.append("interrupted")
            try:
                os.kill(worker.pid, signal.SIGINT)
            except OSError:
                pass
            return time.monotonic() + INTERRUPT_GRACE
        stops.append("killed")
        kill_wait(worker.pid)
        return None

    timed_out, cancelled = follow(
        rid, timeout, {worker.out_r: 1, worker.err_r: 2}, ended, stop, extra=(worker.res_r,), linger=0
    )
    header = {"timed_out": timed_out, "cancelled": cancelled, "signal": None}
    value = b""
    answer = answers[0] if answers and isinstance(answers[0], dict) else None
    if answer is not None:
        error = answer.get("error")
        header["exit_code"] = 1 if error else 0
        if answer.get("value") is not None:
            value = str(answer["value"]).encode()
            header["value_len"] = len(value)
    else:
        # No answer: it was killed, or it ended or broke.
        # (Reaps it if it ended by itself: its own status is kept.)
        kill_wait(worker.pid)
        status = _exited.get(worker.pid)
        worker.kill()
        _worker = None
        lost = True
        if stops and stops[-1] == "killed":
            kind = "InterpreterKilled"
            message = "the interpreter did not stop when interrupted and was killed; its state is lost"
        else:
            kind = "InterpreterExited"
            message = "the interpreter ended; its state is lost"
        header.update(status_fields(status) if status is not None else {"exit_code": None, "signal": 9})
        error = {"type": kind, "message": message, "traceback": ""}
    # The message and the traceback travel in the body like the value: a
    # header is ASCII-escaped JSON, in which 16384 characters can be six
    # times as many bytes, more than noded takes for a header.
    message = trace = b""
    if error:
        message = str(error.get("message") or "").encode()
        trace = str(error.get("traceback") or "").encode()
        header["error"] = {"type": str(error.get("type"))[:MAX_TYPE]}
        header["message_len"] = len(message)
        header["traceback_len"] = len(trace)
    header["state_lost"] = lost
    header["duration_ms"] = (time.monotonic() - start) * 1000.0
    return header, value + message + trace


def op_reset(request, body):
    global _worker, _worker_lost
    had = _worker is not None
    if had:
        _worker.kill()
        _worker = None
    _worker_lost = False
    return {"had_state": had}, b""


def open_file(path, flags, mode=0o644):
    # O_NONBLOCK: opening a FIFO must not block the agent.
    try:
        fd = os.open(path, flags | os.O_NONBLOCK | os.O_CLOEXEC, mode)
    except OSError as err:
        raise os_failure(err, path)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        if stat.S_ISDIR(st.st_mode):
            raise Failure("is_directory", f"{path} is a directory")
        raise Failure("not_regular", f"{path} is not a regular file")
    os.set_blocking(fd, True)
    return fd


def read_file(path, limit):
    fd = open_file(path, os.O_RDONLY)
    try:
        chunks, size = [], 0
        while True:
            data = os.read(fd, 1 << 20)
            if not data:
                break
            size += len(data)
            if size > limit:
                raise Failure("too_large", f"{path} is larger than {limit} bytes")
            chunks.append(data)
        return b"".join(chunks)
    except OSError as err:
        raise os_failure(err, path)
    finally:
        os.close(fd)


def write_file(path, data, make_dirs=True):
    """Replaces the contents of `path` with `data`, or leaves the file as
    it was: the data goes to a new file next to it, which then takes its
    name. A write that fails part-way (no space left) must not cost the
    file it was meant to replace."""
    # Through symbolic links: the file they lead to is the one replaced.
    path = os.path.realpath(path)
    parent = os.path.dirname(path)
    if make_dirs:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as err:
            raise os_failure(err, parent)
    mode = 0o644
    try:
        st = os.stat(path)
    except FileNotFoundError:
        pass
    except OSError as err:
        raise os_failure(err, path)
    else:
        if stat.S_ISDIR(st.st_mode):
            raise Failure("is_directory", f"{path} is a directory")
        if not stat.S_ISREG(st.st_mode):
            raise Failure("not_regular", f"{path} is not a regular file")
        mode = stat.S_IMODE(st.st_mode)
    temp = os.path.join(parent, f".{os.path.basename(path)}.{random.getrandbits(64):016x}.tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    except OSError as err:
        raise os_failure(err, path)
    try:
        try:
            write_all(fd, data)
            # The mode asked for, whatever the umask made of it.
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        os.replace(temp, path)
    except OSError as err:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise os_failure(err, path)


def op_read(request, body):
    path = resolve(request["path"])
    return {}, read_file(path, int(request["max_bytes"]))


def op_write(request, body):
    path = resolve(request["path"])
    write_file(path, body)
    return {"bytes": len(body)}, b""


def op_edit(request, body):
    path = resolve(request["path"])
    limit = int(request["max_bytes"])
    old, new = request["old"], request["new"]
    if not isinstance(old, str) or not isinstance(new, str) or not old:
        raise Failure("bad_request", "old must be a non-empty string")
    try:
        text = read_file(path, limit).decode("utf-8")
    except UnicodeDecodeError:
        raise Failure("not_text", f"{path} is not UTF-8 text")
    count = text.count(old)
    if count == 0:
        raise Failure("no_match", f"the text to replace does not occur in {path}")
    if count > 1 and not request.get("replace_all"):
        raise Failure(
            "ambiguous",
            f"the text to replace occurs {count} times in {path}; "
            "give more context or set replace_all",
        )
    text = text.replace(old, new) if request.get("replace_all") else text.replace(old, new, 1)
    data = text.encode("utf-8")
    if len(data) > limit:
        raise Failure("too_large", f"the edited file would be larger than {limit} bytes")
    write_file(path, data, make_dirs=False)
    return {"replacements": count if request.get("replace_all") else 1}, b""


OPS = {"exec": op_exec, "read": op_read, "write": op_write, "edit": op_edit, "reset": op_reset}


def serve():
    while True:
        reap()
        rid = None
        try:
            request, body = read_frame()
            rid = request.get("id")
            if request.get("op") == "cancel":
                # For an exec that ended meanwhile: nothing to do.
                continue
            op = OPS.get(request.get("op"))
            if op is None:
                raise Failure("bad_request", f"unknown operation {request.get('op')!r}")
            header, out = op(request, body)
            header.update(id=rid, ok=True)
            send(header, out)
        except Failure as failure:
            send({"id": rid, "ok": False, "code": failure.code, "message": failure.message})
        except Exception as err:
            traceback.print_exc()
            send({"id": rid, "ok": False, "code": "agent_error", "message": repr(err)[:1000]})


# The clone point: the template freezes here. Each clone continues with
# its own console and reseeds what must differ between clones.
with open("/dev/hellovm-clone", "rb") as _point:
    _point.read()
random.seed()
send({"id": 0, "ok": True, "op": "hello", "version": VERSION, "pid": os.getpid(), "preloaded": PRELOADED})
serve()
