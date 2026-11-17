# The hellovm sandbox agent. hellovm-noded runs it as a warm-clone
# template (`python3 -I -c AGENT MODULE...`): it imports MODULE..., waits at
# the clone point, and in each clone serves requests from the node daemon
# on its console: stdin carries requests, stdout answers, stderr is the
# agent's log. A frame is
#
#     [header length u32 BE][body length u32 BE][header: JSON][body]
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

VERSION = 1
MAX_HEADER = 16 << 20
MAX_BODY = 32 << 20
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


def read_exact(n):
    chunks = []
    while n:
        data = os.read(0, min(n, 1 << 20))
        if not data:
            # noded closed the console: nothing more to serve.
            os._exit(0)
        chunks.append(data)
        n -= len(data)
    return b"".join(chunks)


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


class Capture:
    """Keeps the first and the last half of `limit` bytes of a stream."""

    def __init__(self, limit):
        self.head_cap = limit // 2
        self.tail_cap = limit - self.head_cap
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def add(self, data):
        self.total += len(data)
        room = self.head_cap - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data:
            self.tail += data
            if len(self.tail) > 2 * self.tail_cap:
                del self.tail[: len(self.tail) - self.tail_cap]

    def result(self):
        kept = len(self.head) + len(self.tail)
        if self.total == kept and len(self.tail) <= self.tail_cap:
            return bytes(self.head + self.tail), False
        tail = self.tail[-self.tail_cap :] if self.tail_cap else b""
        omitted = self.total - len(self.head) - len(tail)
        marker = f"\n[... {omitted} bytes omitted ...]\n".encode()
        return bytes(self.head) + marker + bytes(tail), True


def reap(target):
    """Reaps every ended child (the agent is the sandbox's init, so
    orphans become its children); returns the status of `target` if it
    was among them."""
    status = None
    while True:
        try:
            pid, st = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return status
        if pid == 0:
            return status
        if pid == target:
            status = st


def close_other_fds():
    # One close per open fd: a brute-force close of every possible fd
    # would be tens of thousands of emulated syscalls.
    try:
        fds = [int(name) for name in os.listdir("/proc/self/fd")]
    except OSError:
        fds = range(3, 1024)
    for fd in fds:
        if fd > 2:
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


def supervise(pid, out_fd, err_fd, in_fd, stdin, timeout, max_output):
    """Collects the output of process group `pid` until it ends or times
    out. Returns the result header and body."""
    start = time.monotonic()
    deadline = start + timeout
    captures = {out_fd: Capture(max_output), err_fd: Capture(max_output)}
    open_fds = {out_fd, err_fd}
    poller = select.poll()
    for fd in open_fds:
        os.set_blocking(fd, False)
        poller.register(fd, select.POLLIN)
    poller.register(_wake_r, select.POLLIN)
    pending = memoryview(stdin) if in_fd is not None else None
    if in_fd is not None:
        os.set_blocking(in_fd, False)
        if pending:
            poller.register(in_fd, select.POLLOUT)
        else:
            os.close(in_fd)
            in_fd = None
    status = None
    timed_out = False
    ended_at = None
    while True:
        if status is None:
            status = reap(pid)
            if status is not None:
                ended_at = time.monotonic()
        now = time.monotonic()
        if status is not None and (not open_fds or now - ended_at > 0.1):
            # Ended, and its output reached end of file (or something it
            # left running in the background still holds the pipes).
            break
        if status is None and now >= deadline:
            timed_out = True
            # The group, and the process itself: a forked Python run may
            # not have made its own group yet, and then only the second
            # kill reaches it (and the wait below would never end).
            for kill, target in ((os.killpg, pid), (os.kill, pid)):
                try:
                    kill(target, signal.SIGKILL)
                except OSError:
                    pass
            _, status = os.waitpid(pid, 0)
            ended_at = time.monotonic()
            continue
        wait = deadline - now if status is None else 0.1 - (now - ended_at)
        for fd, ev in poller.poll(max(1, min(int(wait * 1000) + 1, 1000))):
            if fd == _wake_r:
                drain_wake()
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
                try:
                    data = os.read(fd, 1 << 16)
                except BlockingIOError:
                    continue
                if data:
                    captures[fd].add(data)
                else:
                    poller.unregister(fd)
                    open_fds.discard(fd)
    for fd in (out_fd, err_fd) + ((in_fd,) if in_fd is not None else ()):
        try:
            os.close(fd)
        except OSError:
            pass
    out, out_cut = captures[out_fd].result()
    err, err_cut = captures[err_fd].result()
    header = {
        "exit_code": os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
        "signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
        "timed_out": timed_out,
        "stdout_len": len(out),
        "stdout_truncated": out_cut,
        "stderr_truncated": err_cut,
        "stdout_bytes": captures[out_fd].total,
        "stderr_bytes": captures[err_fd].total,
        "duration_ms": (time.monotonic() - start) * 1000.0,
    }
    return header, out + err


def exec_env(request):
    env = dict(os.environ)
    env.update(request.get("env") or {})
    return env


def op_exec(request, body):
    timeout = float(request["timeout"])
    max_output = int(request["max_output"])
    cwd = resolve(request.get("cwd") or HOME)
    if not os.path.isdir(cwd):
        raise Failure("not_found", f"working directory {cwd} does not exist")
    env = exec_env(request)
    stdin = body if request.get("has_stdin") else None
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
        in_fd = os.dup(proc.stdin.fileno()) if proc.stdin else None
        out_fd, err_fd = os.dup(proc.stdout.fileno()), os.dup(proc.stderr.fileno())
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f:
                f.close()
        header, out = supervise(proc.pid, out_fd, err_fd, in_fd, stdin or b"", timeout, max_output)
        # Reaped by supervise(); keep Popen from waiting for it again.
        proc.returncode = 0
        return header, out
    return run_python(request["python"], cwd, env, stdin, timeout, max_output)


def run_python(source, cwd, env, stdin, timeout, max_output):
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
    for fd in (out_w, err_w, in_r):
        if fd is not None:
            os.close(fd)
    return supervise(pid, out_r, err_r, in_w, stdin or b"", timeout, max_output)


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


OPS = {"exec": op_exec, "read": op_read, "write": op_write, "edit": op_edit}


def serve():
    while True:
        reap(None)
        lengths = read_exact(8)
        head_len = int.from_bytes(lengths[:4], "big")
        body_len = int.from_bytes(lengths[4:], "big")
        if head_len > MAX_HEADER or body_len > MAX_BODY:
            print("agent: frame too large; stopping", file=sys.stderr, flush=True)
            os._exit(2)
        head = read_exact(head_len)
        body = read_exact(body_len)
        rid = None
        try:
            request = json.loads(head)
            rid = request.get("id")
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
