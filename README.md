# hellovm

A sandbox for AI models.

## The kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `hellovm-core` | `kernel/core` | Syscall emulation: processes, threads, signals, pipes, ELF loading, memory map, filesystem, terminal, `/proc`, IPv4 sockets; independent of the host OS |
| `hellovm-host` | `kernel/host` | Host interface implementations: console, image directory, random bytes, clocks, spliced byte streams |
| `hellovm-platform-seccomp` | `kernel/platform-seccomp` | Linux platform: ptrace and `SECCOMP_RET_TRACE` (see below) |
| `hellovm` | `kernel/hellovm` | Command-line launcher |
| `hellovm-test-guest` | `kernel/test-guest` | Small test programs built at build time |

Syscall interception on Linux is ptrace plus `SECCOMP_RET_TRACE`, not
seccomp user notification. Every app thread is a host process. Its filter
returns `SECCOMP_RET_TRACE` for every native-ABI syscall, and one
event-loop thread is the ptrace tracer of those processes: it emulates the
syscall and skips it, so the host kernel does not run it. Changes to an
address space, and new tasks, are injected `mmap`, `munmap`, `mprotect` and
`clone` through a trusted stub page, with arguments the tracer wrote.
`kernel/platform-seccomp/src/spawn.rs` is the full argument, including why
an in-app stub plus user notification was rejected.

What runs today (milestone U2): x86_64 and aarch64 Linux programs,
static or dynamically linked, with any number of processes and threads.
A busybox shell runs external commands, pipelines, background jobs, traps
and job control; dynamically linked glibc programs and CPython (with
`subprocess`, `threading` and file I/O) run in images assembled from a
Debian system.

- **Processes and threads**: `fork`, `vfork`, `clone` (threads with TLS,
  `CLONE_CHILD_CLEARTID`, robust futex lists), `execve`/`execveat` (static
  and dynamic ELF, `#!` scripts, close-on-exec), `exit`/`exit_group`,
  `wait4`/`waitid`, process groups, sessions, reparenting to init and
  zombies. The sandbox's first process plays init: when it ends, every
  other process is killed.
- **Waiting**: one event loop serves the whole sandbox. A syscall that has
  to wait (pipe I/O, `wait4`, `futex`, sleeps, `poll`/`ppoll`,
  `select`/`pselect6`, `sigsuspend`, console input) parks its thread
  without blocking anything else.
- **Pipes** with blocking, end of file, `PIPE_BUF` atomicity and
  `SIGPIPE`/`EPIPE`.
- **Signals**: handlers on correct signal frames (with FP state) and
  `rt_sigreturn` on both architectures, masks, `sigaltstack`, default
  actions including core-dump status and job-control stops, `kill`,
  `tgkill`, `rt_sigqueueinfo`, `SIGCHLD`, `alarm` and `ITIMER_REAL`,
  interrupted syscalls with `SA_RESTART`, faults the program can handle,
  and asynchronous signals to code that never makes a syscall.
- **Memory**: the kernel loads programs and their interpreter itself and
  owns every address space (`brk`, `mmap`, `munmap`, `mprotect`, `mremap`);
  `MAP_SHARED` anonymous memory stays shared across `fork`.
- **Filesystem**: a read-only image directory under an in-memory writable
  layer. Paths are resolved entirely inside the kernel and cannot leave the
  sandbox root; writes never reach the image directory.
- **`/proc`**: `self`, `<pid>/{exe,cwd,fd,maps,stat,status,statm,cmdline,
  comm,task}`, `meminfo`, `cpuinfo`, `uptime`, `stat`, `loadavg`, `mounts`,
  `net/tcp`, `net/udp`; `ps` works.
- **Terminal**: when hellovm runs on a terminal, the sandbox console is a
  terminal too (`/dev/console`, `/dev/tty`): line editing, echo, termios,
  window size, a foreground process group, and Ctrl-C, Ctrl-\ and Ctrl-Z
  for the foreground job.

**Networking (002a).** Sockets are emulated in the kernel. There is no
packet-level TCP/IP stack and no smoltcp: that is a user-approved deviation
(2026-11-13) from design §4.4, which described an in-kernel userspace stack
behind a normal NIC. The guest still sees a POSIX socket API and one
virtual NIC. Outbound TCP to an address the kernel itself issued is spliced
onto a host byte stream; everything else stays in the kernel or is refused.
The egress proxy is not built yet (002b).

| Role | Address | What the guest sees |
|---|---|---|
| Guest NIC | `192.0.2.2/24` (TEST-NET-1) | The guest's own address. `SIOCGIFCONF` / `SIOCGIFADDR` report it as `eth0`. |
| Gateway / DNS | `192.0.2.1` port 53 | In-kernel DNS, UDP and TCP. Without an egress proxy every query is NXDOMAIN. Any other port is `ECONNREFUSED`. |
| Rest of the NIC net | other `192.0.2.0/24` | `EHOSTUNREACH` |
| Loopback | `127.0.0.0/8`, and `0.0.0.0` as a wildcard | In-kernel TCP and UDP. Connecting to `0.0.0.0` uses `127.0.0.1`. |
| Fake-IP pool | `198.51.100.0/24` (TEST-NET-2) | The only destinations that may be spliced to the host, and only after the kernel has issued that address. |

`bind` is allowed on `0.0.0.0`, `127.0.0.0/8`, and `192.0.2.2`. Anything else,
including the gateway, the rest of `192.0.2.0/24`, and any fake IP, is
`EADDRNOTAVAIL`. Ports the guest does not choose come from **32768–60999**
(Linux's default `ip_local_port_range`), unique per local address and
protocol; the range answers `EADDRINUSE` when it is exhausted. `listen`'s
backlog is clamped to **[1, 128]**; a full accept queue refuses the next
in-kernel connect with `ECONNREFUSED`.

A connect or send that is not loopback, not the guest NIC, not virtual DNS,
and not an issued fake IP fails immediately with `ENETUNREACH`. That
includes metadata (`169.254.169.254`), RFC1918, and any other public
address. Outbound UDP is `ENETUNREACH` except virtual DNS and in-kernel
loopback / the guest NIC. An issued fake IP with no splice endpoint
configured is also `ENETUNREACH`. The guest address is never used as a host
dial address.

`shutdown(SHUT_WR)` half-closes: the peer reads EOF and the caller can
still receive. A bare FIN does not cause `EPIPE`. After a clean full close
the first write is accepted and the next one returns `EPIPE` and raises
`SIGPIPE`, unless the write used `MSG_NOSIGNAL`. A reset (the peer closed
with unread data, or a host write fails) fails the write immediately. A
non-blocking connect that will proceed returns
`EINPROGRESS`; `poll` then reports `POLLOUT` and `SO_ERROR` is the result.
A blocking connect to a loopback address with no listener is `ECONNREFUSED`.
The same connect on a non-blocking socket is `EINPROGRESS` with
`SO_ERROR == ECONNREFUSED`.

Unnamed `AF_UNIX` `socketpair` (`SOCK_STREAM` and `SOCK_DGRAM`) works.
`socket(AF_UNIX)`, path-bound `AF_UNIX`, `AF_INET6`, and netlink
(`AF_NETLINK`) return `EAFNOSUPPORT`. IPv6 and raw sockets are
`EAFNOSUPPORT` / `EPROTONOSUPPORT`.

glibc 2.39 (this host's libc, also what CPython and distro busybox-static
are built with) opens a netlink socket in `getifaddrs` and in
`getaddrinfo`'s `AI_ADDRCONFIG` check. When that socket returns
`EAFNOSUPPORT`, `getifaddrs` fails with errno 97 and does not fall back to
ioctl. `__check_pf` instead assumes both IPv4 and IPv6 are configured, so
`AI_ADDRCONFIG` still returns IPv4 answers. Confirmed in the sandbox:
`getifaddrs` and CPython `socket.if_nameindex()` fail with `EAFNOSUPPORT`,
while `getaddrinfo("127.0.0.1")` and `getaddrinfo("localhost")` return
`127.0.0.1`, and busybox `nc` moves `hi` across `127.0.0.1:5000`. Netlink
is not implemented.

`--splice-to 127.0.0.1:PORT` is a **dev-only** hook, restricted to loopback,
and orthogonal to 002b's `--egress`. 002b will put it behind the
`insecure-test-hooks` feature. A guest connect to an issued fake IP is
spliced to that address; the fake IP is not dialed. Nothing issues a fake
IP unless a test (or, later, egress DNS) calls `Kernel::issue_fake_ip`.
There are at most 4096 sockets. `SO_REUSEADDR` is stored but a second bind
of the same port, including `0.0.0.0` against a specific address, is still
`EADDRINUSE`. With no endpoint configured, a connect to an issued fake IP
is `ENETUNREACH`.

Loopback in one command (the trace lists `socket`, `connect`, `sendto`, and
`recvfrom`; libc has no separate `send`/`recv` syscall):

```sh
mkdir -p /tmp/image/bin && cp /bin/busybox /tmp/image/bin/busybox && ln -sfn busybox /tmp/image/bin/sh && ln -sfn busybox /tmp/image/bin/nc && ln -sfn busybox /tmp/image/bin/echo && ln -sfn busybox /tmp/image/bin/cat && ln -sfn busybox /tmp/image/bin/sleep && timeout 15 cargo run -p hellovm -- --root /tmp/image --no-tty --trace /bin/sh -c 'nc -l -p 5000 >/got & i=0; while [ "$i" -lt 50 ]; do echo hello-loopback | nc -w 2 127.0.0.1 5000 && break; i=$((i+1)); done; sleep 1; wait; cat /got'
```

Not yet: the egress proxy (`pip install`, `git clone`), `epoll`, `eventfd`,
`timerfd`, `inotify`, `clone3` (glibc falls back to `clone`), `fexecve`,
POSIX timers, `ITIMER_VIRTUAL`/`ITIMER_PROF`, priority-inheritance futexes,
writable shared *file* mappings (they are private copies), and permission
checks (the guest is root). Unimplemented syscalls fail with `ENOSYS` and
are logged.

Both the aarch64 and the x86_64 builds have been tested end to end
(busybox shell, CPython, pthreads, signals, dynamic linking and the
terminal). The x86_64 run is `kernel/dev/run-e2e.sh` on a native x86_64
Linux host.

## Building and testing

Running sandboxed programs needs a **Linux** host: kernel 5.5 or newer on
x86_64 or aarch64. Rust **1.99.1** is required; `rust-toolchain.toml` at the
repository root makes rustup install it (with clippy and rustfmt). The dev
image is `rust:1.99.1-bookworm`, the same pin. The workspace `rust-version`
is `1.99`, deliberately stricter than the language MSRV (about 1.88). A C
compiler with a static libc (`cc`, used to build the test guests) is also
required. No root or extra capabilities are required, and it works inside a
container with the default Docker seccomp profile (ptrace of one's own
child is allowed there). On other hosts the workspace builds, but the
end-to-end tests are skipped and `hellovm` cannot run programs yet.

`kernel/dev/run-e2e.sh`, run from the repository root, is the one-shot
path on the machine it runs on (a native host, or the dev container on
either architecture). It checks that rustc is 1.99.1, that a C compiler
exists, that busybox is present and statically linked, and that `/usr/bin/python3` has
its standard library at `/usr/lib/python3.X`. It then runs `cargo check`,
`cargo test`, clippy and rustfmt. The script exports `HELLOVM_REQUIRE_E2E=1`
and fails if the test log contains `SKIPPING` or `skipping:`.

Only the value `1` for `HELLOVM_REQUIRE_E2E` requires those end-to-end
tests to run. Any other value (unset, empty, `0`, `false`, or another
string) keeps the skip-and-return behaviour, so a machine without busybox
can still run the unit tests. With `HELLOVM_REQUIRE_E2E=1`, a missing
busybox, CPython or native test guest fails the test and names what to
install.

```sh
cd kernel
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The busybox tests need Debian or Ubuntu **`busybox-static`**: a statically
linked busybox at `/bin/busybox`, or at the path in `HELLOVM_BUSYBOX`. A
musl binary from busybox.net is not a supported image. Without a distro
static busybox the tests are skipped, unless `HELLOVM_REQUIRE_E2E=1`. The
CPython tests need `/usr/bin/python3` and its standard library on the host
(the dev image has them); they copy the interpreter, its libraries and the
standard library into a temporary image.
The dynamic-linking test builds a C program against the host's glibc and
runs it with the host's libraries the same way.

Run a program in a sandbox whose root is an image directory. The program path
is a path inside the sandbox; `--trace` lists every syscall the kernel
handled, `--splice-to 127.0.0.1:PORT` is a dev-only loopback hook that
splices issued fake IPs onto that address (it is not `--egress`), and `--timeout SECONDS` kills every process of a sandbox that runs
longer (hellovm then exits with 124). When hellovm's stdin and stdout are a
terminal, the sandbox gets a terminal console (`--tty`/`--no-tty` override
this), so an interactive shell works:

```sh
mkdir -p /tmp/image/bin && cp /bin/busybox /tmp/image/bin/
cargo run -p hellovm -- --root /tmp/image --trace /bin/busybox ls -l /
cargo run -p hellovm -- --root /tmp/image /bin/busybox sh -i
```

The container's own root works as an image too, e.g. for CPython:
`hellovm --root / /usr/bin/python3 -c 'print(42)'`.

On macOS, use a Linux container. `kernel/dev/Dockerfile` starts from
`rust:1.99.1-bookworm` (matching `rust-toolchain.toml`) and adds clippy,
rustfmt, `busybox-static` and an x86_64 cross toolchain. The base image
already has `python3`, its standard library and `ldd`:

```sh
docker build -t hellovm-dev kernel/dev
docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/target \
  hellovm-dev kernel/dev/run-e2e.sh
```

`cargo test` from `kernel/` still works in that image:

```sh
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  hellovm-dev cargo test
```

On an aarch64 machine, the x86_64 build can be type-checked and linted (not
run) in the same container:

```sh
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  -e HELLOVM_GUEST_CC=x86_64-linux-gnu-gcc \
  hellovm-dev cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```
