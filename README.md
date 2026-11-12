# hellovm

A sandbox for AI models.

## The kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `hellovm-core` | `kernel/core` | Syscall emulation: processes, threads, signals, pipes, ELF loading, memory map, filesystem, terminal, `/proc`; independent of the host OS |
| `hellovm-host` | `kernel/host` | Host interface implementations: console, image directory, random bytes, clocks |
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
  comm,task}`, `meminfo`, `cpuinfo`, `uptime`, `stat`, `loadavg`, `mounts`;
  `ps` works.
- **Terminal**: when hellovm runs on a terminal, the sandbox console is a
  terminal too (`/dev/console`, `/dev/tty`): line editing, echo, termios,
  window size, a foreground process group, and Ctrl-C, Ctrl-\ and Ctrl-Z
  for the foreground job.

Not yet: networking (sockets fail with `ENOSYS`), `epoll`, `eventfd`,
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
handled, and `--timeout SECONDS` kills every process of a sandbox that runs
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
