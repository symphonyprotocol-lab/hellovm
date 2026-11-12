# cansol

A sandbox for AI models.

## The kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `cansol-core` | `kernel/core` | Syscall emulation, ELF loading, memory map, filesystem; independent of the host OS |
| `cansol-host` | `kernel/host` | Host interface implementations: console, image directory, random bytes, clocks |
| `cansol-platform-seccomp` | `kernel/platform-seccomp` | Runs apps on Linux: seccomp traps every syscall to the kernel process, which traces the app with ptrace |
| `cansol` | `kernel/cansol` | Command-line launcher |
| `cansol-test-guest` | `kernel/test-guest` | Small test programs built at build time |

What runs today (milestone U1): statically linked x86_64 and aarch64 Linux
programs, non-PIE or static-PIE, one process with one thread. The kernel
loads the program itself, owns its address space (`brk`, `mmap`,
`munmap`, `mprotect`, `mremap`) and gives it a filesystem made of a
read-only image directory under an in-memory writable layer. Paths are
resolved entirely inside the kernel and cannot leave the sandbox root;
writes never reach the image directory. Non-interactive busybox applets
work. Not yet: `fork`/`exec`, pipes, signal delivery, terminals, threads,
dynamic linking and networking. Unimplemented syscalls fail with `ENOSYS`
and are logged.

The aarch64 build is tested end to end. The x86_64 build compiles and
passes lint, and its syscall table and struct layouts are unit-tested, but
it has not been run end to end yet. There is no `/proc` yet, so applets
that read it (`ps`, `free`, `df`) fail.

## Building and testing

Running sandboxed programs needs a **Linux** host: kernel 5.5 or newer on
x86_64 or aarch64, a Rust toolchain and a C compiler with a static libc
(`cc`, used to build the test guests). No root or extra capabilities are
required, and it works inside a container with the default Docker seccomp
profile (ptrace of one's own child is allowed there). On other hosts the
workspace builds, but the end-to-end tests are skipped and `cansol` cannot
run programs yet.

```sh
cd kernel
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The busybox tests need a statically linked busybox at `/bin/busybox` (Debian:
`busybox-static`), or at the path in `CANSOL_BUSYBOX`; without one they are
skipped with a message.

Run a program in a sandbox whose root is an image directory. The program path
is a path inside the sandbox; `--trace` lists every syscall the kernel
handled:

```sh
mkdir -p /tmp/image/bin && cp /bin/busybox /tmp/image/bin/
cargo run -p cansol -- --root /tmp/image --trace /bin/busybox ls -l /
```

On macOS, use a Linux container. `kernel/dev/Dockerfile` adds clippy,
rustfmt, busybox and an x86_64 cross toolchain to the official Rust image:

```sh
docker build -t cansol-dev kernel/dev
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  cansol-dev cargo test
```

On an aarch64 machine, the x86_64 build can be type-checked and linted (not
run) in the same container:

```sh
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  -e CANSOL_GUEST_CC=x86_64-linux-gnu-gcc \
  cansol-dev cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```
