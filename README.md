# cansol

A sandbox for AI models.

## Building and testing the kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `cansol-core` | `kernel/core` | Syscall emulation, independent of the host OS |
| `cansol-host` | `kernel/host` | Host interface implementations |
| `cansol-platform-seccomp` | `kernel/platform-seccomp` | Runs apps on Linux, trapping every syscall with seccomp user notification |
| `cansol` | `kernel/cansol` | Command-line launcher |
| `cansol-test-guest` | `kernel/test-guest` | Tiny libc-free test programs, assembled at build time |

Running sandboxed programs needs a **Linux** host: kernel 5.5 or newer on
x86_64 or aarch64, a Rust toolchain and a C compiler (`cc`, used to assemble
the test guests). No root or extra capabilities are required, and it works
inside a container with the default Docker seccomp profile. On other hosts the
workspace builds, but the end-to-end tests are skipped and `cansol` cannot run
programs yet.

```sh
cd kernel
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Run a program inside the kernel (`--trace` lists every syscall the kernel
handled):

```sh
cargo run -p cansol -- --trace path/to/static-binary
```

On macOS, use a Linux container. `kernel/dev/Dockerfile` adds clippy and
rustfmt to the official Rust image:

```sh
docker build -t cansol-dev kernel/dev
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  cansol-dev cargo test
```
