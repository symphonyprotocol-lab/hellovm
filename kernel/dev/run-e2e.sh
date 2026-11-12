#!/bin/sh
# Run from the repository root:
#   kernel/dev/run-e2e.sh
# This script changes into kernel/ before invoking cargo.
#
# One-shot check, test, clippy and rustfmt on the machine it runs on
# (a native host, or the dev container on either architecture). Requires
# Rust 1.99.1 (rust-toolchain.toml), a C compiler, Debian/Ubuntu
# busybox-static, and distro python3 with its standard library under
# /usr/lib/python3.X.
# It does not install packages and does not need root or Docker when those
# dependencies are already on the host.
set -eu

cd "$(dirname "$0")/.."

case "$(rustc --version)" in
  "rustc 1.99.1"*) ;;
  *)
    echo "run-e2e: need rustc 1.99.1 (see rust-toolchain.toml), got: $(rustc --version)" >&2
    exit 1
    ;;
esac

cc_bin=${HELLOVM_GUEST_CC:-cc}
if ! command -v "$cc_bin" >/dev/null 2>&1; then
  echo "run-e2e: C compiler '$cc_bin' not found (install gcc and libc6-dev, or set HELLOVM_GUEST_CC)" >&2
  exit 1
fi

bb=${HELLOVM_BUSYBOX:-/bin/busybox}
if [ ! -f "$bb" ]; then
  echo "run-e2e: busybox not found at $bb; install Debian/Ubuntu busybox-static (a busybox.net build is not the supported image)" >&2
  exit 1
fi

# Statically linked means ldd does not report a dynamic linker or shared
# libraries. A typical static binary makes ldd exit non-zero and print
# "not a dynamic executable". ldd cannot tell a static musl busybox from
# a static glibc one; the supported image is still Debian/Ubuntu
# busybox-static. Output that matches neither case fails, so a missing or
# broken ldd cannot let a dynamic busybox through.
if ! command -v ldd >/dev/null 2>&1; then
  echo "run-e2e: ldd not found; it is needed to check that $bb is statically linked (install libc-bin)" >&2
  exit 1
fi
ldd_out=$(ldd "$bb" 2>&1) || true
case "$ldd_out" in
  *"=>"*|*ld-linux*|*"dynamic linker"*)
    echo "run-e2e: $bb is dynamically linked. Install Debian/Ubuntu busybox-static (a busybox.net build is not the supported image). This check only verifies that the binary is static." >&2
    echo "run-e2e: ldd said: $ldd_out" >&2
    exit 1
    ;;
esac
case "$ldd_out" in
  *"not a dynamic executable"*|*"statically linked"*) ;;
  *)
    echo "run-e2e: cannot tell that $bb is statically linked (ldd: $ldd_out). Install Debian/Ubuntu busybox-static (a busybox.net build is not the supported image). This check only verifies that the binary is static." >&2
    exit 1
    ;;
esac

if [ ! -e /usr/bin/python3 ]; then
  echo "run-e2e: /usr/bin/python3 is missing; install the distro python3 package (the tests hard-code that path)" >&2
  exit 1
fi
if python_real=$(readlink -f /usr/bin/python3 2>/dev/null); then
  :
elif python_real=$(realpath /usr/bin/python3 2>/dev/null); then
  :
else
  echo "run-e2e: cannot resolve /usr/bin/python3 (need readlink -f or realpath) to find /usr/lib/python3.X" >&2
  exit 1
fi
python_name=$(basename "$python_real")
if [ ! -d "/usr/lib/$python_name" ]; then
  echo "run-e2e: Python stdlib directory /usr/lib/$python_name is missing (resolved /usr/bin/python3 -> $python_real). Install the distro python3 standard library under /usr/lib/python3.X." >&2
  exit 1
fi

export HELLOVM_REQUIRE_E2E=1

cargo check --workspace --all-targets

log=$(mktemp)
trap 'rm -f "$log"' EXIT
if ! cargo test --workspace -- --nocapture >"$log" 2>&1; then
  cat "$log" >&2
  echo "run-e2e: cargo test failed" >&2
  exit 1
fi
cat "$log"
if grep -E 'SKIPPING|skipping:' "$log" >/dev/null; then
  echo "run-e2e: cargo test log contains SKIPPING or skipping:; a required e2e test did not run" >&2
  exit 1
fi

cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

echo "hellovm e2e: ok"
