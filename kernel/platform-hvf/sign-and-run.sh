#!/bin/sh
# Cargo runner for macOS on Apple silicon (see kernel/.cargo/config.toml):
# signs the executable ad hoc with the hypervisor entitlement, which
# Hypervisor.framework requires, then runs it. `cargo run` and `cargo test`
# go through it; it changes nothing but the executable's signature.
set -e
exe=$1
codesign --force --sign - \
    --entitlements "$(dirname "$0")/hellovm.entitlements" "$exe" 2>/dev/null ||
    echo "sign-and-run.sh: could not sign $exe; HVF tests will be skipped" >&2
exec "$@"
