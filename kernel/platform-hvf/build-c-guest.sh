#!/bin/sh
# Builds kernel/test-guest/c/smoke.c as a static aarch64 Linux executable
# (glibc) in the Linux dev container, for the HVF platform's c_program test:
#
#   kernel/platform-hvf/build-c-guest.sh [IMAGE]
#
# run from the repository root on an Apple silicon Mac with Docker (the
# container is arm64, so no cross compiler is needed). IMAGE is the dev
# image (default hellovm-dev, built from kernel/dev/Dockerfile). Writes
# kernel/target/hvf-guests/smoke; then
#
#   HELLOVM_HVF_C_GUEST=kernel/target/hvf-guests/smoke cargo test -p hellovm-platform-hvf
set -eu
image=${1:-hellovm-dev}
out=kernel/target/hvf-guests
mkdir -p "$out"
docker run --rm --init --platform linux/arm64 -v "$PWD":/src -w /src "$image" \
    gcc -static -O2 -Wl,--build-id=none -o "$out/smoke" kernel/test-guest/c/smoke.c
file "$out/smoke" 2>/dev/null || ls -l "$out/smoke"
