#!/bin/sh
# Runs the KVM platform's tests in a Lima VM on an Apple silicon Mac:
#
#   kernel/dev/run-kvm-lima.sh [INSTANCE [IMAGE]]
#
# from the repository root. INSTANCE is a running Lima instance made from
# kernel/dev/lima-kvm.yaml (default hellovm-kvm; see that file for how to
# make it), IMAGE the dev image (default hellovm-dev, built from
# kernel/dev/Dockerfile).
#
# The tests are built in the dev container (arm64, like the VM) into
# kernel/target/linux, and the guest image of
# kernel/platform-hvf/build-guests.sh is built if missing; then each test
# binary runs in the VM, from the repository mounted at /src, one test at
# a time, with HELLOVM_REQUIRE_E2E=1 (a test that cannot use KVM fails).
# Set HELLOVM_REGISTRY_VOLUME to a Docker volume to keep cargo's registry
# between runs, and HELLOVM_TEST_ARGS to pass more to every test binary
# (a filter, --nocapture).
set -eu
instance=${1:-hellovm-kvm}
image=${2:-hellovm-dev}
root=$(pwd)
if [ ! -f kernel/dev/lima-kvm.yaml ]; then
  echo "run-kvm-lima: run from the repository root" >&2
  exit 1
fi
if ! limactl list --format '{{.Status}}' "$instance" 2>/dev/null | grep -qx Running; then
  echo "run-kvm-lima: Lima instance $instance is not running (see kernel/dev/lima-kvm.yaml)" >&2
  exit 1
fi
[ -f kernel/target/hvf-guests/root/guests/forks ] || kernel/platform-hvf/build-guests.sh "$image"
registry=""
if [ -n "${HELLOVM_REGISTRY_VOLUME:-}" ]; then
  registry="-v $HELLOVM_REGISTRY_VOLUME:/usr/local/cargo/registry"
fi
# shellcheck disable=SC2086
docker run --rm --init --platform linux/arm64 -v "$root":/src $registry -w /src/kernel \
  -e CARGO_TARGET_DIR=/src/kernel/target/linux "$image" sh -eu -c '
list() {
  python3 -c "
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get(\"reason\") == \"compiler-artifact\" and m.get(\"executable\") and m[\"profile\"][\"test\"]:
        print(m[\"executable\"])
"
}
cargo build -p hellovm
{
  cargo test --no-run --message-format=json -p hellovm-platform-arm64 -p hellovm-platform-kvm | list
  cargo test --no-run --message-format=json -p hellovm --features kvm-tests --test kvm_cli | list
} > target/linux/kvm-tests.txt
'
# The repository at /src in the VM (an instance mounted elsewhere gets a
# link), and /dev/kvm usable by the Lima user.
limactl shell "$instance" sudo sh -c "[ -e /src/kernel ] || ln -sfn '$root' /src; chmod 0666 /dev/kvm"
limactl shell --workdir / "$instance" sh -eu -c "
cd /src/kernel
status=0
for test in \$(cat target/linux/kvm-tests.txt); do
  echo \"run-kvm-lima: \$test\"
  HELLOVM_REQUIRE_E2E=1 HELLOVM_KVM_GUESTS=/src/kernel/target/hvf-guests/root \
    \"\$test\" --test-threads=1 ${HELLOVM_TEST_ARGS:-} || status=1
done
exit \$status
"
