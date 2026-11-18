#!/bin/sh
# Run from the repository root:
#   kernel/dev/run-sdk-e2e.sh
#
# The SDKs (sdk/python, sdk/ts) and the MCP server (sdk/mcp): type
# checks, then their unit and end-to-end tests, each suite against a real
# plane (hellovm, hellovm-noded and hellovm-api with a warm CPython
# template) that kernel/api/tests/sdk.rs starts.
#
# Needs what run-e2e.sh needs (run that first: this script relies on the
# same Rust toolchain and distro packages), plus Python 3.10 or later and
# Node.js 20 or later with npm. `npm ci` fetches the TypeScript compiler
# and the MCP SDK (network once, then npm's cache). The Python type check
# runs when mypy is found (MYPY, or mypy on PATH).
#
# A missing Python or Node.js skips its part with a SKIPPING line, unless
# HELLOVM_REQUIRE_E2E=1, which makes it a failure (as CI does).
set -eu

cd "$(dirname "$0")/../.."
root=$PWD
required=${HELLOVM_REQUIRE_E2E:-}

missing() {
  if [ "$required" = 1 ]; then
    echo "run-sdk-e2e: required e2e dependency missing: $1" >&2
    exit 1
  fi
  echo "SKIPPING $1"
}

have_python=no
if command -v python3 >/dev/null 2>&1 \
  && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  have_python=yes
else
  missing "the Python SDK: python3 3.10 or later not found (install python3)"
fi

have_node=no
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 \
  && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)'; then
  have_node=yes
else
  missing "the TypeScript SDK and the MCP server: Node.js 20 or later with npm not found (install nodejs)"
fi

if [ "$have_python" = yes ]; then
  mypy=${MYPY:-$(command -v mypy || true)}
  if [ -n "$mypy" ]; then
    (cd sdk/python && "$mypy" --strict src tests)
  else
    echo "run-sdk-e2e: note: mypy not found (set MYPY or put it on PATH): the Python type check is skipped"
  fi
fi

if [ "$have_node" = yes ]; then
  # Type checks are the builds (tsc --strict); the MCP server builds
  # against the SDK's output, so the SDK goes first.
  (cd sdk/ts && npm ci --no-audit --no-fund && npm run build)
  (cd sdk/mcp && npm ci --no-audit --no-fund && npm run build)
fi

filters=""
[ "$have_python" = yes ] && filters="$filters python_sdk"
[ "$have_node" = yes ] && filters="$filters typescript_sdk mcp_server"
if [ -z "$filters" ]; then
  echo "run-sdk-e2e: nothing to run"
  exit 0
fi

cd "$root/kernel"
# The suites run the hellovm, hellovm-noded and hellovm-api binaries
# next to the test.
cargo build --workspace
log=$(mktemp)
trap 'rm -f "$log"' EXIT
# shellcheck disable=SC2086
if ! cargo test -p hellovm-api --test sdk -- --ignored --exact $filters --nocapture >"$log" 2>&1; then
  cat "$log" >&2
  echo "run-sdk-e2e: the SDK tests failed" >&2
  exit 1
fi
cat "$log"
if [ "$required" = 1 ] && grep -E 'SKIPPING|skipping:' "$log" >/dev/null; then
  echo "run-sdk-e2e: the log contains SKIPPING or skipping:; a required test did not run" >&2
  exit 1
fi
echo "hellovm SDK e2e: ok"
