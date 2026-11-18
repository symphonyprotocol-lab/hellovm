# Linux build and test environment for the hellovm kernel, e.g. on a macOS
# development machine. See the "Building and testing" section of README.md.
#
# The base image is pinned to Rust 1.99.1, the same toolchain
# `rust-toolchain.toml` selects (`channel = "1.99.1"`). A floating `1.99`
# tag is a different rustup toolchain, so the component and target adds
# below would not apply to the toolchain a checkout selects.
#
# busybox-static provides /bin/busybox for the end-to-end tests; the base
# image's python3 and ldd serve the CPython and dynamic-linking tests, and
# its git and openssl, with python3-pip, the egress tests (pip install and
# git clone through the egress proxy, against local servers). The x86_64
# Rust target and cross compiler let an aarch64 machine type-check and lint
# the x86_64 build (it cannot run it). Node.js runs the TypeScript SDK's
# and the MCP server's tests (kernel/dev/run-sdk-e2e.sh): Debian's own
# nodejs is too old, so the official build is fetched and checked against
# its published SHA-256.
FROM rust:1.99.1-bookworm
RUN rustup component add clippy rustfmt \
    && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static gcc-x86-64-linux-gnu python3-pip \
    && rm -rf /var/lib/apt/lists/*
ARG NODE_VERSION=24.22.2
RUN case "$(uname -m)" in \
      x86_64) arch=x64 sha=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75 ;; \
      aarch64) arch=arm64 sha=eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8 ;; \
      *) echo "no Node.js build for $(uname -m)" >&2; exit 1 ;; \
    esac \
    && curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$arch.tar.xz" \
    && echo "$sha  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
    && rm /tmp/node.tar.xz \
    && node --version
