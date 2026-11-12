# Linux build and test environment for the hellovm kernel, e.g. on a macOS
# development machine. See the "Building and testing" section of README.md.
#
# busybox-static provides /bin/busybox for the end-to-end tests. The x86_64
# Rust target and cross compiler let an aarch64 machine type-check and lint
# the x86_64 build (it cannot run it).
FROM rust:1.99-bookworm
RUN rustup component add clippy rustfmt \
    && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static gcc-x86-64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*
