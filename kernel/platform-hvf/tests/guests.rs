//! Real programs on the HVF platform, through the kernel core: the C test
//! guests (`kernel/test-guest/c`), a busybox shell and CPython, from the
//! image `kernel/platform-hvf/build-guests.sh` assembles in the Linux dev
//! container. Its path is `HELLOVM_HVF_GUESTS`; without it (or without
//! the hypervisor) the tests print `SKIPPING` and pass, unless
//! `HELLOVM_REQUIRE_E2E=1`.
//!
//! Every test checks afterwards that every frame of app memory went back
//! to the pool and that only the shim's page tables are left.
//!
//! The tests are the shared suite of the arm64 VM platforms
//! (`platform-arm64/suite/guests.rs`), which the KVM platform runs too.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use hellovm_platform_hvf::{HvfConfig as TestConfig, HvfPlatform as TestPlatform};

const NAME: &str = "HVF";
const VCPUS_VAR: &str = "HELLOVM_HVF_VCPUS";
const GUESTS_VAR: &str = "HELLOVM_HVF_GUESTS";
include!("../../platform-arm64/suite/guests.rs");
