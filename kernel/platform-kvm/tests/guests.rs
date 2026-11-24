//! Real programs on the KVM platform, through the kernel core: the C test
//! guests (`kernel/test-guest/c`), a busybox shell and CPython, from the
//! image `kernel/platform-hvf/build-guests.sh` assembles in the Linux dev
//! container (the same image as for the HVF platform). Its path is
//! `HELLOVM_KVM_GUESTS`; without it (or without `/dev/kvm`) the tests
//! print `SKIPPING` and pass, unless `HELLOVM_REQUIRE_E2E=1`.
//!
//! The tests are the shared suite of the arm64 VM platforms
//! (`platform-arm64/suite/guests.rs`).

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use hellovm_platform_kvm::{KvmConfig as TestConfig, KvmPlatform as TestPlatform};

const NAME: &str = "KVM";
const VCPUS_VAR: &str = "HELLOVM_KVM_VCPUS";
const GUESTS_VAR: &str = "HELLOVM_KVM_GUESTS";
include!("../../platform-arm64/suite/guests.rs");
