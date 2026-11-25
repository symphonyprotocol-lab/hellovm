//! End-to-end tests of the KVM platform: the shared suite of the arm64 VM
//! platforms (`platform-arm64/suite/platform.rs`), which the HVF platform
//! runs on macOS. Without `/dev/kvm` the tests print `SKIPPING` and pass,
//! unless `HELLOVM_REQUIRE_E2E=1`.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use hellovm_platform_kvm::{KvmConfig as TestConfig, KvmPlatform as TestPlatform};

const NAME: &str = "KVM";
const VCPUS_VAR: &str = "HELLOVM_KVM_VCPUS";
include!("../../platform-arm64/suite/platform.rs");
