//! End-to-end tests of the HVF platform on this Mac.
//!
//! The tests are the shared suite of the arm64 VM platforms
//! (`platform-arm64/suite/platform.rs`), which the KVM platform runs too.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use hellovm_platform_hvf::{HvfConfig as TestConfig, HvfPlatform as TestPlatform};

const NAME: &str = "HVF";
const VCPUS_VAR: &str = "HELLOVM_HVF_VCPUS";
include!("../../platform-arm64/suite/platform.rs");
