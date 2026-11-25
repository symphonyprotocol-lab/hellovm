//! Warm clones on macOS (the HVF platform), end to end: `hellovm
//! --template` with CPython and busybox from the guest image
//! (`HELLOVM_HVF_GUESTS`), clones made through the control socket
//! (`hellovm::warm`) and the `--clone` command line, all under `--sandbox
//! require`. The macOS counterpart of `warm.rs`: what a clone sees, that
//! clones are isolated from the template and from each other, input and
//! exit status, `--ready`, `--timeout`, a template that dies, requesters
//! that break the protocol, many clones.
//!
//! One test at a time, as in every HVF test (`hvf_support::serial`), and
//! in all tests but one, one VM at a time: the template's kernel process
//! has exited before the first clone starts, and each clone's kernel
//! process is gone before the next one starts. One test keeps several
//! clones alive at once (up to four VMs).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod hvf_support;

mod support {
    use std::path::{Path, PathBuf};

    pub use super::hvf_support::{serial, FREE_AND_REUSE};

    pub const PLATFORM_ARGS: &[&str] = &[];
    /// macOS has no inbound connections yet: a template refuses an
    /// ingress channel.
    pub const INGRESS: bool = false;

    /// The signed `hellovm` and the guest image, or `None` (skipped).
    pub fn setup() -> Option<(&'static Path, PathBuf)> {
        let exe = super::hvf_support::hellovm()?;
        let root = super::hvf_support::guest_image()?;
        Some((exe, root))
    }

    pub fn progress(what: &str) {
        super::hvf_support::progress(&format!("hvf_warm: {what}"));
    }

    /// Measuring what the profile lacks (README, "Warm clones on macOS"):
    /// with `HVF_WARM_LEARN` set, every kernel process learns.
    pub fn learn_env() -> Option<(&'static str, &'static str)> {
        std::env::var("HVF_WARM_LEARN")
            .ok()
            .map(|_| ("HELLOVM_SEATBELT_LEARN", "1"))
    }

    /// A process's physical footprint (what Activity Monitor calls its
    /// memory), in bytes.
    pub fn footprint(pid: u32) -> u64 {
        super::hvf_support::phys_footprint(pid)
    }

    pub fn memory_detail(_pid: u32) -> String {
        "physical footprint".into()
    }

    pub fn memory_goes_back(
        pid: u32,
        line: impl FnMut() -> String,
        send: impl FnMut(),
    ) -> [f64; 4] {
        super::hvf_support::memory_goes_back(pid, line, send)
    }

    /// `kernels` kernel processes entered the same Seatbelt profile.
    pub fn assert_confined(output: &str, kernels: usize) {
        assert_eq!(
            output.matches("Seatbelt profile: active (7 rules)").count(),
            kernels,
            "{output}"
        );
        assert_eq!(
            output
                .matches("no debugger (PT_DENY_ATTACH): active")
                .count(),
            kernels
        );
        assert_eq!(output.matches("resource limits: active").count(), kernels);
    }
}

include!("vm_warm/tests.rs");
