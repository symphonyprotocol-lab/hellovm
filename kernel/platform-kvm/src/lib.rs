//! The KVM platform: runs aarch64 Linux apps in a virtual machine of KVM
//! (`/dev/kvm`) on arm64 Linux, the way the HVF platform runs them in one
//! of Hypervisor.framework on macOS (see README, "The KVM platform").
//!
//! The platform itself (the scheduler, the page tables, the decoding of
//! exceptions) is `hellovm-platform-arm64`'s, shared with the HVF
//! platform; this crate is its KVM backend ([`Kvm`]): the VM and its
//! memory slots, a shim that saves the app's registers to memory and
//! leaves the VM with one MMIO store (`shim`), the vCPUs, the IRQ line
//! that kicks a vCPU out, the clock thread for deadlines, and host memory
//! given back with `madvise(MADV_DONTNEED)` (`sys`).
//!
//! # What the app can reach
//!
//! The VM's guest-physical space is exactly four memory slots of this
//! platform: the shim (read only), the vCPUs' register frames, the page
//! tables (read only) and app memory; nothing in the VM can address any
//! other host memory. KVM's memory slots cannot forbid execution, so
//! stage 1 does: the stage-1 tables hellovm writes decide what EL0 may
//! touch (the pages the core mapped, with their protections, and nothing
//! else); the shim is mapped for EL1 only (read and execute), the frames
//! and the exit page for EL1 only and never executable, and the page
//! tables not at all. EL0 reaches EL1 only through an exception, which
//! goes to the shim and out of the VM.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

mod kvm;
mod shim;
mod sys;

#[cfg(test)]
mod tests;

pub use hellovm_platform_arm64::{Flushes, Trimmed, MAX_VCPUS};
pub use kvm::{Kvm, KvmKicker, KvmVcpu};

/// The KVM platform: the shared arm64 platform on a KVM VM.
pub type KvmPlatform = hellovm_platform_arm64::VmPlatform<Kvm>;
/// How much memory a [`KvmPlatform`] reserves and how many vCPUs it runs.
pub type KvmConfig = hellovm_platform_arm64::VmConfig;
/// Ends every app of a [`KvmPlatform`] from any thread.
pub type AppKiller = hellovm_platform_arm64::AppKiller<Kvm>;

/// Whether this process may use KVM: `Ok` if `/dev/kvm` opens and has
/// what the platform needs, otherwise why not (`NotFound` without
/// `/dev/kvm`, `PermissionDenied` without access to it).
pub fn check_access() -> std::io::Result<()> {
    let kvm = sys::Kvm::open()?;
    for cap in [
        sys::KVM_CAP_USER_MEMORY,
        sys::KVM_CAP_ONE_REG,
        sys::KVM_CAP_READONLY_MEM,
    ] {
        if kvm.extension(cap) <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("the host's KVM lacks capability {cap}"),
            ));
        }
    }
    Ok(())
}
