//! The HVF platform: runs aarch64 Linux apps in a virtual machine of
//! Hypervisor.framework, on macOS on Apple silicon: processes with
//! `fork` (copy-on-write), `execve` and dynamic linking, on one vCPU (see
//! README, "The HVF platform").
//!
//! # How app code runs
//!
//! The app runs at EL0 of a VM that has no guest kernel. At EL1 there is
//! only a shim of a few instructions (`layout::shim_code`): each of the 16
//! exception vectors is `hvc #slot`. A `svc` (system call), a fault, an
//! undefined instruction, any exception the app takes, lands in a vector
//! and leaves the VM: `hv_vcpu_run` returns in the kernel process, which
//! reads the app's untouched registers and `ESR_EL1`/`FAR_EL1`/`ELR_EL1`,
//! and reports a [`Trap`](hellovm_core::platform::Trap) to the core. To
//! resume, the host sets `PC` and `CPSR` (EL0t) itself; nothing at EL1
//! runs on the way back unless page tables changed, when the vCPU first
//! runs one of the shim's flush routines (the whole TLB, or one page).
//!
//! The vCPU belongs to the thread that made the platform, the kernel's
//! event-loop thread, and runs inside [`Platform::wait`]: the core's
//! "resume never blocks" holds because `resume` only marks a task
//! runnable. Tasks (every thread of every process) are register contexts
//! multiplexed on that one vCPU: the runnable task that has run least
//! goes next, and while another one is runnable a task runs for one slice
//! at most. A timeout of `wait`, or the end of a slice, is the guest's
//! virtual timer, which makes the vCPU exit
//! (`HV_EXIT_REASON_VTIMER_ACTIVATED`); a [`Waker`] or the [`AppKiller`]
//! calls `hv_vcpus_exit`.
//!
//! # Address spaces
//!
//! hellovm writes the stage-1 page tables (4 KiB granule, 48-bit, four
//! levels) itself, in a pool of host memory the VM maps read only at stage
//! 2; app pages come from another pool that stage 2 maps read, write and
//! execute, and get memory on first touch. A process's address space has
//! its own ASID. `fork` copies the tables and shares every frame
//! copy-on-write; frames have reference counts on the host side. See
//! `mmu` (and what keeps address spaces apart) and `layout` for the
//! guest-physical layout, the descriptor bits and the system registers.
//!
//! # What the app can reach
//!
//! The isolation boundary is the stage-2 mapping: the VM's guest-physical
//! space is exactly three host allocations of this platform (shim, page
//! tables, app memory), so nothing in the VM can address any other host
//! memory. Inside it, the stage-1 tables decide what EL0 may touch: the
//! pages the core mapped, with their protections, and nothing else. The
//! shim and the vectors are mapped for EL1 only (read and execute), the
//! page tables are not mapped at stage 1 at all, and stage 2 makes both
//! unwritable even for EL1. EL0 reaches EL1 only through an exception,
//! which goes to the shim and out of the VM at once.
//!
//! [`Platform::wait`]: hellovm_core::platform::Platform::wait
//! [`Waker`]: hellovm_core::platform::Waker

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod app;
mod exit;
mod layout;
mod mmu;
mod sys;

pub use app::{AppKiller, Flushes, HvfConfig, HvfPlatform};

/// Whether this process may use Hypervisor.framework: `Ok` if a VM could
/// be created (and was destroyed again), otherwise why not. A process
/// whose executable lacks the `com.apple.security.hypervisor` entitlement
/// gets `PermissionDenied`; one that already has a VM, `ResourceBusy`.
pub fn check_access() -> std::io::Result<()> {
    sys::Vm::create().map(drop).map_err(Into::into)
}
