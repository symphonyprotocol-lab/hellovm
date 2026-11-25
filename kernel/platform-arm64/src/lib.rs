//! What the hellovm platforms that run aarch64 Linux apps in a virtual
//! machine share, whatever the hypervisor: the HVF platform (macOS,
//! Hypervisor.framework, `hellovm-platform-hvf`) and the KVM platform
//! (Linux, `/dev/kvm`, `hellovm-platform-kvm`). See README, "The HVF
//! platform" and "The KVM platform".
//!
//! # How app code runs
//!
//! The app runs at EL0 of a VM that has no guest kernel. At EL1 there is
//! only a shim of a few instructions (the backend's): each of the 16
//! exception vectors leaves the VM. A `svc` (system call), a fault, an
//! undefined instruction, any exception the app takes, lands in a vector
//! and leaves the VM: the backend's [`Vcpu::run`] returns in the kernel
//! process, which reads the app's registers and `ESR_EL1`/`FAR_EL1`/
//! `ELR_EL1` ([`exit`] decodes them), and reports a
//! [`Trap`](hellovm_core::platform::Trap) to the core. To resume, the
//! host points the vCPU back at the app, through one of the shim's flush
//! routines when page tables changed (the whole TLB, or one page).
//!
//! vCPU 0 belongs to the thread that made the platform, the kernel's
//! event-loop thread, and runs inside [`Platform::wait`]; every other
//! vCPU has a host thread of its own, made with the platform. The core's
//! "resume never blocks" holds because `resume` only marks a task
//! runnable. Tasks (every thread of every process) are register contexts
//! that the vCPUs take from one scheduler: the runnable task that has run
//! least goes next, a task whose registers are still in a vCPU waits for
//! that one, and a task runs for one slice at most (on vCPU 0 alone: while
//! another one is runnable). A timeout of `wait`, or the end of a slice,
//! is the backend's timer ([`Vcpu::arm_timer`]); a [`Waker`], the
//! [`AppKiller`], a trap on another vCPU for the event loop, or a change
//! to page tables that a running vCPU may hold in its TLB, kicks the vCPU
//! out ([`Kicker`]). The other vCPUs report their traps to `wait` through
//! a queue.
//!
//! # Address spaces
//!
//! hellovm writes the stage-1 page tables (4 KiB granule, 48-bit, four
//! levels) itself, in a pool of host memory the VM maps read only at stage
//! 2; app pages come from another pool that stage 2 maps read and write,
//! and get memory on first touch. A process's address space has its own
//! ASID. The tables and pools are behind one lock, held from a change
//! until every vCPU that may hold a stale TLB entry of it has left the
//! VM, and every vCPU invalidates before it runs an app again. `fork`
//! copies the tables and shares every frame copy-on-write; frames have
//! reference counts on the host side. See [`mmu`] (and what keeps address
//! spaces apart) and [`layout`] for the guest-physical layout, the
//! descriptor bits and the system registers.
//!
//! [`Platform::wait`]: hellovm_core::platform::Platform::wait
//! [`Waker`]: hellovm_core::platform::Waker

pub mod backend;
pub mod exit;
pub mod layout;
pub mod mmu;
mod vm;

#[cfg(feature = "testing")]
pub use vm::testing;

pub use backend::{Exit, Flush, Hypervisor, IdRegs, Kicker, Reg, Stopped, Vcpu};
pub use mmu::{Backing, El1Page, Origin, SaveStats, Trimmed};
pub use vm::{AppKiller, Flushes, VmConfig, VmPlatform, MAX_VCPUS};
