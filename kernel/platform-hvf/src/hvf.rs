//! [`Hvf`]: Hypervisor.framework as the hypervisor of the shared arm64
//! platform (`hellovm-platform-arm64`).
//!
//! The shim's vectors are `hvc #slot` (`layout::shim_code`): an exception
//! of the app leaves the VM with the registers untouched, and the host
//! reads them, and the EL1 registers that describe the exception, from
//! the vCPU. To resume, the host sets `PC` and `CPSR` (EL0t) itself, or
//! points the vCPU at one of the shim's flush routines. The guest's
//! virtual timer ends a run at a deadline; `hv_vcpus_exit` kicks a vCPU
//! out from another thread.

use std::io;
use std::time::Instant;

use hellovm_core::platform::Aarch64Context;
use hellovm_platform_arm64::layout::{self, FLUSH_OFFSET, FLUSH_PAGE_OFFSET, PAGE, SHIM_VA};
use hellovm_platform_arm64::mmu::{MmuError, Phys};
use hellovm_platform_arm64::{
    exit, Backing, Exit, Flush, Hypervisor, IdRegs, Kicker, Reg, Stopped, Vcpu,
};

use crate::sys::{
    self, sysreg, HostMem, VcpuKicker, Vm, VmToken, HV_EXIT_REASON_CANCELED,
    HV_EXIT_REASON_EXCEPTION, HV_EXIT_REASON_VTIMER_ACTIVATED, HV_MEMORY_EXEC, HV_MEMORY_READ,
    HV_MEMORY_WRITE, HV_REG_CPSR, HV_REG_FPCR, HV_REG_FPSR, HV_REG_PC,
};

impl Backing for HostMem {
    fn bytes(&self) -> &[u8] {
        self.slice(0, self.len())
    }

    fn len(&self) -> usize {
        HostMem::len(self)
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.slice_mut(0, self.len())
    }

    fn sync_icache(&mut self, offset: usize, len: usize) {
        self.check_range(offset, len);
        // SAFETY: in bounds (checked); the call only maintains caches.
        sys::icache_invalidate(unsafe { self.ptr().add(offset) }, len);
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) {
        HostMem::read_at(self, offset, buf)
    }

    fn write_at(&mut self, offset: usize, data: &[u8]) {
        HostMem::write_at(self, offset, data)
    }

    fn copy_at(&mut self, from: usize, to: usize, len: usize) {
        HostMem::copy_at(self, from, to, len)
    }

    fn zero_at(&mut self, offset: usize, len: usize) {
        HostMem::zero_at(self, offset, len)
    }

    fn store_u64(&mut self, offset: usize, value: u64) {
        HostMem::store_u64(self, offset, value)
    }

    fn give_back(&mut self, offset: usize, len: usize) {
        HostMem::give_back(self, offset, len)
    }

    fn take_back(&mut self, offset: usize, len: usize) {
        HostMem::take_back(self, offset, len)
    }
}

impl Kicker for VcpuKicker {
    fn kick(&self) {
        VcpuKicker::kick(self)
    }
}

/// The process's VM (Hypervisor.framework allows one per process) with
/// its shim page.
pub struct Hvf {
    // Field order is drop order: the VM, then the memory behind it.
    vm: Vm,
    _shim: HostMem,
}

impl Hypervisor for Hvf {
    const NAME: &'static str = "HVF";
    const SNAPSHOT_PREFIX: &'static str = "hellovm-hvf-";
    type Mem = HostMem;
    type Token = VmToken;
    type Vcpu = HvfVcpu;
    type Kicker = VcpuKicker;

    fn create(memory: usize, table_memory: usize) -> io::Result<(Hvf, HostMem, HostMem)> {
        let vm = Vm::create()?;
        let mut shim = HostMem::new(layout::SHIM_REGION as usize)?;
        let tables = HostMem::new(table_memory)?;
        let ram = HostMem::new(memory)?;
        let code = layout::shim_code();
        shim.slice_mut(0, code.len()).copy_from_slice(&code);
        shim.sync_icache(0, code.len());
        // SAFETY: each region lives until after the VM is destroyed (the
        // shim in `Hvf`, after its VM; the pools in the platform, which
        // drops its `Hvf` first), and holds only what the guest may see:
        // the shim, the guest's page tables (read only) and app memory.
        unsafe {
            vm.map(
                shim.ptr(),
                layout::SHIM_IPA,
                shim.len(),
                HV_MEMORY_READ | HV_MEMORY_EXEC,
            )?;
            vm.map(
                tables.ptr(),
                layout::TABLES_IPA,
                tables.len(),
                HV_MEMORY_READ,
            )?;
            vm.map(
                ram.ptr(),
                layout::RAM_IPA,
                ram.len(),
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )?;
        }
        Ok((Hvf { vm, _shim: shim }, tables, ram))
    }

    fn shim_space(&self, phys: &mut Phys<HostMem>) -> Result<u64, MmuError> {
        phys.shim_space()
    }

    fn max_vcpus(&self) -> u32 {
        self.vm.max_vcpus().unwrap_or(1)
    }

    fn token(&self) -> VmToken {
        self.vm.token()
    }

    fn vcpu(token: VmToken, _index: usize) -> io::Result<HvfVcpu> {
        let vcpu = sys::Vcpu::create(token)?;
        let mut timebase = sys::MachTimebaseInfo::default();
        sys::timebase(&mut timebase);
        let ticks_per_sec = if timebase.numer == 0 {
            24_000_000
        } else {
            1_000_000_000 * u64::from(timebase.denom) / u64::from(timebase.numer)
        };
        Ok(HvfVcpu {
            vcpu,
            ticks_per_sec,
            timer_armed: false,
            armed_for: None,
        })
    }

    fn release(&mut self, table_memory: usize, memory: usize) {
        for (ipa, len) in [
            (layout::SHIM_IPA, layout::SHIM_REGION as usize),
            (layout::TABLES_IPA, table_memory),
            (layout::RAM_IPA, memory),
        ] {
            if let Err(err) = self.vm.unmap(ipa, len) {
                log::warn!("{err}");
            }
        }
    }
}

/// A vCPU of the VM, with its virtual timer.
pub struct HvfVcpu {
    pub(crate) vcpu: sys::Vcpu,
    /// `mach_absolute_time` ticks per second.
    ticks_per_sec: u64,
    timer_armed: bool,
    /// The deadline the armed timer has.
    armed_for: Option<Instant>,
}

impl HvfVcpu {
    /// Where the app was when the vCPU was stopped from outside (by
    /// `hv_vcpus_exit` or the timer), which can be anywhere.
    pub(crate) fn interrupted_at(&mut self) -> io::Result<Stopped> {
        let cpsr = self.vcpu.reg(HV_REG_CPSR)?;
        let pc = self.vcpu.reg(HV_REG_PC)?;
        if cpsr & 0xf == 0 {
            // In the app (EL0t).
            return Ok(Stopped::At { pc, pstate: cpsr });
        }
        if (SHIM_VA..SHIM_VA + FLUSH_OFFSET).contains(&pc) {
            return Ok(Stopped::InVector);
        }
        if (SHIM_VA + FLUSH_PAGE_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the page flush routine: x0 may still be its operand. The
            // app's own is in TPIDR_EL1; it starts over, with a whole
            // flush.
            let x0 = self.vcpu.sys_reg(sysreg::TPIDR_EL1)?;
            self.vcpu.set_reg(0, x0)?;
            return Ok(Stopped::Flushing);
        }
        if (SHIM_VA + FLUSH_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the flush routine, before the app ran: it starts over,
            // flushing again.
            return Ok(Stopped::Flushing);
        }
        Ok(Stopped::Lost(format!(
            "stopped at EL1 outside the shim, pc {pc:#x} cpsr {cpsr:#x}"
        )))
    }
}

impl Vcpu for HvfVcpu {
    type Kicker = VcpuKicker;

    fn kicker(&self) -> VcpuKicker {
        self.vcpu.kicker()
    }

    fn id_regs(&self) -> io::Result<IdRegs> {
        let v = &self.vcpu;
        Ok(IdRegs {
            mmfr0: v.sys_reg(sysreg::ID_AA64MMFR0_EL1)?,
            pfr0: v.sys_reg(sysreg::ID_AA64PFR0_EL1)?,
            isar0: v.sys_reg(sysreg::ID_AA64ISAR0_EL1)?,
            isar1: v.sys_reg(sysreg::ID_AA64ISAR1_EL1)?,
        })
    }

    fn set_up(&mut self, tcr: u64, shim_root: u64) -> io::Result<()> {
        for (reg, value) in [
            (sysreg::MAIR_EL1, layout::MAIR_EL1),
            (sysreg::TCR_EL1, tcr),
            (sysreg::TTBR1_EL1, shim_root),
            (sysreg::TTBR0_EL1, 0),
            (sysreg::VBAR_EL1, SHIM_VA),
            (sysreg::CPACR_EL1, layout::CPACR_EL1),
            (sysreg::CNTKCTL_EL1, layout::CNTKCTL_EL1),
            (sysreg::CNTV_CTL_EL0, 0),
            (sysreg::SP_EL1, 0),
            (sysreg::TPIDRRO_EL0, 0),
            (sysreg::SCTLR_EL1, layout::SCTLR_EL1),
        ] {
            self.vcpu.set_sys_reg(reg, value)?;
        }
        Ok(())
    }

    fn read_context(&self) -> io::Result<Box<Aarch64Context>> {
        let v = &self.vcpu;
        let mut c = Box::new(Aarch64Context {
            x: [0; 31],
            sp: v.sys_reg(sysreg::SP_EL0)?,
            pc: 0,
            pstate: 0,
            v: [0; 32],
            fpsr: v.reg(HV_REG_FPSR)? as u32,
            fpcr: v.reg(HV_REG_FPCR)? as u32,
            tpidr: v.sys_reg(sysreg::TPIDR_EL0)?,
        });
        for (i, x) in c.x.iter_mut().enumerate() {
            *x = v.reg(i as u32)?;
        }
        for (i, q) in c.v.iter_mut().enumerate() {
            *q = v.simd(i as u32)?;
        }
        Ok(c)
    }

    fn write_context(&mut self, c: &Aarch64Context) -> io::Result<()> {
        let v = &self.vcpu;
        for (i, &x) in c.x.iter().enumerate() {
            v.set_reg(i as u32, x)?;
        }
        for (i, &q) in c.v.iter().enumerate() {
            v.set_simd(i as u32, q)?;
        }
        v.set_sys_reg(sysreg::SP_EL0, c.sp)?;
        v.set_sys_reg(sysreg::TPIDR_EL0, c.tpidr)?;
        v.set_reg(HV_REG_FPSR, u64::from(c.fpsr))?;
        v.set_reg(HV_REG_FPCR, u64::from(c.fpcr))?;
        Ok(())
    }

    fn reg(&self, reg: Reg) -> io::Result<u64> {
        let v = &self.vcpu;
        Ok(match reg {
            Reg::X(i) => v.reg(u32::from(i.min(30)))?,
            Reg::Pc => v.reg(HV_REG_PC)?,
            Reg::Cpsr => v.reg(HV_REG_CPSR)?,
            Reg::ElrEl1 => v.sys_reg(sysreg::ELR_EL1)?,
            Reg::SpsrEl1 => v.sys_reg(sysreg::SPSR_EL1)?,
            Reg::EsrEl1 => v.sys_reg(sysreg::ESR_EL1)?,
            Reg::FarEl1 => v.sys_reg(sysreg::FAR_EL1)?,
            Reg::SpEl0 => v.sys_reg(sysreg::SP_EL0)?,
        })
    }

    fn set_x0(&mut self, value: u64) -> io::Result<()> {
        Ok(self.vcpu.set_reg(0, value)?)
    }

    fn set_ttbr0(&mut self, value: u64) -> io::Result<()> {
        Ok(self.vcpu.set_sys_reg(sysreg::TTBR0_EL1, value)?)
    }

    fn arm_timer(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        match deadline {
            None => {
                if self.timer_armed {
                    self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 0)?;
                    self.timer_armed = false;
                }
            }
            // Armed for it already (a trap since does not disarm it).
            Some(deadline) if self.timer_armed && self.armed_for == Some(deadline) => {}
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let ticks = (left.as_nanos() * u128::from(self.ticks_per_sec) / 1_000_000_000)
                    .min(u128::from(u64::MAX / 2)) as u64;
                let cval = self.vcpu.guest_counter()?.saturating_add(ticks);
                self.vcpu.set_sys_reg(sysreg::CNTV_CVAL_EL0, cval)?;
                // ENABLE, interrupt not masked: the framework exits with
                // HV_EXIT_REASON_VTIMER_ACTIVATED when it fires.
                self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 1)?;
                self.vcpu.set_vtimer_mask(false)?;
                self.timer_armed = true;
                self.armed_for = Some(deadline);
            }
        }
        Ok(())
    }

    fn enter(&mut self, pc: u64, pstate: u64, flush: Flush) -> io::Result<()> {
        let v = &self.vcpu;
        match flush {
            Flush::All => {
                v.set_sys_reg(sysreg::ELR_EL1, pc)?;
                v.set_sys_reg(sysreg::SPSR_EL1, pstate)?;
                v.set_reg(HV_REG_PC, SHIM_VA + FLUSH_OFFSET)?;
                v.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)?;
            }
            Flush::Page(operand) => {
                // The routine takes its operand in x0 and gives the app
                // its own back from TPIDR_EL1.
                let x0 = v.reg(0)?;
                v.set_sys_reg(sysreg::TPIDR_EL1, x0)?;
                v.set_reg(0, operand)?;
                v.set_sys_reg(sysreg::ELR_EL1, pc)?;
                v.set_sys_reg(sysreg::SPSR_EL1, pstate)?;
                v.set_reg(HV_REG_PC, SHIM_VA + FLUSH_PAGE_OFFSET)?;
                v.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)?;
            }
            Flush::None => {
                v.set_reg(HV_REG_PC, pc)?;
                v.set_reg(HV_REG_CPSR, pstate)?;
            }
        }
        Ok(())
    }

    fn run(&mut self) -> io::Result<Exit> {
        let exit = self.vcpu.run()?;
        Ok(match exit.reason {
            HV_EXIT_REASON_CANCELED | HV_EXIT_REASON_VTIMER_ACTIVATED => {
                if exit.reason == HV_EXIT_REASON_VTIMER_ACTIVATED {
                    self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 0)?;
                    self.timer_armed = false;
                }
                Exit::Stopped(self.interrupted_at()?)
            }
            // `hvc` is undefined at EL0, so an `hvc` exit came from a
            // vector of the shim.
            HV_EXIT_REASON_EXCEPTION => match exit::hvc_immediate(exit.syndrome) {
                Some(slot) => Exit::Vector(slot),
                None => Exit::Direct {
                    syndrome: exit.syndrome,
                    virtual_address: exit.virtual_address,
                    physical_address: exit.physical_address,
                },
            },
            other => Exit::Unexpected(format!("unexpected exit reason {other}")),
        })
    }
}
