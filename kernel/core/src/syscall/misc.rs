//! Identity, time, scheduling and other process-level syscalls.

use std::time::Duration;

use crate::abi;
use crate::arch::Arch;
use crate::errno::{Errno, SysResult, EFAULT, EINVAL, ENOSYS, EPERM};
use crate::host::Host;
use crate::platform::{GuestAddr, Platform};
use crate::task::Restart;

use super::{Action, Ctx};

const PR_SET_PDEATHSIG: i64 = 1;
const PR_GET_PDEATHSIG: i64 = 2;
const PR_GET_DUMPABLE: i64 = 3;
const PR_SET_DUMPABLE: i64 = 4;
const PR_SET_NAME: i64 = 15;
const PR_GET_NAME: i64 = 16;
const PR_SET_NO_NEW_PRIVS: i64 = 38;
const PR_GET_NO_NEW_PRIVS: i64 = 39;
const PR_SET_CHILD_SUBREAPER: i64 = 36;

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    pub fn sys_getresid(&mut self, a: GuestAddr, b: GuestAddr, c: GuestAddr) -> SysResult<u64> {
        for addr in [a, b, c] {
            self.write_u32(addr, 0)?;
        }
        Ok(0)
    }

    pub fn sys_uname(&mut self, buf: GuestAddr) -> SysResult<u64> {
        let machine = self.arch.name();
        let uts = abi::encode_utsname([
            "Linux",
            "hellovm",
            "6.1.0-hellovm",
            "#1 SMP hellovm",
            machine,
            "(none)",
        ]);
        self.write_mem(buf, &uts)?;
        Ok(0)
    }

    pub fn sys_sysinfo(&mut self, buf: GuestAddr) -> SysResult<u64> {
        let mut info = [0u8; 112];
        let uptime = self.host.clock_monotonic().as_secs();
        info[..8].copy_from_slice(&uptime.to_le_bytes());
        info[32..40].copy_from_slice(&(1u64 << 30).to_le_bytes()); // totalram
        info[40..48].copy_from_slice(&(1u64 << 29).to_le_bytes()); // freeram
        let procs = self.st.threads.len().min(u16::MAX as usize) as u16;
        info[80..82].copy_from_slice(&procs.to_le_bytes()); // procs
        info[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
        self.write_mem(buf, &info)?;
        Ok(0)
    }

    pub fn sys_prctl(&mut self, option: i64, arg: u64) -> SysResult<u64> {
        match option {
            PR_SET_NAME => {
                let name = self.read_cstr(arg, 16).or_else(|err| {
                    if err == Errno(crate::errno::ENAMETOOLONG) {
                        // Longer names are truncated.
                        self.read_mem(arg, 15)
                    } else {
                        Err(err)
                    }
                })?;
                self.proc_mut().name = name[..name.len().min(15)].to_vec();
                Ok(0)
            }
            PR_GET_NAME => {
                let mut name = self.proc().name.clone();
                name.resize(16, 0);
                self.write_mem(arg, &name)?;
                Ok(0)
            }
            PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_NO_NEW_PRIVS | PR_SET_CHILD_SUBREAPER => {
                Ok(0)
            }
            PR_GET_PDEATHSIG => {
                self.write_u32(arg, 0)?;
                Ok(0)
            }
            PR_GET_DUMPABLE => Ok(1),
            PR_GET_NO_NEW_PRIVS => Ok(0),
            _ => {
                log::warn!("unimplemented prctl option {option}");
                Err(Errno(EINVAL))
            }
        }
    }

    pub fn sys_arch_prctl(&mut self, code: u64, addr: u64) -> SysResult<u64> {
        if self.arch != Arch::X86_64 {
            return Err(Errno(ENOSYS));
        }
        match code {
            ARCH_SET_FS => {
                let mut context = self.plat.context(self.task).map_err(|_| Errno(EINVAL))?;
                context.set_thread_pointer(addr);
                context.set_ret(0);
                self.plat
                    .set_context(self.task, &context)
                    .map_err(|_| Errno(EINVAL))?;
                self.action = Some(Action::Continue);
                Ok(0)
            }
            ARCH_GET_FS => {
                let context = self.plat.context(self.task).map_err(|_| Errno(EFAULT))?;
                self.write_u64(addr, context.thread_pointer())?;
                Ok(0)
            }
            ARCH_GET_GS => {
                self.write_u64(addr, 0)?;
                Ok(0)
            }
            ARCH_SET_GS => Err(Errno(EPERM)),
            _ => Err(Errno(EINVAL)),
        }
    }

    pub fn sys_getrandom(&mut self, buf: GuestAddr, len: u64, flags: u64) -> SysResult<u64> {
        // GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE.
        if flags & !7 != 0 {
            return Err(Errno(EINVAL));
        }
        let len = (len as usize).min(1 << 20);
        let mut data = vec![0u8; len];
        self.host
            .random(&mut data)
            .map_err(|err| Errno::from_host(&err))?;
        self.write_mem(buf, &data)?;
        Ok(len as u64)
    }

    fn clock(&mut self, clock: i64) -> SysResult<Duration> {
        Ok(match clock {
            // REALTIME, REALTIME_COARSE, REALTIME_ALARM, TAI.
            0 | 5 | 8 | 11 => self.host.clock_realtime(),
            // MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME,
            // BOOTTIME_ALARM; process and thread CPU clocks (a single
            // thread that is always running, as far as it can tell).
            1 | 4 | 6 | 7 | 9 | 2 | 3 => self.host.clock_monotonic(),
            // Per-process and per-thread CPU clocks by id.
            c if c < 0 => self.host.clock_monotonic(),
            _ => return Err(Errno(EINVAL)),
        })
    }

    pub fn sys_clock_gettime(&mut self, clock: i64, tp: GuestAddr) -> SysResult<u64> {
        let t = self.clock(clock)?;
        self.write_mem(
            tp,
            &abi::encode_pair(t.as_secs() as i64, i64::from(t.subsec_nanos())),
        )?;
        Ok(0)
    }

    pub fn sys_clock_getres(&mut self, clock: i64, res: GuestAddr) -> SysResult<u64> {
        self.clock(clock)?;
        if res != 0 {
            self.write_mem(res, &abi::encode_pair(0, 1))?;
        }
        Ok(0)
    }

    pub fn sys_gettimeofday(&mut self, tv: GuestAddr, tz: GuestAddr) -> SysResult<u64> {
        let t = self.host.clock_realtime();
        if tv != 0 {
            self.write_mem(
                tv,
                &abi::encode_pair(t.as_secs() as i64, i64::from(t.subsec_micros())),
            )?;
        }
        if tz != 0 {
            self.write_mem(tz, &[0; 8])?;
        }
        Ok(0)
    }

    pub fn sys_time(&mut self, tloc: GuestAddr) -> SysResult<u64> {
        let secs = self.host.clock_realtime().as_secs();
        if tloc != 0 {
            self.write_u64(tloc, secs)?;
        }
        Ok(secs)
    }

    pub fn sys_times(&mut self, buf: GuestAddr) -> SysResult<u64> {
        if buf != 0 {
            self.write_mem(buf, &[0; 32])?;
        }
        let t = self.host.clock_monotonic();
        Ok(t.as_millis() as u64 / 10)
    }

    pub fn sys_getrusage(&mut self, buf: GuestAddr) -> SysResult<u64> {
        self.write_mem(buf, &[0; 144])?;
        Ok(0)
    }

    /// Sleeps until `deadline` on `clock`; with `rem`, reports the time left
    /// when interrupted.
    fn sleep(&mut self, request: Duration, rem: GuestAddr) -> SysResult<u64> {
        if self.timed_out() || request.is_zero() {
            return Ok(0);
        }
        let _ = rem;
        Err(self.park_retry(Some(request), Restart::Never))
    }

    pub fn sys_nanosleep(&mut self, req: GuestAddr, rem: GuestAddr) -> SysResult<u64> {
        let d = self.read_timespec(req)?;
        self.sleep(d, rem)
    }

    pub fn sys_clock_nanosleep(
        &mut self,
        clock: i64,
        flags: u64,
        req: GuestAddr,
        rem: GuestAddr,
    ) -> SysResult<u64> {
        const TIMER_ABSTIME: u64 = 1;
        let mut d = self.read_timespec(req)?;
        if flags & TIMER_ABSTIME != 0 {
            if self.parked.is_none() {
                d = d.saturating_sub(self.clock(clock)?);
            }
        } else {
            self.clock(clock)?;
        }
        self.sleep(d, if flags & TIMER_ABSTIME != 0 { 0 } else { rem })
    }

    pub fn sys_sched_getparam(&mut self, param: GuestAddr) -> SysResult<u64> {
        self.write_u32(param, 0)?;
        Ok(0)
    }

    /// `capget`: the guest is root with every capability.
    pub fn sys_capget(&mut self, data: GuestAddr) -> SysResult<u64> {
        if data != 0 {
            // Two 32-bit-capability triples (effective, permitted,
            // inheritable): all set.
            let mut caps = [0u8; 24];
            for (i, chunk) in caps.chunks_mut(4).enumerate() {
                let v: u32 = if i % 3 == 2 { 0 } else { u32::MAX };
                chunk.copy_from_slice(&v.to_le_bytes());
            }
            self.write_mem(data, &caps)?;
        }
        Ok(0)
    }

    pub fn sys_sched_getaffinity(&mut self, len: u64, mask: GuestAddr) -> SysResult<u64> {
        if len < 8 || !len.is_multiple_of(8) {
            return Err(Errno(EINVAL));
        }
        self.write_u64(mask, 1)?;
        Ok(8)
    }

    pub fn sys_getcpu(&mut self, cpu: GuestAddr, node: GuestAddr) -> SysResult<u64> {
        for addr in [cpu, node] {
            if addr != 0 {
                self.write_u32(addr, 0)?;
            }
        }
        Ok(0)
    }
}
