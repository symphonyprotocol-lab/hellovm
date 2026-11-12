//! Identity, time, signals, limits and other process-level syscalls.

use std::time::Duration;

use crate::abi;
use crate::arch::{Arch, Sysno};
use crate::errno::{Errno, SysResult, EAGAIN, EFAULT, EINVAL, ENOSYS, EPERM, ESRCH, ETIMEDOUT};
use crate::host::Host;
use crate::kernel::RLIM_INFINITY;
use crate::platform::{GuestAddr, Platform};

use super::Ctx;

/// The app's pid (and tid, pgid, sid). The app is the sandbox's first and
/// only process.
pub(crate) const PID: u64 = 1;

const SIGKILL: i64 = 9;
const SIGSTOP: i64 = 19;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

const PR_SET_PDEATHSIG: i64 = 1;
const PR_GET_DUMPABLE: i64 = 3;
const PR_SET_DUMPABLE: i64 = 4;
const PR_SET_NAME: i64 = 15;
const PR_GET_NAME: i64 = 16;
const PR_SET_NO_NEW_PRIVS: i64 = 38;
const PR_GET_NO_NEW_PRIVS: i64 = 39;

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_WAIT_BITSET: i64 = 9;
const FUTEX_WAKE_BITSET: i64 = 10;

/// Whether a signal's default action leaves the process running (ignore or
/// stop; there is no job control in U1).
fn default_is_harmless(sig: i64) -> bool {
    matches!(sig, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    /// `kill`/`tkill`/`tgkill`. Only the app itself exists; returns the
    /// signal that ends it, if any. Signal handlers are not run before U2:
    /// a signal that would reach one ends the app as its default action
    /// would.
    pub fn sys_kill(&mut self, pid: i64, sig: i64) -> SysResult<Option<u32>> {
        if !(0..=64).contains(&sig) {
            return Err(Errno(EINVAL));
        }
        if !matches!(pid, 0 | -1) && pid != PID as i64 {
            return Err(Errno(ESRCH));
        }
        if sig == 0 {
            return Ok(None);
        }
        let handler = self.proc.sigactions[sig as usize - 1][0];
        if sig != SIGKILL && sig != SIGSTOP {
            if handler == SIG_IGN || (handler == SIG_DFL && default_is_harmless(sig)) {
                return Ok(None);
            }
            if handler != SIG_DFL {
                log::warn!("signal {sig} has a handler, but signal delivery is not implemented; ending the app");
            }
        } else if sig == SIGSTOP {
            return Ok(None);
        }
        Ok(Some(sig as u32))
    }

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
        info[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs
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
                self.proc.name = name[..name.len().min(15)].to_vec();
                Ok(0)
            }
            PR_GET_NAME => {
                let mut name = self.proc.name.clone();
                name.resize(16, 0);
                self.write_mem(arg, &name)?;
                Ok(0)
            }
            PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_NO_NEW_PRIVS => Ok(0),
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
                self.app
                    .set_thread_pointer(addr)
                    .map_err(|_| Errno(EINVAL))?;
                self.proc.thread_pointer = addr;
                Ok(0)
            }
            ARCH_GET_FS => {
                let tp = self.proc.thread_pointer;
                self.write_u64(addr, tp)?;
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

    fn read_timespec(&mut self, addr: GuestAddr) -> SysResult<Duration> {
        let (sec, nsec) = abi::decode_pair(&self.read_array(addr)?);
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno(EINVAL));
        }
        Ok(Duration::new(sec as u64, nsec as u32))
    }

    pub fn sys_nanosleep(&mut self, req: GuestAddr) -> SysResult<u64> {
        let d = self.read_timespec(req)?;
        self.host.sleep(d);
        Ok(0)
    }

    pub fn sys_clock_nanosleep(
        &mut self,
        clock: i64,
        flags: u64,
        req: GuestAddr,
    ) -> SysResult<u64> {
        const TIMER_ABSTIME: u64 = 1;
        let mut d = self.read_timespec(req)?;
        if flags & TIMER_ABSTIME != 0 {
            d = d.saturating_sub(self.clock(clock)?);
        } else {
            self.clock(clock)?;
        }
        self.host.sleep(d);
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

    pub fn sys_prlimit64(
        &mut self,
        pid: i64,
        resource: u64,
        new: GuestAddr,
        old: GuestAddr,
    ) -> SysResult<u64> {
        if pid != 0 && pid != PID as i64 {
            return Err(Errno(ESRCH));
        }
        let resource = usize::try_from(resource)
            .ok()
            .filter(|&r| r < self.proc.rlimits.len())
            .ok_or(Errno(EINVAL))?;
        if old != 0 {
            let (cur, max) = self.proc.rlimits[resource];
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&cur.to_le_bytes());
            buf[8..].copy_from_slice(&max.to_le_bytes());
            self.write_mem(old, &buf)?;
        }
        if new != 0 {
            let buf: [u8; 16] = self.read_array(new)?;
            let cur = u64::from_le_bytes(buf[..8].try_into().unwrap());
            let max = u64::from_le_bytes(buf[8..].try_into().unwrap());
            if cur > max {
                return Err(Errno(EINVAL));
            }
            let (_, old_max) = self.proc.rlimits[resource];
            if max > old_max && old_max != RLIM_INFINITY {
                // Raising a hard limit is allowed for root; the fd table
                // cannot grow, though.
                if resource == 7 {
                    return Err(Errno(EPERM));
                }
            }
            self.proc.rlimits[resource] = (cur, max);
        }
        Ok(0)
    }

    pub fn sys_rt_sigaction(
        &mut self,
        sig: i64,
        act: GuestAddr,
        old: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        if size != 8 || !(1..=64).contains(&sig) {
            return Err(Errno(EINVAL));
        }
        if act != 0 && (sig == SIGKILL || sig == SIGSTOP) {
            return Err(Errno(EINVAL));
        }
        let index = sig as usize - 1;
        let current = self.proc.sigactions[index];
        let new = if act != 0 {
            let raw: [u8; 32] = self.read_array(act)?;
            let mut fields = [0u64; 4];
            for (i, field) in fields.iter_mut().enumerate() {
                *field = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
            }
            Some(fields)
        } else {
            None
        };
        if old != 0 {
            let mut raw = [0u8; 32];
            for (i, field) in current.iter().enumerate() {
                raw[i * 8..i * 8 + 8].copy_from_slice(&field.to_le_bytes());
            }
            self.write_mem(old, &raw)?;
        }
        if let Some(new) = new {
            self.proc.sigactions[index] = new;
        }
        Ok(0)
    }

    pub fn sys_rt_sigprocmask(
        &mut self,
        how: i64,
        set: GuestAddr,
        old: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        const SIG_BLOCK: i64 = 0;
        const SIG_UNBLOCK: i64 = 1;
        const SIG_SETMASK: i64 = 2;
        const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));
        if size != 8 {
            return Err(Errno(EINVAL));
        }
        let new = if set != 0 {
            Some(self.read_u64(set)?)
        } else {
            None
        };
        if old != 0 {
            let mask = self.proc.sigmask;
            self.write_u64(old, mask)?;
        }
        if let Some(set) = new {
            let mask = &mut self.proc.sigmask;
            *mask = match how {
                SIG_BLOCK => *mask | set,
                SIG_UNBLOCK => *mask & !set,
                SIG_SETMASK => set,
                _ => return Err(Errno(EINVAL)),
            } & !UNBLOCKABLE;
        }
        Ok(0)
    }

    pub fn sys_sigaltstack(&mut self, old: GuestAddr) -> SysResult<u64> {
        const SS_DISABLE: u32 = 2;
        if old != 0 {
            let mut raw = [0u8; 24];
            raw[8..12].copy_from_slice(&SS_DISABLE.to_le_bytes());
            self.write_mem(old, &raw)?;
        }
        Ok(0)
    }

    /// `alarm`, `setitimer`, `getitimer`: accepted, but timers never fire
    /// before signal delivery exists (U2).
    pub fn sys_timers(&mut self, sysno: Sysno) -> SysResult<u64> {
        log::warn!("{}: timers are accepted but never fire yet", sysno.name());
        Ok(0)
    }

    /// `futex` for a single thread: waits can only time out or fail.
    pub fn sys_futex(&mut self, addr: GuestAddr, op: i64, val: u64) -> SysResult<u64> {
        match op & 0x7f {
            FUTEX_WAKE | FUTEX_WAKE_BITSET => Ok(0),
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let current = self.read_u32(addr).map_err(|_| Errno(EFAULT))?;
                if current != val as u32 {
                    return Err(Errno(EAGAIN));
                }
                log::warn!("futex wait with no other thread to wake it");
                Err(Errno(ETIMEDOUT))
            }
            other => {
                log::warn!("unimplemented futex op {other}");
                Err(Errno(ENOSYS))
            }
        }
    }
}
