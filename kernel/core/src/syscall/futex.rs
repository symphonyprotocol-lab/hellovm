//! `futex`: wait queues keyed by address-space and address.
//!
//! A waiter is a parked thread whose [`WaitKind::Futex`] names the word it
//! waits on; waking makes it ready with return value 0. Waiters are never
//! retried, so a wake is never lost to a value that changed in between, and
//! a waiter whose futex word changes without a wake keeps waiting, as on
//! Linux. Keys are (address space, address) for private and "shared"
//! futexes alike: shared memory between processes exists only as
//! `MAP_SHARED` anonymous mappings, which are never at different addresses
//! in related processes, but two unrelated mappings of one file are not
//! recognized as the same futex.
//!
//! Priority-inheritance operations are not implemented (`ENOSYS`); glibc
//! uses them only for `PTHREAD_PRIO_INHERIT` mutexes.

use std::time::Duration;

use crate::errno::{Errno, SysResult, EAGAIN, EFAULT, EINVAL, ENOSYS, ETIMEDOUT};
use crate::host::Host;
use crate::platform::{GuestAddr, Platform};
use crate::task::{Next, Restart, ThreadState, Tid, WaitKind};

use super::Ctx;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_REQUEUE: i64 = 3;
const FUTEX_CMP_REQUEUE: i64 = 4;
const FUTEX_WAKE_OP: i64 = 5;
const FUTEX_WAIT_BITSET: i64 = 9;
const FUTEX_WAKE_BITSET: i64 = 10;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_CLOCK_REALTIME: i64 = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    #[allow(clippy::too_many_arguments)]
    pub fn sys_futex(
        &mut self,
        addr: GuestAddr,
        op: i64,
        val: u64,
        arg4: u64,
        addr2: GuestAddr,
        val3: u64,
    ) -> SysResult<u64> {
        let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
        if op & FUTEX_CLOCK_REALTIME != 0 && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAIT {
            return Err(Errno(ENOSYS));
        }
        if !addr.is_multiple_of(4) {
            return Err(Errno(EINVAL));
        }
        let val = val as u32;
        match cmd {
            FUTEX_WAIT => self.futex_wait(addr, val, arg4, false, FUTEX_BITSET_MATCH_ANY, op),
            FUTEX_WAIT_BITSET => {
                let bitset = val3 as u32;
                if bitset == 0 {
                    return Err(Errno(EINVAL));
                }
                self.futex_wait(addr, val, arg4, true, bitset, op)
            }
            FUTEX_WAKE => Ok(self.futex_wake_addr(addr, val, FUTEX_BITSET_MATCH_ANY)),
            FUTEX_WAKE_BITSET => {
                let bitset = val3 as u32;
                if bitset == 0 {
                    return Err(Errno(EINVAL));
                }
                Ok(self.futex_wake_addr(addr, val, bitset))
            }
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
                if !addr2.is_multiple_of(4) {
                    return Err(Errno(EINVAL));
                }
                if cmd == FUTEX_CMP_REQUEUE {
                    let current = self.read_u32(addr).map_err(|_| Errno(EFAULT))?;
                    if current != val3 as u32 {
                        return Err(Errno(EAGAIN));
                    }
                }
                let woken = self.futex_wake_addr(addr, val, FUTEX_BITSET_MATCH_ANY);
                let moved = self.futex_requeue(addr, addr2, arg4 as u32);
                Ok(if cmd == FUTEX_CMP_REQUEUE {
                    woken + moved
                } else {
                    woken
                })
            }
            FUTEX_WAKE_OP => self.futex_wake_op(addr, val, arg4 as u32, addr2, val3 as u32),
            other => {
                log::warn!("unimplemented futex operation {other}");
                Err(Errno(ENOSYS))
            }
        }
    }

    fn futex_wait(
        &mut self,
        addr: GuestAddr,
        val: u32,
        timeout: GuestAddr,
        absolute: bool,
        bitset: u32,
        op: i64,
    ) -> SysResult<u64> {
        let Some(mm) = self.proc().mm else {
            return Err(Errno(EFAULT));
        };
        let current = self.read_u32(addr)?;
        if current != val {
            return Err(Errno(EAGAIN));
        }
        let timeout = if timeout == 0 {
            None
        } else {
            let t = self.read_timespec(timeout)?;
            Some(if absolute {
                let now = if op & FUTEX_CLOCK_REALTIME != 0 {
                    self.host.clock_realtime()
                } else {
                    self.host.clock_monotonic()
                };
                t.saturating_sub(now)
            } else {
                t
            })
        };
        if timeout == Some(Duration::ZERO) {
            return Err(Errno(ETIMEDOUT));
        }
        Err(self.park(
            WaitKind::Futex { mm, addr, bitset },
            timeout,
            Restart::IfSaRestart,
        ))
    }

    /// The threads waiting on `addr` in this address space, in tid order.
    fn futex_waiters(&self, addr: GuestAddr, bitset: u32) -> Vec<Tid> {
        let Some(mm) = self.proc().mm else {
            return Vec::new();
        };
        self.st
            .threads
            .values()
            .filter(|t| {
                matches!(t.parked().map(|p| p.kind), Some(WaitKind::Futex { mm: m, addr: a, bitset: b })
                    if m == mm && a == addr && b & bitset != 0)
            })
            .map(|t| t.tid)
            .collect()
    }

    /// Wakes up to `count` waiters on `addr`; returns how many.
    pub(crate) fn futex_wake_addr(&mut self, addr: GuestAddr, count: u32, bitset: u32) -> u64 {
        let mut woken = 0;
        for tid in self.futex_waiters(addr, bitset) {
            if woken >= u64::from(count) {
                break;
            }
            self.st.thread_mut(tid).state = ThreadState::Ready(Next::Return(0));
            woken += 1;
        }
        woken
    }

    /// Moves up to `count` waiters from `from` to `to`.
    fn futex_requeue(&mut self, from: GuestAddr, to: GuestAddr, count: u32) -> u64 {
        let mut moved = 0;
        for tid in self.futex_waiters(from, FUTEX_BITSET_MATCH_ANY) {
            if moved >= u64::from(count) {
                break;
            }
            if let ThreadState::Parked(p) = &mut self.st.thread_mut(tid).state {
                if let WaitKind::Futex { addr, .. } = &mut p.kind {
                    *addr = to;
                    moved += 1;
                }
            }
        }
        moved
    }

    fn futex_wake_op(
        &mut self,
        addr: GuestAddr,
        count: u32,
        count2: u32,
        addr2: GuestAddr,
        encoded: u32,
    ) -> SysResult<u64> {
        if !addr2.is_multiple_of(4) {
            return Err(Errno(EINVAL));
        }
        let op = (encoded >> 28) & 0x7;
        let shift = encoded & (8 << 28) != 0;
        let cmp = (encoded >> 24) & 0xf;
        let mut oparg = (encoded >> 12) & 0xfff;
        let cmparg = encoded & 0xfff;
        if shift {
            if oparg > 31 {
                return Err(Errno(EINVAL));
            }
            oparg = 1 << oparg;
        }
        let old = self.read_u32(addr2)?;
        let new = match op {
            0 => oparg,
            1 => old.wrapping_add(oparg),
            2 => old | oparg,
            3 => old & !oparg,
            4 => old ^ oparg,
            _ => return Err(Errno(ENOSYS)),
        };
        self.write_u32(addr2, new)?;
        let mut woken = self.futex_wake_addr(addr, count, FUTEX_BITSET_MATCH_ANY);
        let (old, cmparg) = (old as i32, cmparg as i32);
        let hit = match cmp {
            0 => old == cmparg,
            1 => old != cmparg,
            2 => old < cmparg,
            3 => old <= cmparg,
            4 => old > cmparg,
            5 => old >= cmparg,
            _ => return Err(Errno(ENOSYS)),
        };
        if hit {
            woken += self.futex_wake_addr(addr2, count2, FUTEX_BITSET_MATCH_ANY);
        }
        Ok(woken)
    }
}
