//! `epoll_create1`, `epoll_ctl`, `epoll_wait`/`epoll_pwait`/`epoll_pwait2`
//! (see `crate::epoll` for the model).

use std::time::Duration;

use crate::abi;
use crate::arch::Arch;
use crate::epoll::{EpollId, Watch, MAX_WATCHES, VALID};
use crate::errno::{Errno, SysResult, EBADF, EEXIST, EINVAL, ELOOP, ENFILE, ENOENT, ENOSPC, EPERM};
use crate::fd::{Access, FileObject, OpenFile};
use crate::host::Host;
use crate::platform::{GuestAddr, Platform};
use crate::task::Restart;
use crate::vfs::FileType;

use super::Ctx;

const EPOLL_CTL_ADD: i64 = 1;
const EPOLL_CTL_DEL: i64 = 2;
const EPOLL_CTL_MOD: i64 = 3;

/// How deep epoll instances may be nested (Linux: `EP_MAX_NESTS`).
const MAX_NESTS: u32 = 4;

/// Most events one `epoll_wait` returns (Linux: `INT_MAX` divided by the
/// size of an event; the core caps the buffer it writes).
const MAX_EVENTS: i64 = 64 * 1024;

/// The size of `struct epoll_event`: packed on x86_64 (`u32` events, `u64`
/// data), naturally aligned elsewhere (four bytes of padding).
fn event_size(arch: Arch) -> usize {
    match arch {
        Arch::X86_64 => 12,
        Arch::Aarch64 => 16,
    }
}

fn decode_event(arch: Arch, raw: &[u8]) -> (u32, u64) {
    let events = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let at = event_size(arch) - 8;
    let data = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
    (events, data)
}

fn encode_event(arch: Arch, events: u32, data: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&events.to_le_bytes());
    if arch == Arch::Aarch64 {
        out.extend_from_slice(&[0; 4]);
    }
    out.extend_from_slice(&data.to_le_bytes());
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    pub fn sys_epoll_create1(&mut self, flags: u64) -> SysResult<u64> {
        if flags & !abi::O_CLOEXEC != 0 {
            return Err(Errno(EINVAL));
        }
        let id = self.st.epolls.create().ok_or(Errno(ENFILE))?;
        let file = OpenFile::new(FileObject::Epoll(id), Access::ReadWrite);
        // `install` releases the instance again if the fd table is full.
        self.install(file, 0, flags & abi::O_CLOEXEC != 0)
            .map(|fd| fd as u64)
    }

    /// `epoll_create` (x86_64): the size only has to be positive.
    pub fn sys_epoll_create(&mut self, size: i64) -> SysResult<u64> {
        if size <= 0 {
            return Err(Errno(EINVAL));
        }
        self.sys_epoll_create1(0)
    }

    /// The epoll instance behind `fd`.
    fn epoll_of(&self, fd: i64) -> SysResult<EpollId> {
        match self.file(fd)?.1.object {
            FileObject::Epoll(id) => Ok(id),
            _ => Err(Errno(EINVAL)),
        }
    }

    /// Drops the watches whose description is gone.
    fn prune_watches(&mut self, id: EpollId) {
        let files = &self.st.files;
        self.st
            .epolls
            .get_mut(id)
            .watches
            .retain(|w| files.get_serial(w.file, w.serial).is_some());
    }

    /// Whether instance `inner`, or one nested in it, is `outer` (adding
    /// `inner` to `outer` would make a loop), or the nesting gets deeper
    /// than [`MAX_NESTS`].
    fn epoll_loops(&mut self, outer: EpollId, inner: EpollId, depth: u32) -> bool {
        if inner == outer || depth >= MAX_NESTS {
            return true;
        }
        self.prune_watches(inner);
        let nested: Vec<EpollId> = self
            .st
            .epolls
            .get(inner)
            .watches
            .iter()
            .filter_map(|w| match self.st.files.get(w.file).object {
                FileObject::Epoll(id) => Some(id),
                _ => None,
            })
            .collect();
        nested
            .into_iter()
            .any(|id| self.epoll_loops(outer, id, depth + 1))
    }

    pub fn sys_epoll_ctl(
        &mut self,
        epfd: i64,
        op: i64,
        fd: i64,
        event: GuestAddr,
    ) -> SysResult<u64> {
        let (_, ep_file) = self.file(epfd)?;
        let ep_object = ep_file.object;
        let (file_id, file) = self.file(fd)?;
        let (target, serial) = (file.object, file.serial);
        let FileObject::Epoll(id) = ep_object else {
            return Err(Errno(EINVAL));
        };
        if fd == epfd {
            return Err(Errno(EINVAL));
        }
        // Regular files and directories cannot be polled.
        if let FileObject::Node(ino) = target {
            if matches!(
                self.vfs.file_type(ino),
                FileType::Regular | FileType::Directory
            ) {
                return Err(Errno(EPERM));
            }
        }
        let (events, data) = match op {
            EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
                let raw = self.read_mem(event, event_size(self.arch))?;
                let (events, data) = decode_event(self.arch, &raw);
                (events & VALID, data)
            }
            EPOLL_CTL_DEL => (0, 0),
            _ => return Err(Errno(EINVAL)),
        };
        self.prune_watches(id);
        let fd32 = fd as i32;
        let existing = self.st.epolls.get(id).find(fd32, file_id);
        match op {
            EPOLL_CTL_ADD => {
                if existing.is_some() {
                    return Err(Errno(EEXIST));
                }
                if let FileObject::Epoll(inner) = target {
                    if self.epoll_loops(id, inner, 1) {
                        return Err(Errno(ELOOP));
                    }
                }
                let epoll = self.st.epolls.get_mut(id);
                if epoll.watches.len() >= MAX_WATCHES {
                    return Err(Errno(ENOSPC));
                }
                epoll.watches.push(Watch {
                    fd: fd32,
                    file: file_id,
                    serial,
                    events,
                    data,
                    seen: 0,
                    disabled: false,
                });
            }
            EPOLL_CTL_MOD => {
                let at = existing.ok_or(Errno(ENOENT))?;
                let watch = &mut self.st.epolls.get_mut(id).watches[at];
                watch.events = events;
                watch.data = data;
                watch.seen = 0;
                watch.disabled = false;
            }
            _ => {
                let at = existing.ok_or(Errno(ENOENT))?;
                self.st.epolls.get_mut(id).watches.remove(at);
            }
        }
        // A thread parked in `epoll_wait` looks again.
        self.st.changed = true;
        Ok(0)
    }

    /// The current poll events of every watch of `id`, in order.
    fn watch_readiness(&mut self, id: EpollId, depth: u32) -> Vec<(Watch, u32)> {
        self.prune_watches(id);
        let watches = self.st.epolls.get(id).watches.clone();
        watches
            .into_iter()
            .map(|w| {
                let object = self.st.files.get(w.file).object;
                (w, u32::from(self.poll_object(object, depth + 1)))
            })
            .collect()
    }

    /// Whether `epoll_wait` on instance `id` would return something now
    /// (an epoll fd polled, or nested in another instance).
    pub(super) fn epoll_has_events(&mut self, id: EpollId, depth: u32) -> bool {
        if depth > MAX_NESTS {
            return false;
        }
        self.watch_readiness(id, depth)
            .iter()
            .any(|(w, ready)| w.pending(*ready) != 0)
    }

    /// `epoll_wait` and `epoll_pwait`: `timeout_ms` negative (or `None`)
    /// waits for ever.
    pub fn sys_epoll_wait(
        &mut self,
        epfd: i64,
        events: GuestAddr,
        maxevents: i64,
        timeout_ms: Option<i64>,
        sigmask: GuestAddr,
        sigsetsize: u64,
    ) -> SysResult<u64> {
        let timeout = match timeout_ms {
            Some(ms) if ms >= 0 => Some(Duration::from_millis(ms as u64)),
            _ => None,
        };
        self.epoll_wait_until(epfd, events, maxevents, timeout, sigmask, sigsetsize)
    }

    /// `epoll_pwait2`: the timeout is a `timespec`, null for ever.
    pub fn sys_epoll_pwait2(
        &mut self,
        epfd: i64,
        events: GuestAddr,
        maxevents: i64,
        timeout: GuestAddr,
        sigmask: GuestAddr,
        sigsetsize: u64,
    ) -> SysResult<u64> {
        let timeout = if timeout == 0 {
            None
        } else {
            Some(self.read_timespec(timeout)?)
        };
        self.epoll_wait_until(epfd, events, maxevents, timeout, sigmask, sigsetsize)
    }

    fn epoll_wait_until(
        &mut self,
        epfd: i64,
        events: GuestAddr,
        maxevents: i64,
        timeout: Option<Duration>,
        sigmask: GuestAddr,
        sigsetsize: u64,
    ) -> SysResult<u64> {
        if !(1..=MAX_EVENTS).contains(&maxevents) {
            return Err(Errno(EINVAL));
        }
        let id = match self.epoll_of(epfd) {
            Err(Errno(EBADF)) => return Err(Errno(EBADF)),
            other => other?,
        };
        self.temporary_mask(sigmask, sigsetsize)?;
        let readiness = self.watch_readiness(id, 0);
        let len = readiness.len();
        let start = if len == 0 {
            0
        } else {
            self.st.epolls.get(id).cursor % len
        };
        let mut out = Vec::new();
        // The watches as they are after this call: edge-triggered ones
        // track what they saw; reported ones what they reported.
        let mut after: Vec<Watch> = readiness.iter().map(|(w, _)| *w).collect();
        let mut last = None;
        let mut count = 0;
        for step in 0..len {
            let at = (start + step) % len;
            let (watch, ready) = readiness[at];
            after[at].observe(ready);
            if count == maxevents as usize {
                continue;
            }
            let got = watch.pending(ready);
            if got != 0 {
                encode_event(self.arch, got, watch.data, &mut out);
                after[at].reported(got);
                count += 1;
                last = Some(at);
            }
        }
        if count == 0 && !self.timed_out() && timeout != Some(Duration::ZERO) {
            self.st.epolls.get_mut(id).watches = after;
            return Err(self.park_retry(timeout, Restart::Never));
        }
        if count > 0 {
            self.write_mem(events, &out)?;
        }
        let epoll = self.st.epolls.get_mut(id);
        epoll.watches = after;
        if let Some(at) = last {
            epoll.cursor = at + 1;
        }
        Ok(count as u64)
    }
}
