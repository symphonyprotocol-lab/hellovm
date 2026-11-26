//! `epoll` instances: an interest list of (fd, open file description)
//! pairs, each with the events it waits for.
//!
//! Like Linux, a watch refers to the description, not to the fd: it stays
//! when the fd is dup'ed or the process forks, and it goes away when the
//! description's last fd is closed. The core does not track descriptions
//! from here; a watch records the description's serial number
//! ([`crate::fd::OpenFile::serial`]) and a watch whose description is gone
//! (or whose slot now holds another one) is dropped the next time the
//! instance is looked at.
//!
//! Readiness is computed when it is asked for, from the same per-file
//! state `poll` uses; `epoll_wait` parks and is retried when the sandbox
//! changes, like `poll`. Level-triggered watches report what is ready.
//! Edge-triggered ones (`EPOLLET`) report a ready event once, until the
//! instance has seen it not ready again: an approximation of Linux, which
//! reports again whenever new data arrives (a program that reads until
//! `EAGAIN`, as `EPOLLET` asks, sees no difference). `EPOLLONESHOT`
//! disables a watch after it reported, until `EPOLL_CTL_MOD`.
//! `EPOLLEXCLUSIVE` and `EPOLLWAKEUP` are accepted and have no effect.

use crate::fd::FileId;

/// An index into [`Epolls`].
pub type EpollId = usize;

/// Most epoll instances in one sandbox.
pub const MAX_EPOLLS: usize = 1024;
/// Most watches in one instance.
pub const MAX_WATCHES: usize = 16 * 1024;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLRDBAND: u32 = 0x080;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLWRBAND: u32 = 0x200;
pub const EPOLLMSG: u32 = 0x400;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

/// The event bits a watch can wait for.
pub const EVENT_BITS: u32 = EPOLLIN
    | EPOLLPRI
    | EPOLLOUT
    | EPOLLERR
    | EPOLLHUP
    | EPOLLRDNORM
    | EPOLLRDBAND
    | EPOLLWRNORM
    | EPOLLWRBAND
    | EPOLLMSG
    | EPOLLRDHUP;
/// Every flag `epoll_ctl` accepts.
pub const VALID: u32 = EVENT_BITS | EPOLLEXCLUSIVE | EPOLLWAKEUP | EPOLLONESHOT | EPOLLET;

/// One entry of an interest list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    /// The fd it was added with (with `file`, its key).
    pub fd: i32,
    pub file: FileId,
    /// The description's serial number when it was added.
    pub serial: u64,
    /// What it waits for, with the `EPOLLET`/`EPOLLONESHOT` flags.
    pub events: u32,
    /// Returned with each event.
    pub data: u64,
    /// Edge-triggered: the ready events already reported and not seen
    /// cleared since.
    pub seen: u32,
    /// One-shot: reported, and not re-armed yet.
    pub disabled: bool,
}

impl Watch {
    /// What this watch reports for the file's current `ready` events
    /// (poll bits), without changing it. `EPOLLERR` and `EPOLLHUP` are
    /// always waited for.
    pub fn pending(&self, ready: u32) -> u32 {
        if self.disabled {
            return 0;
        }
        let wanted = (self.events & EVENT_BITS) | EPOLLERR | EPOLLHUP;
        let mut got = ready & wanted;
        if self.events & EPOLLET != 0 {
            got &= !self.seen;
        }
        got
    }

    /// Records what the file's `ready` events are now (edge-triggered: an
    /// event seen not ready may be reported again).
    pub fn observe(&mut self, ready: u32) {
        self.seen &= ready;
    }

    /// Records that `events` were reported.
    pub fn reported(&mut self, events: u32) {
        self.seen |= events;
        if self.events & EPOLLONESHOT != 0 {
            self.disabled = true;
        }
    }
}

/// One epoll instance.
#[derive(Clone, Debug, Default)]
pub struct Epoll {
    pub watches: Vec<Watch>,
    /// Where the next `epoll_wait` starts looking, so that a small
    /// `maxevents` does not always return the same watches.
    pub cursor: usize,
}

impl Epoll {
    pub fn find(&self, fd: i32, file: FileId) -> Option<usize> {
        self.watches
            .iter()
            .position(|w| w.fd == fd && w.file == file)
    }
}

/// The sandbox's epoll instances.
#[derive(Debug, Default)]
pub struct Epolls {
    slots: Vec<Option<Epoll>>,
}

impl Epolls {
    /// A new instance, unless the sandbox has [`MAX_EPOLLS`] already.
    pub fn create(&mut self) -> Option<EpollId> {
        if let Some(id) = self.slots.iter().position(Option::is_none) {
            self.slots[id] = Some(Epoll::default());
            return Some(id);
        }
        if self.slots.len() >= MAX_EPOLLS {
            return None;
        }
        self.slots.push(Some(Epoll::default()));
        Some(self.slots.len() - 1)
    }

    pub fn get(&self, id: EpollId) -> &Epoll {
        self.slots[id].as_ref().expect("live epoll")
    }

    pub fn get_mut(&mut self, id: EpollId) -> &mut Epoll {
        self.slots[id].as_mut().expect("live epoll")
    }

    /// The instance's last description is gone.
    pub fn remove(&mut self, id: EpollId) {
        self.slots[id] = None;
    }
}

// The snapshot of a frozen template (see `snap`).
crate::snap_struct!(Watch {
    fd,
    file,
    serial,
    events,
    data,
    seen,
    disabled,
});
crate::snap_struct!(Epoll { watches, cursor });

impl crate::snap::Snap for Epolls {
    fn put(&self, w: &mut crate::snap::Writer) {
        crate::snap::Snap::put(&self.slots, w);
    }
    fn get(r: &mut crate::snap::Reader<'_>) -> Result<Self, crate::snap::Bad> {
        let slots: Vec<Option<Epoll>> = crate::snap::Snap::get(r)?;
        if slots.len() > MAX_EPOLLS {
            return crate::snap::bad("more epoll instances than a sandbox may have");
        }
        if slots
            .iter()
            .flatten()
            .any(|e| e.watches.len() > MAX_WATCHES)
        {
            return crate::snap::bad("more epoll watches than an instance may have");
        }
        Ok(Epolls { slots })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(events: u32) -> Watch {
        Watch {
            fd: 3,
            file: 0,
            serial: 1,
            events,
            data: 7,
            seen: 0,
            disabled: false,
        }
    }

    #[test]
    fn level_triggered_reports_while_ready() {
        let mut w = watch(EPOLLIN);
        assert_eq!(w.pending(EPOLLIN | EPOLLOUT), EPOLLIN);
        w.reported(EPOLLIN);
        assert_eq!(w.pending(EPOLLIN), EPOLLIN);
        // Errors and hang-ups are always reported.
        assert_eq!(w.pending(EPOLLHUP), EPOLLHUP);
    }

    #[test]
    fn edge_triggered_reports_once_until_seen_not_ready() {
        let mut w = watch(EPOLLIN | EPOLLOUT | EPOLLET);
        assert_eq!(w.pending(EPOLLOUT), EPOLLOUT);
        w.reported(EPOLLOUT);
        w.observe(EPOLLOUT);
        assert_eq!(w.pending(EPOLLOUT), 0, "still writable: no new edge");
        assert_eq!(w.pending(EPOLLOUT | EPOLLIN), EPOLLIN);
        w.observe(0);
        assert_eq!(w.pending(EPOLLOUT), EPOLLOUT, "not writable, then again");
    }

    #[test]
    fn one_shot_disables_after_a_report() {
        let mut w = watch(EPOLLIN | EPOLLONESHOT);
        w.reported(EPOLLIN);
        assert_eq!(w.pending(EPOLLIN), 0);
    }
}
