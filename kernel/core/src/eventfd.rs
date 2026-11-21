//! `eventfd` objects: a 64-bit counter behind a file descriptor.
//!
//! A write adds its 8-byte value to the counter; a read takes the whole
//! counter (or 1, with `EFD_SEMAPHORE`) and waits while it is zero. libcurl
//! wakes its resolver thread's waiter this way.

/// An index into [`EventFds`].
pub type EventFdId = usize;

/// Most eventfd objects in one sandbox.
pub const MAX_EVENTFDS: usize = 1024;
/// The largest value the counter holds (Linux: `u64::MAX - 1`).
pub const COUNTER_MAX: u64 = u64::MAX - 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct EventFd {
    pub count: u64,
    pub semaphore: bool,
}

impl EventFd {
    /// What a read returns now, taking it from the counter; `None` when the
    /// counter is zero.
    pub fn take(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let value = if self.semaphore { 1 } else { self.count };
        self.count -= value;
        Some(value)
    }

    /// Adds `value`; `false` when the counter has no room for it.
    pub fn add(&mut self, value: u64) -> bool {
        match self.count.checked_add(value) {
            Some(sum) if sum <= COUNTER_MAX => {
                self.count = sum;
                true
            }
            _ => false,
        }
    }
}

/// The sandbox's eventfd objects.
#[derive(Debug, Default)]
pub struct EventFds {
    slots: Vec<Option<EventFd>>,
}

impl EventFds {
    /// A new object, unless the sandbox has [`MAX_EVENTFDS`] already.
    pub fn create(&mut self, count: u64, semaphore: bool) -> Option<EventFdId> {
        let object = EventFd { count, semaphore };
        if let Some(id) = self.slots.iter().position(Option::is_none) {
            self.slots[id] = Some(object);
            return Some(id);
        }
        if self.slots.len() >= MAX_EVENTFDS {
            return None;
        }
        self.slots.push(Some(object));
        Some(self.slots.len() - 1)
    }

    pub fn get(&self, id: EventFdId) -> &EventFd {
        self.slots[id].as_ref().expect("live eventfd")
    }

    pub fn get_mut(&mut self, id: EventFdId) -> &mut EventFd {
        self.slots[id].as_mut().expect("live eventfd")
    }

    /// The object's last description is gone.
    pub fn remove(&mut self, id: EventFdId) {
        self.slots[id] = None;
    }
}

// The snapshot of a frozen template (see `snap`).
crate::snap_struct!(EventFd { count, semaphore });

impl crate::snap::Snap for EventFds {
    fn put(&self, w: &mut crate::snap::Writer) {
        crate::snap::Snap::put(&self.slots, w);
    }
    fn get(r: &mut crate::snap::Reader<'_>) -> Result<Self, crate::snap::Bad> {
        let slots: Vec<Option<EventFd>> = crate::snap::Snap::get(r)?;
        if slots.len() > MAX_EVENTFDS {
            return crate::snap::bad("more eventfds than a sandbox may have");
        }
        Ok(EventFds { slots })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_and_semaphore() {
        let mut fds = EventFds::default();
        let a = fds.create(0, false).unwrap();
        assert_eq!(fds.get_mut(a).take(), None);
        assert!(fds.get_mut(a).add(3));
        assert!(fds.get_mut(a).add(4));
        assert_eq!(fds.get_mut(a).take(), Some(7));
        assert_eq!(fds.get(a).count, 0);
        assert!(fds.get_mut(a).add(COUNTER_MAX));
        assert!(!fds.get_mut(a).add(1), "full");
        let s = fds.create(2, true).unwrap();
        assert_eq!(fds.get_mut(s).take(), Some(1));
        assert_eq!(fds.get_mut(s).take(), Some(1));
        assert_eq!(fds.get_mut(s).take(), None);
        fds.remove(a);
        assert_eq!(fds.create(0, false), Some(a), "slots are reused");
    }
}
