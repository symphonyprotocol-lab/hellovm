//! The app's memory: the map of virtual memory areas and the emulation of
//! `brk`, `mmap`, `munmap`, `mprotect` and `mremap`.
//!
//! The core decides every address. The platform only carries out the
//! resulting page-level operations through [`AddressSpace`]: map zeroed
//! memory, unmap, change protection. File-backed private mappings are
//! anonymous memory filled with the file's contents (there is no host file
//! to map: the file may live in the in-memory layer, and on KVM there is no
//! host `mmap` at all). Shared mappings are treated as private, which is
//! exact while an app is a single process (U1); `fork` (U2) changes that.

use std::collections::BTreeMap;

use crate::errno::{Errno, SysResult, EEXIST, EFAULT, EINVAL, ENOMEM};
use crate::platform::{AddressSpace, AddressSpaceInfo, AppMemory, GuestAddr, Prot};

/// `mmap` flags (identical on x86_64 and aarch64).
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
pub const MAP_TYPE: u64 = 0x0f;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

/// `mremap` flags.
pub const MREMAP_MAYMOVE: u64 = 1;
pub const MREMAP_FIXED: u64 = 2;

/// `PROT_GROWSDOWN` and `PROT_GROWSUP`, accepted and ignored by `mprotect`.
const PROT_GROWS: u64 = 0x0300_0000;

/// Size of the main thread's stack (the default `RLIMIT_STACK`).
pub const STACK_SIZE: u64 = 8 << 20;
/// Unmapped gap between the stack and the top-down mapping area.
const STACK_GAP: u64 = 16 << 20;

/// What a memory area holds; for traces and debugging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmaKind {
    /// A segment of the loaded executable.
    Image,
    /// The `brk` heap.
    Heap,
    /// The main thread's stack.
    Stack,
    Anonymous,
    /// A private copy of a file.
    File,
    /// Used by the platform; never touched by the core.
    Reserved,
}

/// A virtual memory area: `start..end` with one protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vma {
    pub start: GuestAddr,
    pub end: GuestAddr,
    pub prot: Prot,
    pub kind: VmaKind,
}

/// Non-overlapping memory areas, keyed by start address.
#[derive(Clone, Debug, Default)]
pub struct VmaMap {
    areas: BTreeMap<GuestAddr, Vma>,
}

impl VmaMap {
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.areas.values()
    }

    /// The area containing `addr`.
    pub fn find(&self, addr: GuestAddr) -> Option<&Vma> {
        self.areas
            .range(..=addr)
            .next_back()
            .map(|(_, vma)| vma)
            .filter(|vma| addr < vma.end)
    }

    /// The areas overlapping `start..end`, in address order.
    pub fn overlapping(&self, start: GuestAddr, end: GuestAddr) -> Vec<Vma> {
        let first = self.find(start).map_or(start, |vma| vma.start);
        self.areas
            .range(first..end)
            .map(|(_, vma)| *vma)
            .filter(|vma| vma.end > start)
            .collect()
    }

    pub fn is_free(&self, start: GuestAddr, end: GuestAddr) -> bool {
        self.overlapping(start, end).is_empty()
    }

    /// Whether every address in `start..end` belongs to some area.
    pub fn is_fully_mapped(&self, start: GuestAddr, end: GuestAddr) -> bool {
        let mut at = start;
        for vma in self.overlapping(start, end) {
            if vma.start > at {
                return false;
            }
            at = vma.end;
        }
        at >= end
    }

    pub fn touches_reserved(&self, start: GuestAddr, end: GuestAddr) -> bool {
        self.overlapping(start, end)
            .iter()
            .any(|vma| vma.kind == VmaKind::Reserved)
    }

    /// Splits the area containing `addr` so that an area starts there.
    fn split_at(&mut self, addr: GuestAddr) {
        if let Some(vma) = self.find(addr).copied() {
            if vma.start < addr {
                self.areas.insert(vma.start, Vma { end: addr, ..vma });
                self.areas.insert(addr, Vma { start: addr, ..vma });
            }
        }
    }

    /// Adds an area, replacing whatever overlapped it.
    pub fn insert(&mut self, vma: Vma) {
        debug_assert!(vma.start < vma.end);
        self.remove(vma.start, vma.end);
        self.areas.insert(vma.start, vma);
    }

    /// Removes `start..end`, splitting areas that cross its ends.
    pub fn remove(&mut self, start: GuestAddr, end: GuestAddr) {
        self.split_at(start);
        self.split_at(end);
        let keys: Vec<_> = self.areas.range(start..end).map(|(k, _)| *k).collect();
        for key in keys {
            self.areas.remove(&key);
        }
    }

    /// Sets the protection of `start..end`, which must be fully mapped.
    pub fn set_prot(&mut self, start: GuestAddr, end: GuestAddr, prot: Prot) {
        self.split_at(start);
        self.split_at(end);
        for (_, vma) in self.areas.range_mut(start..end) {
            vma.prot = prot;
        }
    }

    /// The highest address `a` with `a..a + len` free and inside
    /// `low..high`.
    pub fn find_free(&self, len: u64, low: GuestAddr, high: GuestAddr) -> Option<GuestAddr> {
        // Walk the gaps from the top: each gap ends at `limit`.
        let mut limit = high;
        for vma in self.areas.range(..high).rev().map(|(_, vma)| vma) {
            let gap_start = vma.end.max(low);
            if gap_start < limit && limit - gap_start >= len {
                return Some(limit - len);
            }
            limit = limit.min(vma.start);
            if limit <= low {
                return None;
            }
        }
        (limit > low && limit - low >= len).then(|| limit - len)
    }
}

/// The app's address space as the core sees it.
#[derive(Clone, Debug)]
pub struct Mm {
    vmas: VmaMap,
    page_size: u64,
    min_addr: GuestAddr,
    max_addr: GuestAddr,
    stack_top: GuestAddr,
    mmap_top: GuestAddr,
    brk_start: GuestAddr,
    brk: GuestAddr,
}

fn platform_failed<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> Errno + '_ {
    move |err| {
        log::warn!("{what} failed on the platform: {err}");
        Errno(ENOMEM)
    }
}

impl Mm {
    /// An empty address space with the platform's reserved ranges.
    pub fn new(info: &AddressSpaceInfo) -> Mm {
        let page_size = info.page_size;
        let mut vmas = VmaMap::default();
        for range in &info.reserved {
            vmas.insert(Vma {
                start: range.start,
                end: range.end,
                prot: Prot::NONE,
                kind: VmaKind::Reserved,
            });
        }
        let stack_top = (info.max_addr - page_size) & !(page_size - 1);
        let mmap_top = stack_top.saturating_sub(STACK_SIZE + STACK_GAP);
        Mm {
            vmas,
            page_size,
            min_addr: info.min_addr,
            max_addr: info.max_addr,
            stack_top,
            mmap_top,
            brk_start: 0,
            brk: 0,
        }
    }

    pub fn vmas(&self) -> &VmaMap {
        &self.vmas
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    pub fn max_addr(&self) -> GuestAddr {
        self.max_addr
    }

    pub fn page_down(&self, addr: u64) -> u64 {
        addr & !(self.page_size - 1)
    }

    /// Rounds up to a page boundary; `None` on overflow.
    pub fn page_up(&self, addr: u64) -> Option<u64> {
        addr.checked_add(self.page_size - 1)
            .map(|a| a & !(self.page_size - 1))
    }

    fn in_bounds(&self, start: GuestAddr, end: GuestAddr) -> bool {
        start >= self.min_addr && end <= self.max_addr && start < end
    }

    /// Maps `addr..addr + len` (page-aligned), replacing whatever the app
    /// had there.
    pub fn map_fixed<P: AddressSpace + ?Sized>(
        &mut self,
        space: &mut P,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        kind: VmaKind,
    ) -> SysResult<()> {
        let end = addr.checked_add(len).ok_or(Errno(ENOMEM))?;
        if !self.in_bounds(addr, end) || self.vmas.touches_reserved(addr, end) {
            return Err(Errno(ENOMEM));
        }
        space.map(addr, len, prot).map_err(platform_failed("map"))?;
        self.vmas.insert(Vma {
            start: addr,
            end,
            prot,
            kind,
        });
        Ok(())
    }

    /// Maps the main thread's stack and returns its top.
    pub fn map_stack<P: AddressSpace + ?Sized>(&mut self, space: &mut P) -> SysResult<GuestAddr> {
        let bottom = self.stack_top - STACK_SIZE;
        self.map_fixed(space, bottom, STACK_SIZE, Prot::RW, VmaKind::Stack)?;
        Ok(self.stack_top)
    }

    /// A free range of `len` bytes for a mapping without a fixed address.
    fn pick_address(&self, hint: GuestAddr, len: u64) -> SysResult<GuestAddr> {
        if hint != 0 && hint.is_multiple_of(self.page_size) {
            if let Some(end) = hint.checked_add(len) {
                if self.in_bounds(hint, end) && self.vmas.is_free(hint, end) {
                    return Ok(hint);
                }
            }
        }
        let low = self.min_addr.max(self.brk_start);
        self.vmas
            .find_free(len, low, self.mmap_top)
            .or_else(|| self.vmas.find_free(len, self.min_addr, self.mmap_top))
            .ok_or(Errno(ENOMEM))
    }

    /// Places the program break right after the loaded image.
    pub fn set_brk_start(&mut self, addr: GuestAddr) {
        self.brk_start = addr;
        self.brk = addr;
    }

    /// `brk(2)`: returns the new break, or the old one if it cannot move.
    pub fn brk<P: AddressSpace + ?Sized>(&mut self, space: &mut P, new: GuestAddr) -> GuestAddr {
        if new < self.brk_start {
            return self.brk;
        }
        let (Some(old_end), Some(new_end)) = (self.page_up(self.brk), self.page_up(new)) else {
            return self.brk;
        };
        if new_end > old_end {
            if new_end > self.mmap_top || !self.vmas.is_free(old_end, new_end) {
                return self.brk;
            }
            let len = new_end - old_end;
            if self
                .map_fixed(space, old_end, len, Prot::RW, VmaKind::Heap)
                .is_err()
            {
                return self.brk;
            }
        } else if new_end < old_end && self.unmap_range(space, new_end, old_end).is_err() {
            return self.brk;
        }
        self.brk = new;
        self.brk
    }

    /// `mmap(2)`. `contents` holds the file data of a file-backed mapping
    /// (shorter than `len` if the file ends early; the rest is zero).
    #[allow(clippy::too_many_arguments)]
    pub fn mmap<P: AddressSpace + AppMemory + ?Sized>(
        &mut self,
        space: &mut P,
        addr: GuestAddr,
        len: u64,
        prot: u64,
        flags: u64,
        contents: Option<&[u8]>,
    ) -> SysResult<GuestAddr> {
        if len == 0 || prot & !(Prot::ALL.0 as u64) != 0 {
            return Err(Errno(EINVAL));
        }
        if !matches!(
            flags & MAP_TYPE,
            MAP_SHARED | MAP_PRIVATE | MAP_SHARED_VALIDATE
        ) {
            return Err(Errno(EINVAL));
        }
        let prot = Prot(prot as u32);
        let len = self.page_up(len).ok_or(Errno(ENOMEM))?;
        let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        let addr = if fixed {
            if !addr.is_multiple_of(self.page_size) {
                return Err(Errno(EINVAL));
            }
            let end = addr.checked_add(len).ok_or(Errno(ENOMEM))?;
            if !self.in_bounds(addr, end) || self.vmas.touches_reserved(addr, end) {
                return Err(Errno(ENOMEM));
            }
            if flags & MAP_FIXED == 0 && !self.vmas.is_free(addr, end) {
                return Err(Errno(EEXIST));
            }
            addr
        } else {
            self.pick_address(addr, len)?
        };
        match contents {
            None => self.map_fixed(space, addr, len, prot, VmaKind::Anonymous)?,
            Some(data) => {
                self.map_fixed(space, addr, len, Prot::RW, VmaKind::File)?;
                let data = &data[..data.len().min(len as usize)];
                if let Err(err) = space.write(addr, data) {
                    log::warn!("filling a file mapping failed: {err}");
                    let _ = self.unmap_range(space, addr, addr + len);
                    return Err(Errno(ENOMEM));
                }
                if prot != Prot::RW {
                    space
                        .protect(addr, len, prot)
                        .map_err(platform_failed("protect"))?;
                    self.vmas.set_prot(addr, addr + len, prot);
                }
            }
        }
        Ok(addr)
    }

    /// Unmaps every non-reserved area inside `start..end`; holes and
    /// reserved ranges are skipped, so the platform only sees ranges that
    /// are mapped.
    fn unmap_range<P: AddressSpace + ?Sized>(
        &mut self,
        space: &mut P,
        start: GuestAddr,
        end: GuestAddr,
    ) -> SysResult<()> {
        for vma in self.vmas.overlapping(start, end) {
            if vma.kind == VmaKind::Reserved {
                continue;
            }
            let (s, e) = (vma.start.max(start), vma.end.min(end));
            space.unmap(s, e - s).map_err(platform_failed("unmap"))?;
            self.vmas.remove(s, e);
        }
        Ok(())
    }

    /// `munmap(2)`.
    pub fn munmap<P: AddressSpace + ?Sized>(
        &mut self,
        space: &mut P,
        addr: GuestAddr,
        len: u64,
    ) -> SysResult<()> {
        if !addr.is_multiple_of(self.page_size) || len == 0 {
            return Err(Errno(EINVAL));
        }
        let len = self.page_up(len).ok_or(Errno(EINVAL))?;
        let end = addr.checked_add(len).ok_or(Errno(EINVAL))?;
        self.unmap_range(space, addr, end)
    }

    /// `mprotect(2)`.
    pub fn mprotect<P: AddressSpace + ?Sized>(
        &mut self,
        space: &mut P,
        addr: GuestAddr,
        len: u64,
        prot: u64,
    ) -> SysResult<()> {
        if !addr.is_multiple_of(self.page_size) || prot & !(Prot::ALL.0 as u64 | PROT_GROWS) != 0 {
            return Err(Errno(EINVAL));
        }
        let prot = Prot((prot & Prot::ALL.0 as u64) as u32);
        let len = self.page_up(len).ok_or(Errno(ENOMEM))?;
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len).ok_or(Errno(ENOMEM))?;
        if !self.vmas.is_fully_mapped(addr, end) || self.vmas.touches_reserved(addr, end) {
            return Err(Errno(ENOMEM));
        }
        space
            .protect(addr, len, prot)
            .map_err(platform_failed("protect"))?;
        self.vmas.set_prot(addr, end, prot);
        Ok(())
    }

    /// `mremap(2)`. Moving copies the contents through the kernel.
    pub fn mremap<P: AddressSpace + AppMemory + ?Sized>(
        &mut self,
        space: &mut P,
        old: GuestAddr,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: GuestAddr,
    ) -> SysResult<GuestAddr> {
        if !old.is_multiple_of(self.page_size)
            || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED) != 0
            || (flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0)
        {
            return Err(Errno(EINVAL));
        }
        let old_len = self.page_up(old_len).ok_or(Errno(EINVAL))?;
        let new_len = self.page_up(new_len).ok_or(Errno(EINVAL))?;
        if old_len == 0 || new_len == 0 {
            return Err(Errno(EINVAL));
        }
        let old_end = old.checked_add(old_len).ok_or(Errno(EFAULT))?;
        if !self.vmas.is_fully_mapped(old, old_end) || self.vmas.touches_reserved(old, old_end) {
            return Err(Errno(EFAULT));
        }
        let first = *self.vmas.find(old).expect("mapped");
        let fixed = flags & MREMAP_FIXED != 0;
        if !fixed {
            if new_len <= old_len {
                self.unmap_range(space, old + new_len, old_end)?;
                return Ok(old);
            }
            let grow_end = old.checked_add(new_len).ok_or(Errno(ENOMEM))?;
            if self.in_bounds(old, grow_end) && self.vmas.is_free(old_end, grow_end) {
                let last = *self.vmas.find(old_end - 1).expect("mapped");
                self.map_fixed(space, old_end, grow_end - old_end, last.prot, last.kind)?;
                return Ok(old);
            }
            if flags & MREMAP_MAYMOVE == 0 {
                return Err(Errno(ENOMEM));
            }
        }
        // Move: new mapping, copy, drop the old one.
        let target = if fixed {
            let end = new_addr.checked_add(new_len).ok_or(Errno(EINVAL))?;
            if !new_addr.is_multiple_of(self.page_size) || (new_addr < old_end && end > old) {
                return Err(Errno(EINVAL));
            }
            if !self.in_bounds(new_addr, end) || self.vmas.touches_reserved(new_addr, end) {
                return Err(Errno(ENOMEM));
            }
            new_addr
        } else {
            self.pick_address(0, new_len)?
        };
        self.map_fixed(space, target, new_len, Prot::RW, first.kind)?;
        let copy = old_len.min(new_len);
        if !first.prot.contains(Prot::READ) {
            space
                .protect(old, copy, Prot::READ)
                .map_err(platform_failed("protect"))?;
        }
        let mut buf = vec![0u8; copy.min(1 << 20) as usize];
        let mut done = 0;
        while done < copy {
            let n = (copy - done).min(buf.len() as u64) as usize;
            space
                .read(old + done, &mut buf[..n])
                .and_then(|()| space.write(target + done, &buf[..n]))
                .map_err(platform_failed("copy"))?;
            done += n as u64;
        }
        if first.prot != Prot::RW {
            space
                .protect(target, new_len, first.prot)
                .map_err(platform_failed("protect"))?;
            self.vmas.set_prot(target, target + new_len, first.prot);
        }
        self.unmap_range(space, old, old_end)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockApp;

    fn vma(start: u64, end: u64, prot: Prot) -> Vma {
        Vma {
            start,
            end,
            prot,
            kind: VmaKind::Anonymous,
        }
    }

    fn spans(map: &VmaMap) -> Vec<(u64, u64, Prot)> {
        map.iter().map(|v| (v.start, v.end, v.prot)).collect()
    }

    #[test]
    fn vma_map_splits_and_merges_nothing() {
        let mut map = VmaMap::default();
        map.insert(vma(0x1000, 0x5000, Prot::RW));
        map.insert(vma(0x2000, 0x3000, Prot::READ));
        assert_eq!(
            spans(&map),
            vec![
                (0x1000, 0x2000, Prot::RW),
                (0x2000, 0x3000, Prot::READ),
                (0x3000, 0x5000, Prot::RW)
            ]
        );
        map.remove(0x1800, 0x3800);
        assert_eq!(
            spans(&map),
            vec![(0x1000, 0x1800, Prot::RW), (0x3800, 0x5000, Prot::RW)]
        );
        assert!(map.is_free(0x1800, 0x3800));
        assert!(!map.is_free(0x1000, 0x1801));
        assert!(map.is_fully_mapped(0x3800, 0x5000));
        assert!(!map.is_fully_mapped(0x1000, 0x5000));
        map.set_prot(0x4000, 0x4800, Prot::NONE);
        assert_eq!(map.find(0x4100).unwrap().prot, Prot::NONE);
        assert_eq!(map.find(0x3900).unwrap().prot, Prot::RW);
        assert_eq!(map.find(0x5000), None);
        assert_eq!(map.overlapping(0x0, 0x10000).len(), 4);
    }

    #[test]
    fn find_free_is_top_down() {
        let mut map = VmaMap::default();
        assert_eq!(map.find_free(0x1000, 0x1000, 0x10000), Some(0xf000));
        map.insert(vma(0xe000, 0x10000, Prot::RW));
        map.insert(vma(0x9000, 0xb000, Prot::RW));
        assert_eq!(map.find_free(0x3000, 0x1000, 0x10000), Some(0xb000));
        assert_eq!(map.find_free(0x4000, 0x1000, 0x10000), Some(0x5000));
        assert_eq!(map.find_free(0x8000, 0x1000, 0x10000), Some(0x1000));
        assert_eq!(map.find_free(0x9000, 0x1000, 0x10000), None);
        // An area crossing the upper limit.
        assert_eq!(map.find_free(0x1000, 0x1000, 0xf000), Some(0xd000));
    }

    fn setup() -> (Mm, MockApp) {
        let app = MockApp::new(crate::Arch::Aarch64);
        let mm = Mm::new(&crate::platform::Platform::address_space(&app));
        (mm, app)
    }

    #[test]
    fn anonymous_mmap_munmap_mprotect() {
        let (mut mm, mut app) = setup();
        let a = mm
            .mmap(&mut app, 0, 0x2001, 3, MAP_PRIVATE | MAP_ANONYMOUS, None)
            .unwrap();
        assert_eq!(a % 0x1000, 0);
        assert!(a + 0x3000 <= mm.mmap_top);
        app.write(a + 0x2fff, b"x").unwrap();
        mm.mprotect(&mut app, a, 0x1000, 1).unwrap();
        assert!(app.write(a, b"x").is_err());
        assert_eq!(mm.mprotect(&mut app, a, 0x1000, 0x10), Err(Errno(EINVAL)));
        assert_eq!(
            mm.mprotect(&mut app, a + 0x3000, 0x1000, 1),
            Err(Errno(ENOMEM))
        );
        mm.munmap(&mut app, a + 0x1000, 0x1000).unwrap();
        assert!(app.read(a + 0x1000, &mut [0]).is_err());
        assert_eq!(
            mm.vmas()
                .iter()
                .filter(|v| v.kind == VmaKind::Anonymous)
                .count(),
            2
        );
        // Unmapping holes is fine.
        mm.munmap(&mut app, a, 0x10_0000).unwrap();
        assert_eq!(mm.munmap(&mut app, a + 1, 0x1000), Err(Errno(EINVAL)));
        // A second mapping goes below the first.
        let b = mm
            .mmap(&mut app, 0, 0x1000, 3, MAP_PRIVATE | MAP_ANONYMOUS, None)
            .unwrap();
        let c = mm
            .mmap(&mut app, 0, 0x1000, 3, MAP_PRIVATE | MAP_ANONYMOUS, None)
            .unwrap();
        assert_eq!(c, b - 0x1000);
    }

    #[test]
    fn fixed_mappings_and_reserved_ranges() {
        let (mut mm, mut app) = setup();
        let flags = MAP_PRIVATE | MAP_ANONYMOUS;
        let a = mm
            .mmap(&mut app, 0x4000_0000, 0x4000, 3, flags | MAP_FIXED, None)
            .unwrap();
        assert_eq!(a, 0x4000_0000);
        app.write(a, b"old").unwrap();
        assert_eq!(
            mm.mmap(&mut app, a, 0x1000, 3, flags | MAP_FIXED_NOREPLACE, None),
            Err(Errno(EEXIST))
        );
        // MAP_FIXED replaces with zeroed memory.
        mm.mmap(&mut app, a, 0x1000, 3, flags | MAP_FIXED, None)
            .unwrap();
        let mut buf = [1; 3];
        app.read(a, &mut buf).unwrap();
        assert_eq!(buf, [0; 3]);
        let reserved = app.reserved();
        assert_eq!(
            mm.mmap(&mut app, reserved, 0x1000, 3, flags | MAP_FIXED, None),
            Err(Errno(ENOMEM))
        );
        // munmap silently skips the reserved range; mprotect refuses it.
        // (The mock panics if the core touches the reserved range.)
        mm.mmap(
            &mut app,
            reserved - 0x1000,
            0x1000,
            3,
            flags | MAP_FIXED,
            None,
        )
        .unwrap();
        mm.munmap(&mut app, reserved - 0x1000, 0x3_0000).unwrap();
        assert!(!app.is_mapped(reserved - 0x1000));
        assert_eq!(
            mm.mprotect(&mut app, reserved, 0x1000, 3),
            Err(Errno(ENOMEM))
        );
        // A hint is honoured when free.
        let h = mm
            .mmap(&mut app, 0x5000_0000, 0x1000, 3, flags, None)
            .unwrap();
        assert_eq!(h, 0x5000_0000);
        assert_eq!(
            mm.mmap(&mut app, 0, 0x1000, 3, MAP_ANONYMOUS, None),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            mm.mmap(&mut app, 0x1000, 0x1000, 3, flags | MAP_FIXED, None),
            Err(Errno(ENOMEM)),
            "below min_addr"
        );
    }

    #[test]
    fn file_mapping_is_filled_and_protected() {
        let (mut mm, mut app) = setup();
        let a = mm
            .mmap(&mut app, 0, 0x2000, 1, MAP_PRIVATE, Some(b"file data"))
            .unwrap();
        let mut buf = [0; 10];
        app.read(a, &mut buf).unwrap();
        assert_eq!(&buf, b"file data\0");
        assert!(app.write(a, b"x").is_err());
        assert_eq!(mm.vmas().find(a).unwrap().kind, VmaKind::File);
    }

    #[test]
    fn brk_grows_and_shrinks() {
        let (mut mm, mut app) = setup();
        mm.set_brk_start(0x60_0100);
        assert_eq!(mm.brk(&mut app, 0), 0x60_0100);
        assert_eq!(mm.brk(&mut app, 0x60_2000), 0x60_2000);
        app.write(0x60_1fff, b"x").unwrap();
        // The first page was never mapped by brk (it is the image's).
        assert!(!app.is_mapped(0x60_0000));
        assert_eq!(mm.brk(&mut app, 0x60_0200), 0x60_0200);
        assert!(!app.is_mapped(0x60_1000));
        assert_eq!(mm.brk(&mut app, 0x10), 0x60_0200);
        // Cannot grow into another mapping.
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        mm.mmap(&mut app, 0x70_0000, 0x1000, 3, flags, None)
            .unwrap();
        assert_eq!(mm.brk(&mut app, 0x80_0000), 0x60_0200);
    }

    #[test]
    fn mremap_shrinks_grows_and_moves() {
        let (mut mm, mut app) = setup();
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        let a = 0x4000_0000;
        mm.mmap(&mut app, a, 0x2000, 3, flags, None).unwrap();
        app.write(a, b"keep").unwrap();
        assert_eq!(mm.mremap(&mut app, a, 0x2000, 0x1000, 0, 0), Ok(a));
        assert!(!app.is_mapped(a + 0x1000));
        assert_eq!(mm.mremap(&mut app, a, 0x1000, 0x3000, 0, 0), Ok(a));
        app.write(a + 0x2fff, b"x").unwrap();
        // Blocked: needs MAYMOVE.
        mm.mmap(&mut app, a + 0x3000, 0x1000, 3, flags, None)
            .unwrap();
        assert_eq!(
            mm.mremap(&mut app, a, 0x3000, 0x5000, 0, 0),
            Err(Errno(ENOMEM))
        );
        let b = mm
            .mremap(&mut app, a, 0x3000, 0x5000, MREMAP_MAYMOVE, 0)
            .unwrap();
        assert_ne!(a, b);
        let mut buf = [0; 4];
        app.read(b, &mut buf).unwrap();
        assert_eq!(&buf, b"keep");
        assert!(!app.is_mapped(a));
        assert_eq!(
            mm.mremap(&mut app, a, 0x1000, 0x1000, 0, 0),
            Err(Errno(EFAULT))
        );
    }
}
