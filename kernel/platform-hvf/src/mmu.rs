//! Guest-physical memory and the stage-1 page tables hellovm writes for
//! the app.
//!
//! Two pools of 4 KiB frames live in host memory: page tables (mapped
//! into the VM read only) and app memory (read, write, execute). An
//! address space is a 4-level table tree (4 KiB granule, 48-bit
//! addresses) rooted in `TTBR0_EL1`. Its leaf descriptors are also the
//! only record of what the core mapped: a software bit marks a page as
//! mapped and three more keep its `PROT_*` value, so a page can be
//! mapped but not valid in hardware (`PROT_NONE`, or not yet backed).
//!
//! App memory is allocated on first touch: [`Phys::map`] only writes
//! descriptors, and the first access the hardware refuses with a
//! translation fault gets a zeroed frame ([`Phys::demand`]). Frames and
//! tables come from fixed-size pools that are reserved up front: running
//! out fails the operation (or, on first touch, ends the app), and never
//! makes the kernel process allocate more.
//!
//! Nothing here trusts app memory: descriptors are read only from the
//! table pool, which the VM cannot write.

use hellovm_core::platform::Prot;

use crate::layout::{pte, MAX_ADDR, PAGE, RAM_IPA, SHIM_IPA, SHIM_VA, TABLES_IPA};

/// Memory the pools live in.
pub trait Backing {
    fn bytes(&self) -> &[u8];
    fn bytes_mut(&mut self) -> &mut [u8];
    /// Makes code written to `offset..offset + len` visible to the guest's
    /// instruction fetch.
    fn sync_icache(&mut self, offset: usize, len: usize);
}

#[cfg(test)]
impl Backing for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self
    }

    fn sync_icache(&mut self, _offset: usize, _len: usize) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmuError {
    /// A pool is exhausted.
    NoMemory,
    /// The range is not (fully) mapped, or not with the access asked for,
    /// or outside the app's addresses.
    BadAddress,
}

/// How the app touched a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

impl Access {
    fn allowed(self, prot: Prot) -> bool {
        match self {
            // There is no write-only or execute-only memory: any access
            // makes a page readable, as on Linux/arm64.
            Access::Read => prot != Prot::NONE,
            Access::Write => prot.contains(Prot::WRITE),
            Access::Exec => prot.contains(Prot::EXEC),
        }
    }
}

/// What [`Phys::demand`] did about a translation fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demand {
    /// The page was mapped but had no memory yet; it has now. Resume.
    Filled,
    /// The page is mapped, backed and allows the access: the fault came
    /// from a stale TLB entry.
    Present,
    /// Nothing is mapped there (`SEGV_MAPERR`).
    Unmapped,
    /// Mapped, but this access is not allowed (`SEGV_ACCERR`).
    Denied,
    /// The app's memory pool is exhausted.
    NoMemory,
}

/// A pool of 4 KiB frames at a guest-physical base.
#[derive(Debug)]
struct Pool {
    base: u64,
    frames: u64,
    /// Frames below this were handed out at least once.
    next: u64,
    free: Vec<u64>,
}

impl Pool {
    fn new(base: u64, bytes: u64) -> Pool {
        Pool {
            base,
            frames: bytes / PAGE,
            next: 0,
            free: Vec::new(),
        }
    }

    /// A frame and whether it may hold old data (fresh ones are zero).
    fn alloc(&mut self) -> Option<(u64, bool)> {
        if let Some(ipa) = self.free.pop() {
            return Some((ipa, true));
        }
        if self.next == self.frames {
            return None;
        }
        let ipa = self.base + self.next * PAGE;
        self.next += 1;
        Some((ipa, false))
    }

    fn release(&mut self, ipa: u64) {
        debug_assert!(self.contains(ipa));
        // `free` never holds more than `frames` entries: each frame is in
        // it at most once.
        self.free.push(ipa);
    }

    fn contains(&self, ipa: u64) -> bool {
        ipa >= self.base && ipa < self.base + self.frames * PAGE
    }

    fn in_use(&self) -> u64 {
        self.next - self.free.len() as u64
    }
}

/// The two pools and the tables in them.
pub struct Phys<B> {
    tables: B,
    ram: B,
    table_pool: Pool,
    ram_pool: Pool,
}

fn index(va: u64, level: u32) -> usize {
    ((va >> (39 - 9 * level)) & 511) as usize
}

fn leaf(frame: Option<u64>, prot: Prot) -> u64 {
    let sw = pte::SW_MAPPED | ((prot.0 as u64 & 7) << pte::SW_PROT_SHIFT);
    let Some(frame) = frame else {
        return sw;
    };
    if prot == Prot::NONE {
        return sw | frame;
    }
    let mut desc = sw
        | frame
        | pte::VALID
        | pte::TABLE_OR_PAGE
        | pte::AF
        | pte::SH_INNER
        | pte::NG
        | pte::PXN
        | pte::AP_EL0;
    if !prot.contains(Prot::WRITE) {
        desc |= pte::AP_RO;
    }
    if !prot.contains(Prot::EXEC) {
        desc |= pte::UXN;
    }
    desc
}

fn leaf_prot(desc: u64) -> Prot {
    Prot(((desc & pte::SW_PROT_MASK) >> pte::SW_PROT_SHIFT) as u32)
}

fn leaf_frame(desc: u64) -> Option<u64> {
    let frame = desc & pte::ADDR_MASK;
    (frame != 0).then_some(frame)
}

/// Checks that `addr..addr + len` is page aligned and inside the app's
/// addresses, and returns its end.
fn page_range(addr: u64, len: u64) -> Result<u64, MmuError> {
    let end = addr.checked_add(len).ok_or(MmuError::BadAddress)?;
    if !addr.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || end > MAX_ADDR {
        return Err(MmuError::BadAddress);
    }
    Ok(end)
}

impl<B: Backing> Phys<B> {
    /// Pools over `tables` (at [`TABLES_IPA`]) and `ram` (at [`RAM_IPA`]).
    pub fn new(tables: B, ram: B) -> Phys<B> {
        let table_pool = Pool::new(TABLES_IPA, tables.bytes().len() as u64);
        let ram_pool = Pool::new(RAM_IPA, ram.bytes().len() as u64);
        Phys {
            tables,
            ram,
            table_pool,
            ram_pool,
        }
    }

    pub fn tables_backing(&self) -> &B {
        &self.tables
    }

    pub fn ram_backing(&self) -> &B {
        &self.ram
    }

    /// App memory in use, in bytes.
    pub fn ram_in_use(&self) -> u64 {
        self.ram_pool.in_use() * PAGE
    }

    /// Page-table memory in use, in bytes.
    pub fn tables_in_use(&self) -> u64 {
        self.table_pool.in_use() * PAGE
    }

    fn entry(&self, table: u64, idx: usize) -> u64 {
        let off = (table - TABLES_IPA) as usize + idx * 8;
        u64::from_le_bytes(self.tables.bytes()[off..off + 8].try_into().unwrap())
    }

    fn set_entry(&mut self, table: u64, idx: usize, value: u64) {
        let off = (table - TABLES_IPA) as usize + idx * 8;
        self.tables.bytes_mut()[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn new_table(&mut self) -> Result<u64, MmuError> {
        let (ipa, dirty) = self.table_pool.alloc().ok_or(MmuError::NoMemory)?;
        if dirty {
            let off = (ipa - TABLES_IPA) as usize;
            self.tables.bytes_mut()[off..off + PAGE as usize].fill(0);
        }
        Ok(ipa)
    }

    fn new_frame(&mut self) -> Option<u64> {
        let (ipa, dirty) = self.ram_pool.alloc()?;
        if dirty {
            let off = (ipa - RAM_IPA) as usize;
            self.ram.bytes_mut()[off..off + PAGE as usize].fill(0);
        }
        Some(ipa)
    }

    fn frame(&self, ipa: u64) -> &[u8] {
        let off = (ipa - RAM_IPA) as usize;
        &self.ram.bytes()[off..off + PAGE as usize]
    }

    fn frame_mut(&mut self, ipa: u64) -> &mut [u8] {
        let off = (ipa - RAM_IPA) as usize;
        &mut self.ram.bytes_mut()[off..off + PAGE as usize]
    }

    fn sync_frame(&mut self, ipa: u64) {
        self.ram
            .sync_icache((ipa - RAM_IPA) as usize, PAGE as usize);
    }

    /// A new, empty address space: its level-0 table.
    pub fn new_space(&mut self) -> Result<u64, MmuError> {
        self.new_table()
    }

    /// The `TTBR1_EL1` tree: the shim page at [`SHIM_VA`], EL1 read and
    /// execute only. EL0 can neither read nor execute it.
    pub fn shim_space(&mut self) -> Result<u64, MmuError> {
        let root = self.new_table()?;
        let mut table = root;
        for level in 0..3 {
            let next = self.new_table()?;
            self.set_entry(
                table,
                index(SHIM_VA, level),
                next | pte::VALID | pte::TABLE_OR_PAGE,
            );
            table = next;
        }
        let desc = SHIM_IPA
            | pte::VALID
            | pte::TABLE_OR_PAGE
            | pte::AF
            | pte::SH_INNER
            | pte::AP_RO
            | pte::UXN;
        self.set_entry(table, index(SHIM_VA, 3), desc);
        Ok(root)
    }

    /// The level-3 table and index of `va`, creating tables on the way if
    /// `create`.
    fn slot(&mut self, root: u64, va: u64, create: bool) -> Result<Option<(u64, usize)>, MmuError> {
        let mut table = root;
        for level in 0..3 {
            let idx = index(va, level);
            let desc = self.entry(table, idx);
            table = if desc & pte::VALID != 0 {
                desc & pte::ADDR_MASK
            } else if create {
                let next = self.new_table()?;
                self.set_entry(table, idx, next | pte::VALID | pte::TABLE_OR_PAGE);
                next
            } else {
                return Ok(None);
            };
        }
        Ok(Some((table, index(va, 3))))
    }

    /// The leaf descriptor of `va` (0 if none).
    pub fn lookup(&self, root: u64, va: u64) -> u64 {
        if va >= MAX_ADDR {
            return 0;
        }
        let mut table = root;
        for level in 0..3 {
            let desc = self.entry(table, index(va, level));
            if desc & pte::VALID == 0 {
                return 0;
            }
            table = desc & pte::ADDR_MASK;
        }
        self.entry(table, index(va, 3))
    }

    /// Drops the page at a slot, if any. Returns whether the hardware may
    /// have cached it (it was valid).
    fn clear_slot(&mut self, table: u64, idx: usize) -> bool {
        let old = self.entry(table, idx);
        if old & pte::SW_MAPPED == 0 {
            return false;
        }
        if let Some(frame) = leaf_frame(old) {
            self.ram_pool.release(frame);
        }
        self.set_entry(table, idx, 0);
        old & pte::VALID != 0
    }

    /// Maps `addr..addr + len` with `prot`, replacing what was there. The
    /// pages get memory on first touch. Returns whether stale TLB entries
    /// may exist; after an error they may.
    pub fn map(&mut self, root: u64, addr: u64, len: u64, prot: Prot) -> Result<bool, MmuError> {
        let end = page_range(addr, len)?;
        let mut flush = false;
        let mut va = addr;
        while va < end {
            let slot = self.slot(root, va, true);
            let (table, idx) = match slot {
                Ok(slot) => slot.expect("created"),
                Err(err) => {
                    // Leave no half-made mapping behind.
                    // The caller flushes the TLB after a failure too:
                    // pages this call already replaced may be cached.
                    self.unmap(root, addr, va - addr)?;
                    return Err(err);
                }
            };
            flush |= self.clear_slot(table, idx);
            self.set_entry(table, idx, leaf(None, prot));
            va += PAGE;
        }
        Ok(flush)
    }

    /// Unmaps `addr..addr + len`; unmapped parts are ignored. Returns
    /// whether stale TLB entries may exist.
    pub fn unmap(&mut self, root: u64, addr: u64, len: u64) -> Result<bool, MmuError> {
        let end = page_range(addr, len)?;
        let mut flush = false;
        let mut va = addr;
        while va < end {
            match self.slot(root, va, false)? {
                Some((table, idx)) => {
                    flush |= self.clear_slot(table, idx);
                    va += PAGE;
                }
                // No level-3 table: skip to the next 2 MiB.
                None => va = (va | 0x1f_ffff) + 1,
            }
        }
        Ok(flush)
    }

    /// Changes the protection of a fully mapped range. Returns whether
    /// stale TLB entries may exist.
    pub fn protect(
        &mut self,
        root: u64,
        addr: u64,
        len: u64,
        prot: Prot,
    ) -> Result<bool, MmuError> {
        let end = page_range(addr, len)?;
        let mut va = addr;
        while va < end {
            if self.lookup(root, va) & pte::SW_MAPPED == 0 {
                return Err(MmuError::BadAddress);
            }
            va += PAGE;
        }
        let mut flush = false;
        let mut va = addr;
        while va < end {
            let (table, idx) = self.slot(root, va, false)?.expect("checked above");
            let old = self.entry(table, idx);
            let frame = leaf_frame(old);
            flush |= old & pte::VALID != 0;
            self.set_entry(table, idx, leaf(frame, prot));
            if let Some(frame) = frame {
                if prot.contains(Prot::EXEC) && !leaf_prot(old).contains(Prot::EXEC) {
                    self.sync_frame(frame);
                }
            }
            va += PAGE;
        }
        Ok(flush)
    }

    /// Handles a translation fault of the app at `va` (top byte already
    /// removed) for `access`.
    pub fn demand(&mut self, root: u64, va: u64, access: Access) -> Demand {
        let va = va & !(PAGE - 1);
        let desc = self.lookup(root, va);
        if desc & pte::SW_MAPPED == 0 {
            return Demand::Unmapped;
        }
        let prot = leaf_prot(desc);
        if !access.allowed(prot) {
            return Demand::Denied;
        }
        if leaf_frame(desc).is_some() {
            return Demand::Present;
        }
        let Some(frame) = self.new_frame() else {
            return Demand::NoMemory;
        };
        if prot.contains(Prot::EXEC) {
            self.sync_frame(frame);
        }
        let (table, idx) = self
            .slot(root, va, false)
            .ok()
            .flatten()
            .expect("the descriptor was found");
        self.set_entry(table, idx, leaf(Some(frame), prot));
        Demand::Filled
    }

    /// Copies app memory at `addr` into `buf`, as the app could read it.
    /// Pages with no memory yet read as zeros.
    pub fn read(&self, root: u64, addr: u64, buf: &mut [u8]) -> Result<(), MmuError> {
        let end = addr
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= MAX_ADDR)
            .ok_or(MmuError::BadAddress)?;
        let mut va = addr;
        while va < end {
            let page_off = (va % PAGE) as usize;
            let n = ((PAGE as usize - page_off) as u64).min(end - va) as usize;
            let desc = self.lookup(root, va);
            if desc & pte::SW_MAPPED == 0 || !Access::Read.allowed(leaf_prot(desc)) {
                return Err(MmuError::BadAddress);
            }
            let at = (va - addr) as usize;
            match leaf_frame(desc) {
                Some(frame) => {
                    buf[at..at + n].copy_from_slice(&self.frame(frame)[page_off..page_off + n])
                }
                None => buf[at..at + n].fill(0),
            }
            va += n as u64;
        }
        Ok(())
    }

    /// Writes `data` to app memory at `addr`; the pages must be writable.
    /// Nothing is written unless all of it can be.
    pub fn write(&mut self, root: u64, addr: u64, data: &[u8]) -> Result<(), MmuError> {
        let end = addr
            .checked_add(data.len() as u64)
            .filter(|&end| end <= MAX_ADDR)
            .ok_or(MmuError::BadAddress)?;
        let first = addr & !(PAGE - 1);
        let mut va = first;
        let mut unbacked = 0;
        while va < end {
            let desc = self.lookup(root, va);
            if desc & pte::SW_MAPPED == 0 || !Access::Write.allowed(leaf_prot(desc)) {
                return Err(MmuError::BadAddress);
            }
            if leaf_frame(desc).is_none() {
                unbacked += 1;
            }
            va += PAGE;
        }
        if unbacked > self.ram_pool.frames - self.ram_pool.in_use() {
            return Err(MmuError::NoMemory);
        }
        let mut va = addr;
        while va < end {
            let page_off = (va % PAGE) as usize;
            let n = ((PAGE as usize - page_off) as u64).min(end - va) as usize;
            let mut desc = self.lookup(root, va);
            if leaf_frame(desc).is_none() {
                let filled = self.demand(root, va, Access::Write);
                debug_assert_eq!(filled, Demand::Filled);
                desc = self.lookup(root, va);
            }
            let frame = leaf_frame(desc).ok_or(MmuError::NoMemory)?;
            let at = (va - addr) as usize;
            self.frame_mut(frame)[page_off..page_off + n].copy_from_slice(&data[at..at + n]);
            if leaf_prot(desc).contains(Prot::EXEC) {
                self.sync_frame(frame);
            }
            va += n as u64;
        }
        Ok(())
    }

    /// Frees an address space: its memory and its tables.
    pub fn destroy(&mut self, root: u64) {
        self.free_table(root, 0);
    }

    fn free_table(&mut self, table: u64, level: u32) {
        for idx in 0..512 {
            let desc = self.entry(table, idx);
            if level < 3 {
                if desc & pte::VALID != 0 {
                    self.free_table(desc & pte::ADDR_MASK, level + 1);
                }
            } else if desc & pte::SW_MAPPED != 0 {
                if let Some(frame) = leaf_frame(desc) {
                    self.ram_pool.release(frame);
                }
            }
        }
        let off = (table - TABLES_IPA) as usize;
        self.tables.bytes_mut()[off..off + PAGE as usize].fill(0);
        self.table_pool.release(table);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phys(tables: usize, ram: usize) -> Phys<Vec<u8>> {
        Phys::new(
            vec![0; tables * PAGE as usize],
            vec![0; ram * PAGE as usize],
        )
    }

    #[test]
    fn map_touch_read_write_unmap() {
        let mut p = phys(16, 16);
        let root = p.new_space().unwrap();
        assert!(!p.map(root, 0x40_0000, 3 * PAGE, Prot::RW).unwrap());
        assert_eq!(p.ram_in_use(), 0, "memory comes on first touch");
        let mut buf = [1u8; 8];
        p.read(root, 0x40_0ffc, &mut buf).unwrap();
        assert_eq!(buf, [0; 8]);
        p.write(root, 0x40_0ffc, b"abcdefgh").unwrap();
        assert_eq!(p.ram_in_use(), 2 * PAGE);
        p.read(root, 0x40_0ffc, &mut buf).unwrap();
        assert_eq!(&buf, b"abcdefgh");
        let desc = p.lookup(root, 0x40_0000);
        assert_ne!(desc & pte::VALID, 0);
        assert_eq!(desc & pte::AP_RO, 0);
        assert_ne!(desc & pte::UXN, 0);
        assert_ne!(desc & pte::PXN, 0);
        assert!(
            p.unmap(root, 0x40_0000, 3 * PAGE).unwrap(),
            "valid pages need a flush"
        );
        assert_eq!(p.ram_in_use(), 0);
        assert_eq!(p.read(root, 0x40_0000, &mut buf), Err(MmuError::BadAddress));
    }

    #[test]
    fn protections_and_faults() {
        let mut p = phys(16, 16);
        let root = p.new_space().unwrap();
        p.map(root, 0x1_0000, PAGE, Prot::READ).unwrap();
        assert_eq!(p.write(root, 0x1_0000, b"x"), Err(MmuError::BadAddress));
        assert_eq!(p.demand(root, 0x1_0010, Access::Write), Demand::Denied);
        assert_eq!(p.demand(root, 0x1_0010, Access::Exec), Demand::Denied);
        assert_eq!(p.demand(root, 0x1_0010, Access::Read), Demand::Filled);
        assert_eq!(p.demand(root, 0x9_0000, Access::Read), Demand::Unmapped);
        assert_ne!(p.lookup(root, 0x1_0000) & pte::AP_RO, 0);
        p.protect(root, 0x1_0000, PAGE, Prot::NONE).unwrap();
        let desc = p.lookup(root, 0x1_0000);
        assert_eq!(desc & pte::VALID, 0, "PROT_NONE is not valid in hardware");
        assert_ne!(desc & pte::ADDR_MASK, 0, "but keeps its memory");
        assert_eq!(p.demand(root, 0x1_0000, Access::Read), Demand::Denied);
        p.protect(root, 0x1_0000, PAGE, Prot::ALL).unwrap();
        let desc = p.lookup(root, 0x1_0000);
        assert_eq!(desc & (pte::UXN | pte::AP_RO), 0);
        assert_eq!(
            p.protect(root, 0x1_0000, 2 * PAGE, Prot::READ),
            Err(MmuError::BadAddress),
            "partly unmapped"
        );
    }

    #[test]
    fn pools_run_out_cleanly() {
        let mut p = phys(4, 2);
        let root = p.new_space().unwrap();
        p.map(root, 0x1_0000, 4 * PAGE, Prot::RW).unwrap();
        assert_eq!(
            p.write(root, 0x1_0000, &[7; 3 * PAGE as usize]),
            Err(MmuError::NoMemory)
        );
        assert_eq!(p.ram_in_use(), 0, "nothing written");
        assert_eq!(p.demand(root, 0x1_0000, Access::Write), Demand::Filled);
        assert_eq!(p.demand(root, 0x1_1000, Access::Write), Demand::Filled);
        assert_eq!(p.demand(root, 0x1_2000, Access::Write), Demand::NoMemory);
        // A far-away mapping needs three new tables; only none are left.
        assert_eq!(
            p.map(root, 0x7f00_0000_0000, PAGE, Prot::RW),
            Err(MmuError::NoMemory)
        );
        p.destroy(root);
        assert_eq!(p.ram_in_use(), 0);
        assert_eq!(p.tables_in_use(), 0);
    }

    #[test]
    fn bad_ranges_are_refused() {
        let mut p = phys(8, 2);
        let root = p.new_space().unwrap();
        assert_eq!(
            p.map(root, 0x1001, PAGE, Prot::RW),
            Err(MmuError::BadAddress)
        );
        assert_eq!(
            p.map(root, MAX_ADDR, PAGE, Prot::RW),
            Err(MmuError::BadAddress)
        );
        assert_eq!(p.unmap(root, !(PAGE - 1), PAGE), Err(MmuError::BadAddress));
        let mut buf = [0u8; 16];
        assert_eq!(
            p.read(root, u64::MAX - 4, &mut buf),
            Err(MmuError::BadAddress)
        );
        assert_eq!(p.write(root, MAX_ADDR - 8, &buf), Err(MmuError::BadAddress));
        assert_eq!(p.demand(root, u64::MAX, Access::Read), Demand::Unmapped);
    }

    #[test]
    fn shim_is_el1_only() {
        let mut p = phys(8, 1);
        let root = p.shim_space().unwrap();
        // The walk of the upper half uses the same indexes.
        let mut table = root;
        for level in 0..3 {
            table = p.entry(table, index(SHIM_VA, level)) & pte::ADDR_MASK;
        }
        let desc = p.entry(table, index(SHIM_VA, 3));
        assert_eq!(desc & pte::ADDR_MASK, SHIM_IPA);
        assert_eq!(desc & pte::AP_EL0, 0, "no EL0 access");
        assert_ne!(desc & pte::AP_RO, 0, "read only");
        assert_ne!(desc & pte::UXN, 0, "EL0 cannot execute it");
        assert_eq!(desc & pte::PXN, 0, "EL1 can");
    }
}
