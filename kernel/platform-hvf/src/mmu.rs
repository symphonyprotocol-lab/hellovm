//! Guest-physical memory and the stage-1 page tables hellovm writes for
//! the app.
//!
//! Two pools of 4 KiB frames live in host memory: page tables (mapped
//! into the VM read only) and app memory (read, write, execute). An
//! address space is a 4-level table tree (4 KiB granule, 48-bit
//! addresses) rooted in `TTBR0_EL1`. Its descriptors are also the only
//! record of what the core mapped: a software bit marks a page as mapped,
//! three more keep its `PROT_*` value and one says it is shared
//! (`MAP_SHARED`), so a page can be mapped but not valid in hardware
//! (`PROT_NONE`, or not yet backed).
//!
//! A range that covers the whole span of an entry above the last level
//! (2 MiB, 1 GiB or 512 GiB) and has no memory yet is one such descriptor
//! there, a *reservation*, with no table below it: reserving address
//! space costs tables only at the edges of the range, whatever its size.
//! A reservation is split into a table of smaller ones when a part of it
//! is touched, unmapped or protected differently. A table whose last
//! entry goes is freed, so tables are held only for what is mapped now.
//!
//! App memory is allocated on first touch: [`Phys::map`] only writes
//! descriptors, and the first access the hardware refuses with a
//! translation fault gets a zeroed frame ([`Phys::demand`]). Frames and
//! tables come from fixed-size pools that are reserved up front: running
//! out fails the operation (or, on first touch, ends the app), and never
//! makes the kernel process allocate more.
//!
//! # Copies of an address space
//!
//! [`Phys::fork`] copies an address space for `fork`: every table is
//! copied at once (see the README for why and what it costs), and every
//! frame is shared between the two. Each app frame has a reference count,
//! kept here on the host side: the number of page descriptors, in all
//! address spaces, that point at it. A frame goes back to the pool when
//! its count drops to zero, and is zeroed when it is handed out again.
//!
//! A private page whose frame is shared is *copy-on-write*: its software
//! `PROT_*` bits allow writing, but its hardware access bits are read
//! only. The first write faults ([`Phys::demand`]); if the frame is still
//! shared, the page gets a copy of it, otherwise (the other users are
//! gone) the page is just made writable again. The core's own writes
//! ([`Phys::write`]) copy the same way. Pages of shared mappings are never
//! copied: both address spaces keep writing the same frame. A shared page
//! (or reservation) with no memory yet gets none at the copy either, as
//! on Linux: the copy marks it, in both address spaces, as taking its
//! memory from a *shared object* made for that copy, a table on the host
//! side from page address to frame. Whoever touches the page first gets a
//! frame and enters it there; the others find it there when they touch
//! the page. The object keeps a reference on each of its frames, so what
//! was written stays for those who have not touched the page yet, and it
//! goes, with those references, with the last descriptor that names it.
//!
//! What keeps one address space out of another's memory:
//!
//! * A frame is reachable only through the descriptors counted in its
//!   reference count (and, for a shared page, through the shared object
//!   that holds it, which only the address spaces copied from the one
//!   that mapped it can name), and it is freed (and zeroed before its
//!   next use) only when that count reaches zero.
//! * A valid descriptor of a private page is writable in hardware only if
//!   its frame's count is 1. Counts only grow in [`Phys::fork`], which
//!   makes every such page read only in both address spaces first.
//! * Whenever a valid descriptor changes or goes, or a table is freed,
//!   [`Phys::take_stale`] reports it, and the platform invalidates the
//!   TLB before the app runs again: the whole TLB, or only that page's
//!   entries in that address space when nothing else changed (a
//!   copy-on-write page that was written; making such a page writable
//!   would not need it for safety, but a stale read-only entry would
//!   fault again).
//!
//! Nothing here trusts app memory: descriptors are read only from the
//! table pool, which the VM cannot write.

use std::collections::HashMap;

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

/// What [`Phys::demand`] did about a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demand {
    /// The page was mapped but had no memory yet, or was copy-on-write
    /// and was written; it is ready now. Resume.
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
        // it at most once (callers release a frame only when its last
        // user goes).
        self.free.push(ipa);
    }

    fn contains(&self, ipa: u64) -> bool {
        ipa >= self.base && ipa < self.base + self.frames * PAGE
    }

    fn in_use(&self) -> u64 {
        self.next - self.free.len() as u64
    }

    fn available(&self) -> u64 {
        self.frames - self.in_use()
    }
}

/// The two pools and the tables in them.
pub struct Phys<B> {
    tables: B,
    ram: B,
    table_pool: Pool,
    ram_pool: Pool,
    /// Per table frame: how many of its 512 entries are not zero. Kept
    /// here, not in the tables, which only the host writes anyway.
    used: Vec<u16>,
    /// Per app frame: how many page descriptors point at it, and shared
    /// objects hold it.
    refs: Vec<u32>,
    /// Shared objects, by number (see the module documentation).
    objects: HashMap<u64, Object>,
    next_object: u64,
    /// What changes since the last [`Phys::take_stale`] may have left
    /// stale in the TLB (see the module documentation).
    stale: Stale,
}

/// Where shared pages that had no memory when their address space was
/// copied get it from.
#[derive(Default)]
struct Object {
    /// Descriptors, in all address spaces, that name it.
    descs: u64,
    /// The frames it holds (with a reference each), by page number.
    frames: HashMap<u64, u64>,
}

/// Most shared objects ever made: their numbers fit a descriptor's
/// address field.
const MAX_OBJECTS: u64 = 1 << 36;

/// What the TLB may hold that is no longer true ([`Phys::take_stale`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stale {
    Clean,
    /// Only entries for the page at `va` of the address space at `root`.
    Page {
        root: u64,
        va: u64,
    },
    /// Anything.
    All,
}

/// What [`Phys::apply`] does to a range.
#[derive(Clone, Copy)]
enum Op {
    /// Map with this protection, shared or not.
    Map(Prot, bool),
    Unmap,
    Protect(Prot),
}

/// The address span of one entry of a table at `level`.
fn span(level: u32) -> u64 {
    1 << (39 - 9 * level)
}

fn index(va: u64, level: u32) -> usize {
    ((va >> (39 - 9 * level)) & 511) as usize
}

/// A page descriptor (or a reservation, without a frame). `exclusive`
/// says that a private page's frame is its alone: only then may the
/// hardware let it be written. A shared page's frame is never copied, so
/// it may always be written if `prot` says so.
fn leaf(frame: Option<u64>, prot: Prot, shared: bool, exclusive: bool) -> u64 {
    let mut sw = pte::SW_MAPPED | ((prot.0 as u64 & 7) << pte::SW_PROT_SHIFT);
    if shared {
        sw |= pte::SW_SHARED;
    }
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
    if !prot.contains(Prot::WRITE) || !(shared || exclusive) {
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
    if leaf_object(desc).is_some() {
        return None;
    }
    let frame = desc & pte::ADDR_MASK;
    (frame != 0).then_some(frame)
}

/// The shared object a descriptor without memory takes it from, if any.
fn leaf_object(desc: u64) -> Option<u64> {
    (desc & pte::VALID == 0 && desc & pte::SW_LAZY != 0).then_some((desc & pte::ADDR_MASK) >> 12)
}

/// `new`, a descriptor without memory, naming the shared object `old`
/// names (if it names one): for a change that keeps the page.
fn keep_object(new: u64, old: u64) -> u64 {
    match leaf_object(old) {
        Some(id) => new | pte::SW_LAZY | (id << 12),
        None => new,
    }
}

fn leaf_shared(desc: u64) -> bool {
    desc & pte::SW_SHARED != 0
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
        let used = vec![0; table_pool.frames as usize];
        let refs = vec![0; ram_pool.frames as usize];
        Phys {
            tables,
            ram,
            table_pool,
            ram_pool,
            used,
            refs,
            objects: HashMap::new(),
            next_object: 1,
            stale: Stale::Clean,
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

    /// What the TLB may hold that changes since the last call made
    /// stale (see the module documentation).
    pub fn take_stale(&mut self) -> Stale {
        std::mem::replace(&mut self.stale, Stale::Clean)
    }

    fn mark_all(&mut self) {
        self.stale = Stale::All;
    }

    fn mark_page(&mut self, root: u64, va: u64) {
        self.stale = match self.stale {
            Stale::Clean => Stale::Page { root, va },
            same @ Stale::Page { root: r, va: v } if (r, v) == (root, va) => same,
            _ => Stale::All,
        };
    }

    fn entry(&self, table: u64, idx: usize) -> u64 {
        let off = (table - TABLES_IPA) as usize + idx * 8;
        u64::from_le_bytes(self.tables.bytes()[off..off + 8].try_into().unwrap())
    }

    fn table_index(table: u64) -> usize {
        ((table - TABLES_IPA) / PAGE) as usize
    }

    fn set_entry(&mut self, table: u64, idx: usize, value: u64) {
        let old = self.entry(table, idx);
        let off = (table - TABLES_IPA) as usize + idx * 8;
        self.tables.bytes_mut()[off..off + 8].copy_from_slice(&value.to_le_bytes());
        let used = &mut self.used[Self::table_index(table)];
        match (old != 0, value != 0) {
            (false, true) => *used += 1,
            (true, false) => *used -= 1,
            _ => {}
        }
        // The new one first: the same object may be named by both.
        if let Some(id) = leaf_object(value) {
            self.object_named(id, 1);
        }
        if let Some(id) = leaf_object(old) {
            self.object_dropped(id);
        }
    }

    /// `count` more descriptors name shared object `id`.
    fn object_named(&mut self, id: u64, count: u64) {
        if let Some(object) = self.objects.get_mut(&id) {
            object.descs += count;
        }
    }

    /// One descriptor less names shared object `id`; with the last one it
    /// goes, and lets go of its frames.
    fn object_dropped(&mut self, id: u64) {
        let Some(object) = self.objects.get_mut(&id) else {
            return;
        };
        object.descs = object.descs.saturating_sub(1);
        if object.descs == 0 {
            if let Some(object) = self.objects.remove(&id) {
                for frame in object.frames.into_values() {
                    self.put_frame(frame);
                }
            }
        }
    }

    /// The frame shared object `id` has for the page at `va`, if any.
    fn object_frame(&self, id: u64, va: u64) -> Option<u64> {
        self.objects.get(&id)?.frames.get(&(va >> 12)).copied()
    }

    fn new_table(&mut self) -> Result<u64, MmuError> {
        let (ipa, dirty) = self.table_pool.alloc().ok_or(MmuError::NoMemory)?;
        if dirty {
            let off = (ipa - TABLES_IPA) as usize;
            self.tables.bytes_mut()[off..off + PAGE as usize].fill(0);
        }
        self.used[Self::table_index(ipa)] = 0;
        Ok(ipa)
    }

    /// Gives a table back to the pool, zeroed. The walk cache may hold it.
    fn release_table(&mut self, table: u64) {
        let off = (table - TABLES_IPA) as usize;
        self.tables.bytes_mut()[off..off + PAGE as usize].fill(0);
        self.used[Self::table_index(table)] = 0;
        self.table_pool.release(table);
        self.mark_all();
    }

    fn frame_index(ipa: u64) -> usize {
        ((ipa - RAM_IPA) / PAGE) as usize
    }

    /// A zeroed frame with one user.
    fn new_frame(&mut self) -> Option<u64> {
        let (ipa, dirty) = self.ram_pool.alloc()?;
        if dirty {
            let off = (ipa - RAM_IPA) as usize;
            self.ram.bytes_mut()[off..off + PAGE as usize].fill(0);
        }
        self.refs[Self::frame_index(ipa)] = 1;
        Some(ipa)
    }

    /// One more descriptor points at `frame`.
    fn get_frame(&mut self, frame: u64) {
        let refs = &mut self.refs[Self::frame_index(frame)];
        // At most one per table entry of the pool, far below the limit.
        *refs = refs.saturating_add(1);
    }

    /// One descriptor less points at `frame`; the last one gives it back.
    fn put_frame(&mut self, frame: u64) {
        let refs = &mut self.refs[Self::frame_index(frame)];
        match *refs {
            0 => log::error!("HVF platform: frame {frame:#x} released twice; kept"),
            1 => {
                *refs = 0;
                self.ram_pool.release(frame);
            }
            _ => *refs -= 1,
        }
    }

    /// Whether `frame` has one user.
    fn exclusive(&self, frame: u64) -> bool {
        self.refs[Self::frame_index(frame)] == 1
    }

    /// The descriptor for a page with `frame`, as the frame's users allow.
    fn page(&self, frame: Option<u64>, prot: Prot, shared: bool) -> u64 {
        let exclusive = frame.is_none_or(|frame| self.exclusive(frame));
        leaf(frame, prot, shared, exclusive)
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

    /// The level-3 table and index of `va`, splitting reservations on the
    /// way. `None` when nothing is mapped there.
    fn leaf_slot(&mut self, root: u64, va: u64) -> Result<Option<(u64, usize)>, MmuError> {
        let mut table = root;
        for level in 0..3 {
            let idx = index(va, level);
            let desc = self.entry(table, idx);
            table = if desc & pte::VALID != 0 {
                desc & pte::ADDR_MASK
            } else if desc & pte::SW_MAPPED != 0 {
                self.split(table, idx)?
            } else {
                return Ok(None);
            };
        }
        Ok(Some((table, index(va, 3))))
    }

    /// Replaces the reservation at a slot above the last level with a
    /// table of 512 smaller ones (unbacked pages, at the last level) of
    /// the same protection and sharing. Returns the table.
    fn split(&mut self, table: u64, idx: usize) -> Result<u64, MmuError> {
        let desc = self.entry(table, idx);
        let child = self.new_table()?;
        let off = (child - TABLES_IPA) as usize;
        let (entries, _) = self.tables.bytes_mut()[off..off + PAGE as usize].as_chunks_mut::<8>();
        for entry in entries {
            *entry = desc.to_le_bytes();
        }
        self.used[Self::table_index(child)] = 512;
        if let Some(id) = leaf_object(desc) {
            self.object_named(id, 512);
        }
        self.set_entry(table, idx, child | pte::VALID | pte::TABLE_OR_PAGE);
        Ok(child)
    }

    /// The descriptor that says what `va` is: its page's (0 if none), or
    /// the reservation that covers it (mapped, no memory).
    pub fn lookup(&self, root: u64, va: u64) -> u64 {
        if va >= MAX_ADDR {
            return 0;
        }
        let mut table = root;
        for level in 0..3 {
            let desc = self.entry(table, index(va, level));
            if desc & pte::VALID == 0 {
                return if desc & pte::SW_MAPPED != 0 { desc } else { 0 };
            }
            table = desc & pte::ADDR_MASK;
        }
        self.entry(table, index(va, 3))
    }

    /// Lets go of the memory of a page descriptor that is being replaced
    /// or removed, if it has any.
    fn drop_page(&mut self, desc: u64) {
        if desc & pte::SW_MAPPED == 0 {
            return;
        }
        if let Some(frame) = leaf_frame(desc) {
            self.put_frame(frame);
        }
        if desc & pte::VALID != 0 {
            self.mark_all();
        }
    }

    /// Does `op` to `addr..end` (page aligned) within the table `table`
    /// of `level`, whose first entry is for address `base`. After an
    /// error the range may be partly changed.
    fn apply(
        &mut self,
        table: u64,
        level: u32,
        base: u64,
        addr: u64,
        end: u64,
        op: Op,
    ) -> Result<(), MmuError> {
        let span = span(level);
        let mut idx = ((addr - base) / span) as usize;
        while idx < 512 && base + idx as u64 * span < end {
            let lo = base + idx as u64 * span;
            let hi = lo + span;
            let (from, to) = (addr.max(lo), end.min(hi));
            let full = from == lo && to == hi;
            let desc = self.entry(table, idx);
            if level == 3 {
                match op {
                    Op::Map(prot, shared) => {
                        self.drop_page(desc);
                        self.set_entry(table, idx, leaf(None, prot, shared, true));
                    }
                    Op::Unmap => {
                        self.drop_page(desc);
                        self.set_entry(table, idx, 0);
                    }
                    Op::Protect(prot) => {
                        if desc & pte::SW_MAPPED != 0 {
                            let frame = leaf_frame(desc);
                            let new = keep_object(self.page(frame, prot, leaf_shared(desc)), desc);
                            if desc & pte::VALID != 0 && new != desc {
                                self.mark_all();
                            }
                            self.set_entry(table, idx, new);
                            if let Some(frame) = frame {
                                if prot.contains(Prot::EXEC)
                                    && !leaf_prot(desc).contains(Prot::EXEC)
                                {
                                    self.sync_frame(frame);
                                }
                            }
                        }
                    }
                }
            } else if desc & pte::VALID != 0 {
                let child = desc & pte::ADDR_MASK;
                match op {
                    // The whole span is replaced: its tables go at once.
                    Op::Map(..) | Op::Unmap if full => {
                        self.free_subtree(child, level + 1);
                        let new = match op {
                            Op::Map(prot, shared) => leaf(None, prot, shared, true),
                            _ => 0,
                        };
                        self.set_entry(table, idx, new);
                    }
                    _ => {
                        self.apply(child, level + 1, lo, from, to, op)?;
                        if self.used[Self::table_index(child)] == 0 {
                            self.release_table(child);
                            self.set_entry(table, idx, 0);
                        }
                    }
                }
            } else if desc & pte::SW_MAPPED != 0 {
                // A reservation: never valid, so nothing is cached of it.
                let new = match op {
                    Op::Map(prot, shared) => leaf(None, prot, shared, true),
                    Op::Protect(prot) => {
                        keep_object(leaf(None, prot, leaf_shared(desc), true), desc)
                    }
                    Op::Unmap => 0,
                };
                if full {
                    self.set_entry(table, idx, new);
                } else if new != desc {
                    let child = self.split(table, idx)?;
                    self.apply(child, level + 1, lo, from, to, op)?;
                }
            } else if let Op::Map(prot, shared) = op {
                if full {
                    self.set_entry(table, idx, leaf(None, prot, shared, true));
                } else {
                    let child = self.new_table()?;
                    self.set_entry(table, idx, child | pte::VALID | pte::TABLE_OR_PAGE);
                    self.apply(child, level + 1, lo, from, to, op)?;
                }
            }
            idx += 1;
        }
        Ok(())
    }

    /// Whether every page of `addr..end` is mapped.
    fn all_mapped(&self, table: u64, level: u32, base: u64, addr: u64, end: u64) -> bool {
        let span = span(level);
        let mut idx = ((addr - base) / span) as usize;
        while idx < 512 && base + idx as u64 * span < end {
            let lo = base + idx as u64 * span;
            let desc = self.entry(table, idx);
            if level < 3 && desc & pte::VALID != 0 {
                let (from, to) = (addr.max(lo), end.min(lo + span));
                if !self.all_mapped(desc & pte::ADDR_MASK, level + 1, lo, from, to) {
                    return false;
                }
            } else if desc & pte::SW_MAPPED == 0 {
                return false;
            }
            idx += 1;
        }
        true
    }

    /// Maps `addr..addr + len` with `prot`, replacing what was there,
    /// private or `shared`. The pages get memory on first touch.
    pub fn map(
        &mut self,
        root: u64,
        addr: u64,
        len: u64,
        prot: Prot,
        shared: bool,
    ) -> Result<(), MmuError> {
        let end = page_range(addr, len)?;
        match self.apply(root, 0, 0, addr, end, Op::Map(prot, shared)) {
            Ok(()) => Ok(()),
            Err(err) => {
                // Leave no half-made mapping behind (unmapping needs no
                // table that is not there already, except to split a
                // reservation at an edge, which the failed map did first).
                let _ = self.apply(root, 0, 0, addr, end, Op::Unmap);
                Err(err)
            }
        }
    }

    /// Unmaps `addr..addr + len`; unmapped parts are ignored.
    pub fn unmap(&mut self, root: u64, addr: u64, len: u64) -> Result<(), MmuError> {
        let end = page_range(addr, len)?;
        self.apply(root, 0, 0, addr, end, Op::Unmap)
    }

    /// Changes the protection of a fully mapped range.
    pub fn protect(&mut self, root: u64, addr: u64, len: u64, prot: Prot) -> Result<(), MmuError> {
        let end = page_range(addr, len)?;
        if !self.all_mapped(root, 0, 0, addr, end) {
            return Err(MmuError::BadAddress);
        }
        self.apply(root, 0, 0, addr, end, Op::Protect(prot))
    }

    /// Handles a translation or permission fault of the app at `va` (top
    /// byte already removed) for `access`: gives an unbacked page its
    /// memory, or a copy-on-write page that is written its own frame.
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
            if access == Access::Write && desc & pte::AP_RO != 0 {
                return match self.unshare(root, va) {
                    Ok(_) => Demand::Filled,
                    Err(_) => Demand::NoMemory,
                };
            }
            return Demand::Present;
        }
        // The page's own slot first (inside a reservation it needs up to
        // three tables), then its memory.
        let Ok(Some((table, idx))) = self.leaf_slot(root, va) else {
            return Demand::NoMemory;
        };
        // A shared page that was there at a copy: the frame its shared
        // object has for it, if another address space touched it first.
        let object = leaf_object(self.entry(table, idx));
        let frame = match object.and_then(|id| self.object_frame(id, va)) {
            Some(frame) => {
                self.get_frame(frame);
                frame
            }
            None => {
                let Some(frame) = self.new_frame() else {
                    return Demand::NoMemory;
                };
                if let Some(held) = object.and_then(|id| self.objects.get_mut(&id)) {
                    held.frames.insert(va >> 12, frame);
                    // The object's own reference.
                    self.get_frame(frame);
                }
                frame
            }
        };
        if prot.contains(Prot::EXEC) {
            self.sync_frame(frame);
        }
        self.set_entry(table, idx, leaf(Some(frame), prot, leaf_shared(desc), true));
        Demand::Filled
    }

    /// Makes the backed, writable page at `va` writable in hardware: with
    /// a copy of its frame if another page still uses it. Returns the
    /// page's frame.
    fn unshare(&mut self, root: u64, va: u64) -> Result<u64, MmuError> {
        // A backed page is never inside a reservation: nothing is split.
        let (table, idx) = self.leaf_slot(root, va)?.ok_or(MmuError::BadAddress)?;
        let desc = self.entry(table, idx);
        let frame = leaf_frame(desc).ok_or(MmuError::BadAddress)?;
        let (prot, shared) = (leaf_prot(desc), leaf_shared(desc));
        if shared || self.exclusive(frame) {
            let new = leaf(Some(frame), prot, shared, true);
            if new != desc {
                self.set_entry(table, idx, new);
                self.mark_page(root, va);
            }
            return Ok(frame);
        }
        let copy = self.new_frame().ok_or(MmuError::NoMemory)?;
        let (from, to) = ((frame - RAM_IPA) as usize, (copy - RAM_IPA) as usize);
        self.ram
            .bytes_mut()
            .copy_within(from..from + PAGE as usize, to);
        if prot.contains(Prot::EXEC) {
            self.sync_frame(copy);
        }
        self.put_frame(frame);
        self.set_entry(table, idx, leaf(Some(copy), prot, false, true));
        if desc & pte::VALID != 0 {
            self.mark_page(root, va);
        }
        Ok(copy)
    }

    /// Copies app memory at `addr` into `buf`, as the app could read it.
    /// Pages with no memory yet read as zeros (or as what another address
    /// space wrote, for a shared page that was there at a copy).
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
            let frame = leaf_frame(desc)
                .or_else(|| self.object_frame(leaf_object(desc)?, va & !(PAGE - 1)));
            match frame {
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
    /// Copy-on-write pages get their own frame first. Nothing is written
    /// unless all of it is mapped writable and there is memory for it.
    pub fn write(&mut self, root: u64, addr: u64, data: &[u8]) -> Result<(), MmuError> {
        let end = addr
            .checked_add(data.len() as u64)
            .filter(|&end| end <= MAX_ADDR)
            .ok_or(MmuError::BadAddress)?;
        let first = addr & !(PAGE - 1);
        let mut va = first;
        let mut needed = 0;
        while va < end {
            let desc = self.lookup(root, va);
            if desc & pte::SW_MAPPED == 0 || !Access::Write.allowed(leaf_prot(desc)) {
                return Err(MmuError::BadAddress);
            }
            match leaf_frame(desc) {
                None => needed += 1,
                Some(frame) if !leaf_shared(desc) && !self.exclusive(frame) => needed += 1,
                Some(_) => {}
            }
            va += PAGE;
        }
        if needed > self.ram_pool.available() {
            return Err(MmuError::NoMemory);
        }
        let mut va = addr;
        while va < end {
            let page_off = (va % PAGE) as usize;
            let n = ((PAGE as usize - page_off) as u64).min(end - va) as usize;
            let desc = self.lookup(root, va);
            let frame = match leaf_frame(desc) {
                // Fails only when a reservation cannot be split for want
                // of tables: then the pages before this one are written.
                None => match self.demand(root, va, Access::Write) {
                    Demand::Filled => leaf_frame(self.lookup(root, va)),
                    _ => None,
                },
                Some(frame) if !leaf_shared(desc) && !self.exclusive(frame) => {
                    self.unshare(root, va & !(PAGE - 1)).ok()
                }
                Some(frame) => Some(frame),
            }
            .ok_or(MmuError::NoMemory)?;
            let at = (va - addr) as usize;
            self.frame_mut(frame)[page_off..page_off + n].copy_from_slice(&data[at..at + n]);
            if leaf_prot(desc).contains(Prot::EXEC) {
                self.sync_frame(frame);
            }
            va += n as u64;
        }
        Ok(())
    }

    /// Copies the address space at `root` for `fork` and returns the
    /// copy's root. Private pages become copy-on-write in both; shared
    /// pages without memory get it from one shared object from now on. On
    /// failure (the table pool is exhausted) there is no copy, and the
    /// original is as it was (its shared pages without memory may name a
    /// shared object, which changes nothing for it).
    pub fn fork(&mut self, root: u64) -> Result<u64, MmuError> {
        if self.count_tables(root, 0) > self.table_pool.available() {
            return Err(MmuError::NoMemory);
        }
        if self.next_object >= MAX_OBJECTS {
            return Err(MmuError::NoMemory);
        }
        let id = self.next_object;
        self.objects.insert(id, Object::default());
        self.name_shared(root, 0, id);
        if self.objects.get(&id).is_some_and(|o| o.descs == 0) {
            // Nothing shared was without memory: no object needed.
            self.objects.remove(&id);
        } else {
            self.next_object += 1;
        }
        self.copy_table(root, 0)
    }

    /// Makes every shared page and reservation below `table` that has no
    /// memory, and names no shared object yet, name `id`. Nothing is
    /// split and no memory is taken.
    fn name_shared(&mut self, table: u64, level: u32, id: u64) {
        for idx in 0..512 {
            let desc = self.entry(table, idx);
            if level < 3 && desc & pte::VALID != 0 {
                self.name_shared(desc & pte::ADDR_MASK, level + 1, id);
            } else if desc & pte::SW_MAPPED != 0
                && leaf_shared(desc)
                && leaf_frame(desc).is_none()
                && leaf_object(desc).is_none()
            {
                self.set_entry(table, idx, desc | pte::SW_LAZY | (id << 12));
            }
        }
    }

    /// How many tables the tree at `table` has.
    fn count_tables(&self, table: u64, level: u32) -> u64 {
        let mut count = 1;
        if level < 3 {
            for idx in 0..512 {
                let desc = self.entry(table, idx);
                if desc & pte::VALID != 0 {
                    count += self.count_tables(desc & pte::ADDR_MASK, level + 1);
                }
            }
        }
        count
    }

    /// Copies the tree at `table` (of `level`) for [`Phys::fork`]. On
    /// failure, nothing of the copy is left.
    fn copy_table(&mut self, table: u64, level: u32) -> Result<u64, MmuError> {
        let copy = self.new_table()?;
        for idx in 0..512 {
            let desc = self.entry(table, idx);
            if desc == 0 {
                continue;
            }
            let new = if level < 3 {
                if desc & pte::VALID != 0 {
                    match self.copy_table(desc & pte::ADDR_MASK, level + 1) {
                        Ok(child) => child | pte::VALID | pte::TABLE_OR_PAGE,
                        Err(err) => {
                            self.free_subtree(copy, level);
                            return Err(err);
                        }
                    }
                } else {
                    // A reservation: no memory to share.
                    desc
                }
            } else if let Some(frame) = leaf_frame(desc) {
                self.get_frame(frame);
                let new = self.page(Some(frame), leaf_prot(desc), leaf_shared(desc));
                if new != desc {
                    // Made read only: the hardware may hold it writable.
                    self.set_entry(table, idx, new);
                    if desc & pte::VALID != 0 {
                        self.mark_all();
                    }
                }
                new
            } else {
                desc
            };
            self.set_entry(copy, idx, new);
        }
        Ok(copy)
    }

    /// Frees an address space: its memory and its tables.
    pub fn destroy(&mut self, root: u64) {
        self.free_subtree(root, 0);
    }

    /// Frees a table and everything below it.
    fn free_subtree(&mut self, table: u64, level: u32) {
        for idx in 0..512 {
            let desc = self.entry(table, idx);
            if level < 3 && desc & pte::VALID != 0 {
                self.free_subtree(desc & pte::ADDR_MASK, level + 1);
                continue;
            }
            if level == 3 {
                self.drop_page(desc);
            }
            // The table is zeroed below without `set_entry`.
            if let Some(id) = leaf_object(desc) {
                self.object_dropped(id);
            }
        }
        self.release_table(table);
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
        p.map(root, 0x40_0000, 3 * PAGE, Prot::RW, false).unwrap();
        assert_eq!(p.take_stale(), Stale::Clean);
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
        p.unmap(root, 0x40_0000, 3 * PAGE).unwrap();
        assert_eq!(p.take_stale(), Stale::All, "valid pages need a flush");
        assert_eq!(p.ram_in_use(), 0);
        assert_eq!(p.read(root, 0x40_0000, &mut buf), Err(MmuError::BadAddress));
    }

    #[test]
    fn protections_and_faults() {
        let mut p = phys(16, 16);
        let root = p.new_space().unwrap();
        p.map(root, 0x1_0000, PAGE, Prot::READ, false).unwrap();
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
        p.map(root, 0x1_0000, 4 * PAGE, Prot::RW, false).unwrap();
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
            p.map(root, 0x7f00_0000_0000, PAGE, Prot::RW, false),
            Err(MmuError::NoMemory)
        );
        p.destroy(root);
        assert_eq!(p.ram_in_use(), 0);
        assert_eq!(p.tables_in_use(), 0);
    }

    #[test]
    fn reserving_address_space_costs_tables_only_at_its_edges() {
        const GIB: u64 = 1 << 30;
        let mut p = phys(16, 16);
        let root = p.new_space().unwrap();
        // 256 GiB, aligned to 1 GiB: 256 entries of one level-1 table.
        p.map(root, 4 * GIB, 256 * GIB, Prot::NONE, false).unwrap();
        assert_eq!(p.tables_in_use(), 2 * PAGE, "the root and one table");
        assert_ne!(p.lookup(root, 100 * GIB + 0x1234) & pte::SW_MAPPED, 0);
        assert_eq!(p.lookup(root, 3 * GIB), 0);
        assert_eq!(p.lookup(root, 260 * GIB), 0);
        assert_eq!(p.demand(root, 100 * GIB, Access::Read), Demand::Denied);
        // A range that is not aligned takes tables at its two ends only.
        p.map(root, 300 * GIB + PAGE, 8 * GIB, Prot::RW, false)
            .unwrap();
        assert_eq!(p.tables_in_use(), 6 * PAGE, "two per end");
        // Making a part usable splits what covers it, and touching a page
        // gives it memory.
        p.protect(root, 100 * GIB, 16 * PAGE, Prot::RW).unwrap();
        assert_eq!(p.tables_in_use(), 8 * PAGE);
        assert_eq!(
            p.demand(root, 100 * GIB + PAGE, Access::Write),
            Demand::Filled
        );
        assert_eq!(
            p.demand(root, 100 * GIB + 16 * PAGE, Access::Write),
            Demand::Denied
        );
        p.write(root, 304 * GIB, b"far").unwrap();
        let mut buf = [0u8; 3];
        p.read(root, 304 * GIB, &mut buf).unwrap();
        assert_eq!(&buf, b"far");
        assert_eq!(p.ram_in_use(), 2 * PAGE);
        // The same protection again splits nothing.
        let before = p.tables_in_use();
        p.protect(root, 200 * GIB + PAGE, PAGE, Prot::NONE).unwrap();
        assert_eq!(p.tables_in_use(), before);
        // A hole in a reservation: the rest stays mapped.
        p.unmap(root, 50 * GIB + PAGE, PAGE).unwrap();
        assert_eq!(p.lookup(root, 50 * GIB + PAGE), 0);
        assert_ne!(p.lookup(root, 50 * GIB) & pte::SW_MAPPED, 0);
        assert_ne!(p.lookup(root, 50 * GIB + 2 * PAGE) & pte::SW_MAPPED, 0);
        assert_eq!(
            p.protect(root, 50 * GIB, 3 * PAGE, Prot::RW),
            Err(MmuError::BadAddress),
            "a hole"
        );
        // Unmapping everything gives every table back but the root.
        p.unmap(root, 0, MAX_ADDR).unwrap();
        assert_eq!(p.take_stale(), Stale::All);
        assert_eq!(p.tables_in_use(), PAGE);
        assert_eq!(p.ram_in_use(), 0);
        // The whole address space is one reservation per root entry.
        p.map(root, 0, MAX_ADDR, Prot::NONE, false).unwrap();
        assert_eq!(p.tables_in_use(), PAGE);
        p.destroy(root);
        assert_eq!(p.tables_in_use(), 0);
    }

    #[test]
    fn tables_are_given_back_when_their_last_page_goes() {
        let mut p = phys(8, 4);
        let root = p.new_space().unwrap();
        // Map, touch and unmap a page at many places far apart: far more
        // than the pool could hold if tables were kept.
        for i in 0..2000u64 {
            let at = 0x1_0000_0000 + i * (1 << 30) + (i % 7) * PAGE;
            p.map(root, at, 2 * PAGE, Prot::RW, false).unwrap();
            p.write(root, at + PAGE - 1, b"xy").unwrap();
            assert_eq!(p.tables_in_use(), 4 * PAGE);
            p.take_stale();
            p.unmap(root, at, PAGE).unwrap();
            assert_eq!(p.take_stale(), Stale::All);
            assert_eq!(p.tables_in_use(), 4 * PAGE, "one page is left");
            p.unmap(root, at + PAGE, PAGE).unwrap();
            assert_eq!(p.take_stale(), Stale::All);
            assert_eq!(p.tables_in_use(), PAGE, "only the root");
            assert_eq!(p.ram_in_use(), 0);
        }
        // Replacing a mapped range with a reservation frees its tables.
        p.map(root, 0x4000_0000, 4 * PAGE, Prot::RW, false).unwrap();
        p.write(root, 0x4000_0000, b"x").unwrap();
        p.map(root, 0x4000_0000, 1 << 30, Prot::NONE, false)
            .unwrap();
        assert_eq!(p.take_stale(), Stale::All);
        assert_eq!(p.tables_in_use(), 2 * PAGE);
        assert_eq!(p.ram_in_use(), 0);
        // Out of tables in the middle of a map: nothing of it is left.
        let mut small = phys(3, 1);
        let root = small.new_space().unwrap();
        assert_eq!(
            small.map(root, 0x1_0000, PAGE, Prot::RW, false),
            Err(MmuError::NoMemory)
        );
        assert_eq!(small.tables_in_use(), PAGE);
        // A reservation that cannot be split for want of tables: the
        // touch fails, and so does a write, with nothing written.
        small.map(root, 0, 1 << 39, Prot::RW, false).unwrap();
        assert_eq!(
            small.demand(root, 0x1_0000, Access::Write),
            Demand::NoMemory
        );
        assert_eq!(small.write(root, 0x1_0000, b"x"), Err(MmuError::NoMemory));
        assert_eq!(small.ram_in_use(), 0);
    }

    #[test]
    fn bad_ranges_are_refused() {
        let mut p = phys(8, 2);
        let root = p.new_space().unwrap();
        assert_eq!(
            p.map(root, 0x1001, PAGE, Prot::RW, false),
            Err(MmuError::BadAddress)
        );
        assert_eq!(
            p.map(root, MAX_ADDR, PAGE, Prot::RW, false),
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

#[cfg(test)]
#[path = "mmu_cow_tests.rs"]
mod cow_tests;
