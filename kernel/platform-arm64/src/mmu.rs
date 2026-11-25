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
//!   [`Phys::take_stale`] reports it, and every vCPU invalidates the TLB
//!   before it runs an app again (a vCPU running that address space is
//!   made to leave the VM first): the whole TLB, or only that page's
//!   entries in that address space when nothing else changed (a
//!   copy-on-write page that was written; making such a page writable
//!   would not need it for safety, but a stale read-only entry would
//!   fault again).
//!
//! Nothing here trusts app memory: descriptors are read only from the
//! table pool, which the VM cannot write.
//!
//! # Warm clones
//!
//! A frozen template's pools are saved as they are ([`Phys::save`]): the
//! tables, the counts, and the frames that are not all zero. A clone (a
//! new process with a new VM of the same size) starts from that with
//! [`Phys::load`]: its tables are a copy of the template's, so every
//! address space and every descriptor is the same, at the same
//! guest-physical addresses; its app memory starts empty, and each frame
//! the template had is *pending*: copied from the template's snapshot
//! (an [`Origin`]) when it is first used. A valid descriptor never points
//! at a pending frame: [`Phys::load`] clears the valid bit of each such
//! page, the first access faults, and [`Phys::demand`] loads the frame
//! and makes the page valid again (a descriptor that is mapped, has a
//! frame and a protection other than `PROT_NONE`, but is not valid is
//! exactly that). The host's own reads of a pending frame read the
//! snapshot, its writes load the frame first. A frame that is freed is
//! not pending any more.

use std::collections::{HashMap, VecDeque};

use hellovm_core::platform::Prot;

use crate::layout::{pte, MAX_ADDR, PAGE, RAM_IPA, SHIM_IPA, SHIM_VA, TABLES_IPA};

/// A page of the `TTBR1_EL1` tree besides the shim
/// ([`Phys::shim_space_with`]): EL1 only, never executable.
#[derive(Clone, Copy, Debug)]
pub struct El1Page {
    pub va: u64,
    /// Its guest-physical address.
    pub ipa: u64,
    pub writable: bool,
    /// Its `MAIR_EL1` attribute.
    pub attr_index: u64,
}

/// Memory the pools live in.
pub trait Backing {
    fn bytes(&self) -> &[u8];
    /// The size in bytes.
    fn len(&self) -> usize {
        self.bytes().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn bytes_mut(&mut self) -> &mut [u8];
    /// Makes code written to `offset..offset + len` visible to the guest's
    /// instruction fetch.
    fn sync_icache(&mut self, offset: usize, len: usize);

    /// Copies the bytes at `offset` into `buf`. App memory may be written
    /// by the app on another vCPU at the same time: an implementation for
    /// guest memory copies without making a reference to it.
    fn read_at(&self, offset: usize, buf: &mut [u8]) {
        buf.copy_from_slice(&self.bytes()[offset..offset + buf.len()]);
    }

    /// Copies `data` to `offset` (see [`Backing::read_at`]).
    fn write_at(&mut self, offset: usize, data: &[u8]) {
        self.bytes_mut()[offset..offset + data.len()].copy_from_slice(data);
    }

    /// Copies `len` bytes from `from` to `to`, which do not overlap.
    fn copy_at(&mut self, from: usize, to: usize, len: usize) {
        self.bytes_mut().copy_within(from..from + len, to);
    }

    /// Zeroes `len` bytes at `offset`.
    fn zero_at(&mut self, offset: usize, len: usize) {
        self.bytes_mut()[offset..offset + len].fill(0);
    }

    /// Gives the memory at `offset..offset + len` (whole host pages) back
    /// to the host. What it holds is undefined from then on, until it is
    /// written again: the bytes it had, or zeros. Only free memory, which
    /// nothing in the VM reaches any more, is given back. The default, for
    /// tests, overwrites it with garbage.
    fn give_back(&mut self, offset: usize, len: usize) {
        self.bytes_mut()[offset..offset + len].fill(0xdb);
    }

    /// Takes memory that was given back for use again (its bytes still
    /// undefined).
    fn take_back(&mut self, _offset: usize, _len: usize) {}

    /// Stores a descriptor at `offset` (a multiple of 8). The table walk
    /// of a vCPU may read it at any time: an implementation for guest
    /// memory stores it with one 64-bit access, so that no walk sees half
    /// of it.
    fn store_u64(&mut self, offset: usize, value: u64) {
        self.bytes_mut()[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
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

/// Where a clone's pending frames come from: the template's app memory,
/// frame by frame (see the module documentation).
pub trait Origin: Send {
    /// Copies frame `index` of the template's app memory (one page) into
    /// `out`, which is [`PAGE`] bytes long.
    fn read_frame(&self, index: usize, out: &mut [u8]);
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

/// Frames in one host page (16 KiB): the unit in which a pool's memory
/// goes back to the host.
const CHUNK: u64 = 4;

/// [`Pool`] chunk flags.
const RETURNED: u8 = 1;
const IN_PARTIAL: u8 = 2;
const IN_WHOLE: u8 = 4;
const IN_RETURNED: u8 = 8;

/// The most chunks taken back from the host at once ([`Pool::alloc`]).
const TAKE_BACK_RUN: u64 = 16;

/// A pool of 4 KiB frames at a guest-physical base, taken from the host
/// a chunk (a host page, four frames) at a time.
///
/// A chunk that was taken is *partial* (some of its frames are free),
/// *full* (none are), *whole* (all four are free, and the host memory
/// behind them is still there) or *returned* (all four are free and
/// their memory was given back to the host, see [`Pool::give_back`]).
/// Frames are handed out from partial chunks first, then whole ones,
/// then returned ones, then new chunks, so that freed memory gathers in
/// whole chunks that can go back. Each list holds a chunk at most once
/// (a flag says it is in it), and may hold chunks that left its state
/// since: those are skipped when they come up.
#[derive(Debug)]
struct Pool {
    base: u64,
    frames: u64,
    /// Chunks below this were taken.
    next: u64,
    /// Per chunk: its free frames, one bit each.
    state: Vec<u8>,
    flags: Vec<u8>,
    partial: Vec<u32>,
    whole: VecDeque<u32>,
    returned: Vec<u32>,
    /// Free frames in chunks taken.
    free: u64,
    /// Whole chunks (with their memory).
    whole_count: u64,
    /// Per chunk: when it last became whole ([`Pool::clock`] then).
    since: Vec<u64>,
    /// The time now, in the caller's unit ([`Phys::set_clock`]).
    clock: u64,
}

/// A frame from [`Pool::alloc`].
struct Alloc {
    ipa: u64,
    /// Chunks (the first one and how many) whose memory was given back
    /// and must be taken back first: the frame's own, and returned ones
    /// next to it, which are whole again.
    reuse: Option<(u64, u64)>,
}

impl Pool {
    fn new(base: u64, bytes: u64) -> Pool {
        let frames = bytes / PAGE;
        let chunks = frames.div_ceil(CHUNK) as usize;
        Pool {
            base,
            frames,
            next: 0,
            state: vec![0; chunks],
            flags: vec![0; chunks],
            partial: Vec::new(),
            whole: VecDeque::new(),
            returned: Vec::new(),
            free: 0,
            whole_count: 0,
            since: vec![0; chunks],
            clock: 0,
        }
    }

    fn chunks(&self) -> u64 {
        self.state.len() as u64
    }

    /// The frames chunk `c` has (four, but the last one may have fewer).
    fn chunk_frames(&self, c: u64) -> u64 {
        CHUNK.min(self.frames - c * CHUNK)
    }

    fn free_mask(&self, c: u64) -> u8 {
        self.state[c as usize] & 0xf
    }

    /// Whether all four frames of `c` are free. A last chunk of fewer
    /// frames never is: it is never given back.
    fn is_whole(&self, c: u64) -> bool {
        self.free_mask(c) == 0xf && self.chunk_frames(c) == CHUNK
    }

    fn is_partial(&self, c: u64) -> bool {
        self.free_mask(c) != 0 && !self.is_whole(c)
    }

    fn returned(&self, c: u64) -> bool {
        self.flags[c as usize] & RETURNED != 0
    }

    /// Frames below this were taken (handed out, or free in a chunk
    /// taken).
    fn taken(&self) -> u64 {
        (self.next * CHUNK).min(self.frames)
    }

    fn push_partial(&mut self, c: u64) {
        if self.is_partial(c) && self.flags[c as usize] & IN_PARTIAL == 0 {
            self.flags[c as usize] |= IN_PARTIAL;
            self.partial.push(c as u32);
        }
    }

    /// Takes the lowest free frame of chunk `c`.
    fn take(&mut self, c: u64) -> Alloc {
        let state = self.state[c as usize];
        let bit = (state & 0xf).trailing_zeros() as u64;
        self.state[c as usize] = state & !(1 << bit);
        self.free -= 1;
        self.push_partial(c);
        Alloc {
            ipa: self.base + (c * CHUNK + bit) * PAGE,
            reuse: None,
        }
    }

    fn alloc(&mut self) -> Option<Alloc> {
        while let Some(&c) = self.partial.last() {
            let c = c as u64;
            if self.is_partial(c) {
                let frame = self.take(c);
                if self.free_mask(c) == 0 {
                    self.partial.pop();
                    self.flags[c as usize] &= !IN_PARTIAL;
                }
                return Some(frame);
            }
            self.partial.pop();
            self.flags[c as usize] &= !IN_PARTIAL;
        }
        // The most recently freed whole chunk: its memory is the likeliest
        // to be in the caches still.
        while let Some(c) = self.whole.pop_back() {
            let c = c as u64;
            self.flags[c as usize] &= !IN_WHOLE;
            if self.is_whole(c) && !self.returned(c) {
                self.whole_count -= 1;
                return Some(self.take(c));
            }
        }
        while let Some(c) = self.returned.pop() {
            let c = c as u64;
            self.flags[c as usize] &= !IN_RETURNED;
            if self.is_whole(c) && self.returned(c) {
                // Returned chunks next to it come back with it, in one
                // call of the host: they are the likeliest to be used
                // next. They are whole again (and may still be in the
                // returned list, where they are skipped).
                let (mut lo, mut hi) = (c, c);
                while lo > 0 && hi - lo + 1 < TAKE_BACK_RUN && self.returned(lo - 1) {
                    lo -= 1;
                }
                while hi + 1 < self.next && hi - lo + 1 < TAKE_BACK_RUN && self.returned(hi + 1) {
                    hi += 1;
                }
                for k in (lo..=hi).rev() {
                    self.flags[k as usize] &= !RETURNED;
                    if k != c {
                        self.now_whole(k);
                    }
                }
                let mut frame = self.take(c);
                frame.reuse = Some((lo, hi - lo + 1));
                return Some(frame);
            }
        }
        if self.next < self.chunks() {
            let c = self.next;
            self.next += 1;
            self.state[c as usize] = ((1u16 << self.chunk_frames(c)) - 1) as u8;
            self.free += self.chunk_frames(c);
            return Some(self.take(c));
        }
        None
    }

    fn release(&mut self, ipa: u64) {
        debug_assert!(self.contains(ipa));
        let i = (ipa - self.base) / PAGE;
        let (c, bit) = (i / CHUNK, i % CHUNK);
        debug_assert!(c < self.next && self.state[c as usize] & (1 << bit) == 0);
        // Callers release a frame only when its last user goes, so each
        // frame is free at most once.
        self.state[c as usize] |= 1 << bit;
        self.free += 1;
        if self.is_whole(c) {
            self.now_whole(c);
        } else {
            self.push_partial(c);
        }
    }

    /// Chunk `c` became whole, with its memory.
    fn now_whole(&mut self, c: u64) {
        self.whole_count += 1;
        self.since[c as usize] = self.clock;
        if self.flags[c as usize] & IN_WHOLE == 0 {
            self.flags[c as usize] |= IN_WHOLE;
            self.whole.push_back(c as u32);
        }
    }

    /// Whether the chunk first in the whole list is whole and not
    /// returned (the list may hold chunks that left that state since).
    fn front_whole(&self) -> Option<u64> {
        let &c = self.whole.front()?;
        let c = c as u64;
        (self.is_whole(c) && !self.returned(c)).then_some(c)
    }

    /// Drops chunks from the front of the whole list that are no longer
    /// whole (so that its front is the one whole longest).
    fn skip_stale(&mut self) {
        while let Some(&c) = self.whole.front() {
            if self.front_whole().is_some() {
                return;
            }
            self.whole.pop_front();
            self.flags[c as usize] &= !IN_WHOLE;
        }
    }

    /// Marks whole chunks returned, the ones whole longest first, while
    /// more than `keep` are left and the next one became whole at
    /// `before` or earlier, and returns them: their memory is to be
    /// given back to the host.
    fn give_back(&mut self, keep: u64, before: u64) -> Vec<u64> {
        let mut out = Vec::new();
        while self.whole_count > keep {
            self.skip_stale();
            let Some(c) = self.front_whole() else {
                break;
            };
            if self.since[c as usize] > before {
                break;
            }
            self.whole.pop_front();
            self.flags[c as usize] &= !IN_WHOLE;
            self.whole_count -= 1;
            self.flags[c as usize] |= RETURNED;
            if self.flags[c as usize] & IN_RETURNED == 0 {
                self.flags[c as usize] |= IN_RETURNED;
                self.returned.push(c as u32);
            }
            out.push(c);
        }
        out
    }

    fn contains(&self, ipa: u64) -> bool {
        ipa >= self.base && ipa < self.base + self.frames * PAGE
    }

    fn in_use(&self) -> u64 {
        self.taken() - self.free
    }

    fn available(&self) -> u64 {
        self.frames - self.in_use()
    }

    /// Checks the lists and counts against the chunks' states (tests).
    #[cfg(test)]
    fn check(&self) {
        let mut free = 0;
        let mut whole = 0;
        let count =
            |list: &mut dyn Iterator<Item = u32>, c: u64| list.filter(|&x| x as u64 == c).count();
        for c in 0..self.chunks() {
            let flags = self.flags[c as usize];
            let state = self.state[c as usize];
            if c >= self.next {
                assert_eq!((state, flags), (0, 0), "chunk {c} not taken");
                continue;
            }
            free += self.free_mask(c).count_ones() as u64;
            let in_partial = count(&mut self.partial.iter().copied(), c);
            let in_whole = count(&mut self.whole.iter().copied(), c);
            let in_returned = count(&mut self.returned.iter().copied(), c);
            assert_eq!(in_partial, (flags & IN_PARTIAL != 0) as usize, "chunk {c}");
            assert_eq!(in_whole, (flags & IN_WHOLE != 0) as usize, "chunk {c}");
            assert_eq!(
                in_returned,
                (flags & IN_RETURNED != 0) as usize,
                "chunk {c}"
            );
            if self.returned(c) {
                assert!(self.is_whole(c) && in_returned == 1, "chunk {c} returned");
            } else if self.is_whole(c) {
                whole += 1;
                assert_eq!(in_whole, 1, "whole chunk {c} not listed");
            } else if self.is_partial(c) {
                assert_eq!(in_partial, 1, "partial chunk {c} not listed");
            }
        }
        assert_eq!(free, self.free, "free frames");
        assert_eq!(whole, self.whole_count, "whole chunks");
    }

    /// The pool's state for a snapshot ([`Phys::save`]).
    fn saved(&self) -> SavedPool {
        let mut free = Vec::new();
        for c in 0..self.next {
            let mask = self.free_mask(c);
            for bit in 0..self.chunk_frames(c) {
                if mask & (1 << bit) != 0 {
                    free.push(self.base + (c * CHUNK + bit) * PAGE);
                }
            }
        }
        SavedPool {
            base: self.base,
            frames: self.frames,
            next: self.taken(),
            free,
        }
    }

    /// A pool like the saved one (checked by [`Phys::load`]), for a
    /// clone: every frame free there is free here. A whole chunk counts
    /// as returned if its memory was never `touched` here (app memory),
    /// and as whole if it was (page tables, which are copied all).
    fn from_saved(saved: &SavedPool, touched: bool) -> Pool {
        let mut pool = Pool::new(saved.base, saved.frames * PAGE);
        pool.next = saved.next.div_ceil(CHUNK);
        let free = |pool: &mut Pool, i: u64| {
            pool.state[(i / CHUNK) as usize] |= 1 << (i % CHUNK);
            pool.free += 1;
        };
        for i in saved.next..pool.taken() {
            free(&mut pool, i);
        }
        for &ipa in &saved.free {
            free(&mut pool, (ipa - saved.base) / PAGE);
        }
        for c in 0..pool.next {
            if pool.is_whole(c) && touched {
                pool.now_whole(c);
            } else if pool.is_whole(c) {
                pool.flags[c as usize] |= RETURNED | IN_RETURNED;
                pool.returned.push(c as u32);
            } else {
                pool.push_partial(c);
            }
        }
        pool
    }
}

/// A pool as it is saved: frames taken, and the free ones among them.
#[derive(Debug)]
pub struct SavedPool {
    base: u64,
    frames: u64,
    next: u64,
    free: Vec<u64>,
}

/// Bytes of one chunk (a host page).
const HOST_PAGE: usize = (CHUNK * PAGE) as usize;

/// Whole free chunks each pool keeps however long they have been free
/// ([`Phys::trim_aged`]): 4 MiB of app memory, 1 MiB of page tables.
pub const RAM_KEEP: u64 = 256;
pub const TABLES_KEEP: u64 = 64;

/// What [`Phys::trim`] gave back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Trimmed {
    /// Host pages (16 KiB) of app memory and of page tables.
    pub ram: u64,
    pub tables: u64,
    /// `madvise` calls (adjacent host pages go back in one).
    pub calls: u64,
    /// Time it took.
    pub nanos: u64,
}

/// Gives back what `pool` returns ([`Pool::give_back`]), in runs of
/// adjacent chunks. Returns the chunks and the runs.
fn give_back<B: Backing>(pool: &mut Pool, backing: &mut B, keep: u64, before: u64) -> (u64, u64) {
    let mut chunks = pool.give_back(keep, before);
    chunks.sort_unstable();
    let mut runs = 0;
    let mut i = 0;
    while i < chunks.len() {
        let mut j = i + 1;
        while j < chunks.len() && chunks[j] == chunks[j - 1] + 1 {
            j += 1;
        }
        let offset = (chunks[i] * CHUNK * PAGE) as usize;
        backing.give_back(offset, (j - i) * HOST_PAGE);
        runs += 1;
        i = j;
    }
    (chunks.len() as u64, runs)
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
    /// A clone's: the template's memory, and per app frame whether it
    /// still has to be copied from it (one bit each).
    origin: Option<Box<dyn Origin>>,
    pending: Vec<u64>,
    /// Frames copied from the origin so far.
    loaded: u64,
    /// What [`Phys::trim`] did so far.
    trimmed: Trimmed,
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
            origin: None,
            pending: Vec::new(),
            loaded: 0,
            trimmed: Trimmed::default(),
        }
    }

    pub fn tables_backing(&self) -> &B {
        &self.tables
    }

    pub fn ram_backing(&self) -> &B {
        &self.ram
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn ram_backing_mut_for_probe(&mut self) -> &mut B {
        &mut self.ram
    }

    /// The app memory's host memory, while no frame of it is in use (see
    /// `VmPlatform::with_app_memory`).
    pub fn ram_mut(&mut self) -> Option<&mut B> {
        (self.ram_pool.taken() == 0).then_some(&mut self.ram)
    }

    /// App memory in use, in bytes.
    pub fn ram_in_use(&self) -> u64 {
        self.ram_pool.in_use() * PAGE
    }

    /// Page-table memory in use, in bytes.
    pub fn tables_in_use(&self) -> u64 {
        self.table_pool.in_use() * PAGE
    }

    /// Sets the time, in any unit that only grows (the same for
    /// [`Phys::trim_aged`]): chunks that become whole are stamped with it.
    pub fn set_clock(&mut self, now: u64) {
        self.ram_pool.clock = now;
        self.table_pool.clock = now;
    }

    /// Gives the memory of whole free chunks back to the host, keeping
    /// `ram` chunks of app memory and `tables` chunks of page tables (the
    /// ones freed last). Call it only when no vCPU can reach a free frame
    /// any more: after the invalidations that the changes which freed them
    /// made necessary (see the module documentation).
    pub fn trim(&mut self, ram: u64, tables: u64) -> Trimmed {
        self.trim_before(ram, tables, u64::MAX)
    }

    /// [`Phys::trim`] of the chunks that have been whole and free for
    /// `age` or longer at `now` (see [`Phys::set_clock`]), beyond
    /// [`RAM_KEEP`] and [`TABLES_KEEP`]. Returns what it gave back and
    /// when the next chunk beyond those will be that old, if one is.
    pub fn trim_aged(&mut self, now: u64, age: u64) -> (Trimmed, Option<u64>) {
        let trimmed = self.trim_before(RAM_KEEP, TABLES_KEEP, now.saturating_sub(age));
        let due = |pool: &mut Pool, keep: u64| {
            pool.skip_stale();
            pool.front_whole()
                .filter(|_| pool.whole_count > keep)
                .map(|c| pool.since[c as usize].saturating_add(age))
        };
        let ram = due(&mut self.ram_pool, RAM_KEEP);
        let tables = due(&mut self.table_pool, TABLES_KEEP);
        (trimmed, ram.into_iter().chain(tables).min())
    }

    fn trim_before(&mut self, ram: u64, tables: u64, before: u64) -> Trimmed {
        let start = std::time::Instant::now();
        let (ram, ram_runs) = give_back(&mut self.ram_pool, &mut self.ram, ram, before);
        let (tables, table_runs) =
            give_back(&mut self.table_pool, &mut self.tables, tables, before);
        let trimmed = Trimmed {
            ram,
            tables,
            calls: ram_runs + table_runs,
            nanos: start.elapsed().as_nanos() as u64,
        };
        let total = &mut self.trimmed;
        total.ram += trimmed.ram;
        total.tables += trimmed.tables;
        total.calls += trimmed.calls;
        total.nanos += trimmed.nanos;
        trimmed
    }

    /// Bytes of free memory still held in whole chunks (both pools).
    pub fn whole_free(&self) -> u64 {
        (self.ram_pool.whole_count + self.table_pool.whole_count) * CHUNK * PAGE
    }

    /// Everything [`Phys::trim`] did so far.
    pub fn trimmed(&self) -> Trimmed {
        self.trimmed
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
        self.tables.store_u64(off, value);
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
        let Alloc { ipa, reuse } = self.table_pool.alloc().ok_or(MmuError::NoMemory)?;
        if let Some((first, chunks)) = reuse {
            self.tables
                .take_back(first as usize * HOST_PAGE, chunks as usize * HOST_PAGE);
        }
        let off = (ipa - TABLES_IPA) as usize;
        self.tables.bytes_mut()[off..off + PAGE as usize].fill(0);
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
    ///
    /// Every frame is zeroed here, by the host, also one never used (whose
    /// memory is zero already): what a frame holds when the app gets it
    /// then never depends on what the host did with memory given back
    /// ([`Backing::give_back`]), and memory the app gets is always
    /// touched by the host first. On macOS that matters for giving it
    /// back: a page whose first touch was the VM's (through stage 2)
    /// stays in the process's footprint after `MADV_FREE_REUSABLE`, one
    /// the host touched first does not (see the README).
    fn new_frame(&mut self) -> Option<u64> {
        let ipa = self.raw_frame()?;
        self.ram.zero_at((ipa - RAM_IPA) as usize, PAGE as usize);
        Some(ipa)
    }

    /// A frame with one user whose bytes are undefined: the caller, the
    /// host, writes all of it before the app can reach it.
    fn raw_frame(&mut self) -> Option<u64> {
        let Alloc { ipa, reuse } = self.ram_pool.alloc()?;
        if let Some((first, chunks)) = reuse {
            self.ram
                .take_back(first as usize * HOST_PAGE, chunks as usize * HOST_PAGE);
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
                self.clear_pending(frame);
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
        let desc = leaf(frame, prot, shared, exclusive);
        match frame {
            // Valid only once loaded (see the module documentation).
            Some(frame) if self.is_pending(frame) => desc & !pte::VALID,
            _ => desc,
        }
    }

    fn is_pending(&self, frame: u64) -> bool {
        let i = Self::frame_index(frame);
        self.pending
            .get(i / 64)
            .is_some_and(|word| word & (1 << (i % 64)) != 0)
    }

    fn clear_pending(&mut self, frame: u64) {
        let i = Self::frame_index(frame);
        if let Some(word) = self.pending.get_mut(i / 64) {
            *word &= !(1 << (i % 64));
        }
    }

    /// Copies a pending frame from the origin; nothing for any other.
    fn load_frame(&mut self, frame: u64) {
        if !self.is_pending(frame) {
            return;
        }
        let mut page = [0u8; PAGE as usize];
        if let Some(origin) = &self.origin {
            origin.read_frame(Self::frame_index(frame), &mut page);
        }
        self.ram.write_at((frame - RAM_IPA) as usize, &page);
        self.clear_pending(frame);
        self.loaded += 1;
    }

    /// Copies bytes of `frame` at `offset` into `buf`: from the origin
    /// while it is pending.
    fn read_frame(&self, frame: u64, offset: usize, buf: &mut [u8]) {
        match &self.origin {
            Some(origin) if self.is_pending(frame) => {
                let mut page = [0u8; PAGE as usize];
                origin.read_frame(Self::frame_index(frame), &mut page);
                buf.copy_from_slice(&page[offset..offset + buf.len()]);
            }
            _ => self.ram.read_at((frame - RAM_IPA) as usize + offset, buf),
        }
    }

    /// Frames copied from the origin so far (a clone's).
    pub fn loaded(&self) -> u64 {
        self.loaded
    }

    #[cfg(test)]
    fn frame(&self, ipa: u64) -> &[u8] {
        let off = (ipa - RAM_IPA) as usize;
        &self.ram.bytes()[off..off + PAGE as usize]
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
        self.shim_space_with(&[])
    }

    /// [`Phys::shim_space`] with more pages for EL1 only, none of them
    /// executable (the KVM platform's register frames and its exit page),
    /// each in the 2 MiB after the shim page. A page outside it, or on the
    /// shim page, is `BadAddress`.
    pub fn shim_space_with(&mut self, extra: &[El1Page]) -> Result<u64, MmuError> {
        let span = SHIM_VA + PAGE..SHIM_VA + (1 << 21);
        if extra.iter().any(|page| {
            !span.contains(&page.va)
                || !page.va.is_multiple_of(PAGE)
                || page.ipa & !pte::ADDR_MASK != 0
        }) {
            return Err(MmuError::BadAddress);
        }
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
        for page in extra {
            let desc = page.ipa
                | pte::VALID
                | pte::TABLE_OR_PAGE
                | pte::AF
                | pte::SH_INNER
                | (page.attr_index & 7) << 2
                | if page.writable { 0 } else { pte::AP_RO }
                | pte::UXN
                | pte::PXN;
            self.set_entry(table, index(page.va, 3), desc);
        }
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
        if let Some(frame) = leaf_frame(desc) {
            if desc & pte::VALID == 0 {
                // Mapped, backed and accessible, but not valid: a page
                // whose frame was pending (see the module documentation).
                self.load_frame(frame);
                let Ok(Some((table, idx))) = self.leaf_slot(root, va) else {
                    return Demand::NoMemory;
                };
                if prot.contains(Prot::EXEC) {
                    self.sync_frame(frame);
                }
                let new = self.page(Some(frame), prot, leaf_shared(desc));
                self.set_entry(table, idx, new);
                if access == Access::Write && new & pte::AP_RO != 0 {
                    return match self.unshare(root, va) {
                        Ok(_) => Demand::Filled,
                        Err(_) => Demand::NoMemory,
                    };
                }
                return Demand::Filled;
            }
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
                self.load_frame(frame);
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
        self.load_frame(frame);
        let (prot, shared) = (leaf_prot(desc), leaf_shared(desc));
        if shared || self.exclusive(frame) {
            let new = leaf(Some(frame), prot, shared, true);
            if new != desc {
                self.set_entry(table, idx, new);
                self.mark_page(root, va);
            }
            return Ok(frame);
        }
        // Written whole by the copy: no need to zero it first.
        let copy = self.raw_frame().ok_or(MmuError::NoMemory)?;
        let (from, to) = ((frame - RAM_IPA) as usize, (copy - RAM_IPA) as usize);
        self.ram.copy_at(from, to, PAGE as usize);
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
                Some(frame) => self.read_frame(frame, page_off, &mut buf[at..at + n]),
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
                Some(frame) => {
                    self.load_frame(frame);
                    Some(frame)
                }
            }
            .ok_or(MmuError::NoMemory)?;
            let at = (va - addr) as usize;
            self.ram
                .write_at((frame - RAM_IPA) as usize + page_off, &data[at..at + n]);
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

hellovm_core::snap_struct!(SavedPool {
    base,
    frames,
    next,
    free
});
hellovm_core::snap_struct!(Object { descs, frames });

/// The state of the pools apart from their contents ([`Phys::save`]).
pub struct Saved {
    table_pool: SavedPool,
    ram_pool: SavedPool,
    used: Vec<u16>,
    refs: Vec<u32>,
    objects: HashMap<u64, Object>,
    next_object: u64,
    /// Bytes of the table pool that were saved (all of it that was used).
    tables_len: u64,
    /// Per app frame, one bit: saved (not all zero).
    stored: Vec<u64>,
}

hellovm_core::snap_struct!(Saved {
    table_pool,
    ram_pool,
    used,
    refs,
    objects,
    next_object,
    tables_len,
    stored,
});

/// What [`Phys::save`] wrote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaveStats {
    /// App frames in use.
    pub frames: u64,
    /// Of those, the ones saved (the others are all zero).
    pub stored: u64,
    /// Bytes of page tables saved.
    pub tables: u64,
    /// Frames written as zeros between two saved ones (see `gap` in
    /// [`Phys::save`]).
    pub padded: u64,
}

impl<B: Backing> Phys<B> {
    /// Saves a frozen template's pools for its clones (see the module
    /// documentation): the used part of the table pool into `tables`,
    /// each app frame in use that is not all zero into `ram` at its own
    /// offset (the rest of `ram` is left alone: zero), and returns the
    /// rest of the state as bytes for [`Phys::load`]. `tables` and `ram`
    /// are as large as the pools. Nothing may run meanwhile.
    ///
    /// With `gap` > 0, fewer than `gap` frames between two saved ones are
    /// written too, as zeros: a snapshot that clones map from its file in
    /// runs of written pages (the KVM platform's, see
    /// [`Hypervisor::SNAPSHOT_GAP`](crate::Hypervisor::SNAPSHOT_GAP)) then
    /// has fewer, longer runs.
    pub fn save(
        &self,
        tables: &mut [u8],
        ram: &mut [u8],
        gap: u64,
        w: &mut hellovm_core::snap::Writer<'_>,
    ) -> SaveStats {
        use hellovm_core::snap::Snap;
        let tables_len = (self.table_pool.taken() * PAGE) as usize;
        let mut stats = SaveStats {
            tables: tables_len as u64,
            ..SaveStats::default()
        };
        tables[..tables_len].copy_from_slice(&self.tables.bytes()[..tables_len]);
        let mut stored = vec![0u64; self.refs.len().div_ceil(64)];
        let mut page = [0u8; PAGE as usize];
        let mut last: Option<usize> = None;
        for (i, &refs) in self
            .refs
            .iter()
            .enumerate()
            .take(self.ram_pool.taken() as usize)
        {
            if refs == 0 {
                continue;
            }
            stats.frames += 1;
            let off = i * PAGE as usize;
            self.ram.read_at(off, &mut page);
            if page.iter().all(|&b| b == 0) {
                continue;
            }
            ram[off..off + PAGE as usize].copy_from_slice(&page);
            stored[i / 64] |= 1 << (i % 64);
            stats.stored += 1;
            if let Some(last) = last.filter(|&last| i - last > 1 && ((i - last - 1) as u64) < gap) {
                // Written, not left alone: a file allocates what is written.
                ram[(last + 1) * PAGE as usize..off].fill(0);
                stats.padded += (i - last - 1) as u64;
            }
            last = Some(i);
        }
        // The fields of `Saved`, in its order, without copying the pools'
        // state first.
        self.table_pool.saved().put(w);
        self.ram_pool.saved().put(w);
        self.used.put(w);
        self.refs.put(w);
        self.objects.put(w);
        self.next_object.put(w);
        (tables_len as u64).put(w);
        stored.put(w);
        stats
    }

    /// Makes these pools, made for a VM of the template's size and with
    /// nothing allocated but the shim's tables, a clone of the saved
    /// ones: `meta` from [`Phys::save`], `tables` the saved table pool,
    /// `origin` the saved app memory, `roots` the address spaces the clone
    /// will use. Checks that the tables of those spaces stay inside the
    /// pools, and leaves each page whose frame is pending not valid (see
    /// the module documentation).
    ///
    /// Without an `origin`, nothing is pending: the app memory already
    /// holds the template's (the KVM platform maps the snapshot's frames
    /// into it, privately, before it loads: see `hellovm-platform-kvm`).
    pub fn load(
        &mut self,
        saved: Saved,
        tables: &[u8],
        origin: Option<Box<dyn Origin>>,
        roots: &[u64],
    ) -> Result<(), String> {
        let same = |a: &SavedPool, b: &Pool| a.base == b.base && a.frames == b.frames;
        if !same(&saved.table_pool, &self.table_pool) || !same(&saved.ram_pool, &self.ram_pool) {
            return Err("the snapshot is of a VM of another size".into());
        }
        let pool_ok = |pool: &SavedPool| {
            let mut seen = vec![false; pool.frames as usize];
            pool.next <= pool.frames
                && pool.free.len() as u64 <= pool.next
                && pool.free.iter().all(|&ipa| {
                    let i = ((ipa.wrapping_sub(pool.base)) / PAGE) as usize;
                    ipa.is_multiple_of(PAGE)
                        && ipa >= pool.base
                        && (i as u64) < pool.next
                        && !std::mem::replace(&mut seen[i], true)
                })
        };
        if !pool_ok(&saved.table_pool) || !pool_ok(&saved.ram_pool) {
            return Err("the snapshot's pools are inconsistent".into());
        }
        if saved.used.len() != self.used.len()
            || saved.refs.len() != self.refs.len()
            || saved.stored.len() != self.refs.len().div_ceil(64)
            || saved.tables_len != saved.table_pool.next * PAGE
            || saved
                .ram_pool
                .free
                .iter()
                .any(|&ipa| saved.refs[Self::frame_index(ipa)] != 0)
            || tables.len() as u64 != saved.tables_len
            || saved.next_object > MAX_OBJECTS
        {
            return Err("the snapshot's pools are inconsistent".into());
        }
        let frame_ok = |ipa: u64| {
            ipa.is_multiple_of(PAGE)
                && ipa >= RAM_IPA
                && (ipa - RAM_IPA) / PAGE < saved.ram_pool.frames
                && saved.refs[Self::frame_index(ipa)] > 0
        };
        if !saved
            .objects
            .values()
            .all(|o| o.frames.values().all(|&f| frame_ok(f)))
        {
            return Err("a shared object of the snapshot holds a frame not in use".into());
        }
        // The shim's tables, the only ones allocated so far, are the
        // first ones of both pools, with the same contents.
        let shim = (self.table_pool.taken() * PAGE) as usize;
        if tables.len() < shim || tables[..shim] != self.tables.bytes()[..shim] {
            return Err("the snapshot's shim tables differ".into());
        }
        self.tables.bytes_mut()[..tables.len()].copy_from_slice(tables);
        self.table_pool = Pool::from_saved(&saved.table_pool, true);
        self.ram_pool = Pool::from_saved(&saved.ram_pool, false);
        self.used = saved.used;
        self.refs = saved.refs;
        self.objects = saved.objects;
        self.next_object = saved.next_object;
        // Only frames in use are pending, and only with an origin.
        let mut pending = saved.stored;
        for (i, &refs) in self.refs.iter().enumerate() {
            if refs == 0 || origin.is_none() {
                pending[i / 64] &= !(1 << (i % 64));
            }
        }
        self.pending = pending;
        self.origin = origin;
        for &root in roots {
            self.adopt(root, 0)?;
        }
        Ok(())
    }

    /// Checks the tree at `table` (of `level`) for [`Phys::load`] and
    /// makes each of its pages with a pending frame not valid.
    fn adopt(&mut self, table: u64, level: u32) -> Result<(), String> {
        if !table.is_multiple_of(PAGE) || !self.table_pool.contains(table) {
            return Err(format!("a table at {table:#x}, outside the table pool"));
        }
        for idx in 0..512 {
            let desc = self.entry(table, idx);
            if level < 3 {
                if desc & pte::VALID != 0 {
                    self.adopt(desc & pte::ADDR_MASK, level + 1)?;
                }
                continue;
            }
            let Some(frame) = leaf_frame(desc) else {
                continue;
            };
            if desc & pte::SW_MAPPED == 0 || !self.ram_pool.contains(frame) {
                return Err(format!("a page at {frame:#x}, outside app memory"));
            }
            if desc & pte::VALID != 0 && self.is_pending(frame) {
                let off = (table - TABLES_IPA) as usize + idx * 8;
                self.tables.store_u64(off, desc & !pte::VALID);
            }
        }
        Ok(())
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

    /// The template's app memory as a clone's origin.
    struct VecOrigin(Vec<u8>);

    impl Origin for VecOrigin {
        fn read_frame(&self, index: usize, out: &mut [u8]) {
            let off = index * PAGE as usize;
            out.copy_from_slice(&self.0[off..off + PAGE as usize]);
        }
    }

    #[test]
    fn a_clone_loads_frames_on_first_touch_and_keeps_its_writes() {
        let (tables, ram) = (64, 64);
        let mut t = phys(tables, ram);
        t.shim_space().unwrap();
        let a = t.new_space().unwrap();
        t.map(a, 0x40_0000, 4 * PAGE, Prot::RW, false).unwrap();
        t.map(a, 0x80_0000, 2 * PAGE, Prot::RW, true).unwrap();
        t.write(a, 0x40_0000, b"private").unwrap();
        t.write(a, 0x40_2000, &[0; 8]).unwrap(); // in use, all zero
        t.write(a, 0x80_0000, b"shared").unwrap();
        let b = t.fork(a).unwrap();
        t.write(b, 0x40_1000, b"child's").unwrap();
        let mut saved_tables = vec![0u8; tables * PAGE as usize];
        let mut saved_ram = vec![0u8; ram * PAGE as usize];
        let mut w = hellovm_core::snap::Writer::new();
        let stats = t.save(&mut saved_tables, &mut saved_ram, 0, &mut w);
        let meta = w.into_inner();
        let saved = |meta: &[u8]| {
            let mut r = hellovm_core::snap::Reader::new(meta);
            <Saved as hellovm_core::snap::Snap>::get(&mut r)
        };
        assert_eq!(stats.frames, 4);
        assert_eq!(stats.stored, 3, "the zero frame is not stored");
        saved_tables.truncate(stats.tables as usize);

        let mut c = phys(tables, ram);
        c.shim_space().unwrap();
        c.load(
            saved(&meta).unwrap(),
            &saved_tables,
            Some(Box::new(VecOrigin(saved_ram.clone()))),
            &[a, b],
        )
        .unwrap();
        // Same counts; nothing copied yet, and no valid page points at a
        // pending frame.
        assert_eq!(c.ram_in_use(), t.ram_in_use());
        assert_eq!(c.loaded(), 0);
        assert_eq!(c.lookup(a, 0x40_0000) & pte::VALID, 0);
        // The host reads the origin without loading.
        let mut buf = [0u8; 7];
        c.read(a, 0x40_0000, &mut buf).unwrap();
        assert_eq!(&buf, b"private");
        assert_eq!(c.loaded(), 0);
        // A read fault loads the frame and makes the page valid; it stays
        // copy-on-write, being shared with the other space.
        assert_eq!(c.demand(b, 0x40_0000, Access::Read), Demand::Filled);
        assert_eq!(c.loaded(), 1);
        let desc = c.lookup(b, 0x40_0000);
        assert_ne!(desc & pte::VALID, 0);
        assert_ne!(desc & pte::AP_RO, 0);
        // The other space's page names the loaded frame: valid at its
        // first fault, without another copy.
        assert_eq!(c.demand(a, 0x40_0000, Access::Read), Demand::Filled);
        assert_eq!(c.loaded(), 1);
        // A write fault copies: the other space keeps the template's bytes.
        assert_eq!(c.demand(a, 0x40_0000, Access::Write), Demand::Filled);
        c.write(a, 0x40_0000, b"CHANGED").unwrap();
        c.read(b, 0x40_0000, &mut buf).unwrap();
        assert_eq!(&buf, b"private");
        // The host's write to a pending, exclusive frame loads it first:
        // the bytes around the write are the template's.
        c.write(b, 0x40_1000, b"C").unwrap();
        c.read(b, 0x40_1000, &mut buf).unwrap();
        assert_eq!(&buf, b"Child's");
        // Shared memory stays shared between the clone's spaces.
        c.write(b, 0x80_0000, b"S").unwrap();
        let mut six = [0u8; 6];
        c.read(a, 0x80_0000, &mut six).unwrap();
        assert_eq!(&six, b"Shared");
        // The template's memory never changed.
        assert_eq!(&saved_ram[..7], b"private");
        // Freeing a pending frame forgets it; reallocated, it is zero.
        c.unmap(a, 0x40_0000, 4 * PAGE).unwrap();
        c.unmap(b, 0x40_0000, 4 * PAGE).unwrap();
        c.map(a, 0x90_0000, PAGE, Prot::RW, false).unwrap();
        let mut eight = [1u8; 8];
        assert_eq!(c.demand(a, 0x90_0000, Access::Read), Demand::Filled);
        c.read(a, 0x90_0000, &mut eight).unwrap();
        assert_eq!(eight, [0; 8]);

        // A snapshot of another size, or tables outside the pool, are
        // refused.
        let mut d = phys(tables, ram * 2);
        d.shim_space().unwrap();
        assert!(d
            .load(
                saved(&meta).unwrap(),
                &saved_tables,
                Some(Box::new(VecOrigin(saved_ram.clone()))),
                &[a]
            )
            .is_err());
        let mut e = phys(tables, ram);
        e.shim_space().unwrap();
        assert!(e
            .load(
                saved(&meta).unwrap(),
                &saved_tables,
                Some(Box::new(VecOrigin(saved_ram))),
                &[0x1234_5000]
            )
            .is_err());
        assert!(saved(&meta[..meta.len() / 2]).is_err());
    }

    /// The KVM way: the clone's app memory already holds the snapshot's
    /// frames (mapped from its file), so nothing is pending; gaps shorter
    /// than `gap` between saved frames are written as zeros.
    #[test]
    fn a_clone_with_its_memory_mapped_has_nothing_pending() {
        let (tables, ram) = (64, 64);
        let mut t = phys(tables, ram);
        t.shim_space().unwrap();
        let a = t.new_space().unwrap();
        t.map(a, 0x40_0000, 8 * PAGE, Prot::RW, false).unwrap();
        t.write(a, 0x40_0000, b"first").unwrap();
        // In use and all zero: frames 1 and 2 of the pool.
        t.write(a, 0x40_1000, &[0; 8]).unwrap();
        t.write(a, 0x40_2000, &[0; 8]).unwrap();
        t.write(a, 0x40_3000, b"second").unwrap();
        let b = t.fork(a).unwrap();
        let mut saved_tables = vec![0u8; tables * PAGE as usize];
        // Garbage where nothing is written: padding must write its zeros.
        let mut saved_ram = vec![0xeeu8; ram * PAGE as usize];
        let mut w = hellovm_core::snap::Writer::new();
        let stats = t.save(&mut saved_tables, &mut saved_ram, 32, &mut w);
        assert_eq!((stats.frames, stats.stored, stats.padded), (4, 2, 2));
        let first = t.lookup(a, 0x40_0000) & pte::ADDR_MASK;
        let off = (first - RAM_IPA) as usize;
        assert!(saved_ram[off + PAGE as usize..off + 3 * PAGE as usize]
            .iter()
            .all(|&b| b == 0));
        // Past the last saved frame nothing is written.
        assert_eq!(saved_ram[off + 4 * PAGE as usize], 0xee);
        // No padding without a gap to fill.
        let mut again = vec![0xeeu8; ram * PAGE as usize];
        let mut w0 = hellovm_core::snap::Writer::new();
        let unpadded = t.save(&mut saved_tables.clone(), &mut again, 2, &mut w0);
        assert_eq!(unpadded.padded, 0);
        let meta = w.into_inner();
        saved_tables.truncate(stats.tables as usize);
        for page in saved_ram.chunks_mut(PAGE as usize) {
            if page.iter().all(|&b| b == 0xee) {
                page.fill(0);
            }
        }

        // The clone's memory is the snapshot's, as a private mapping makes it.
        let mut c = Phys::new(vec![0; tables * PAGE as usize], saved_ram.clone());
        c.shim_space().unwrap();
        let mut r = hellovm_core::snap::Reader::new(&meta);
        let saved = <Saved as hellovm_core::snap::Snap>::get(&mut r).unwrap();
        c.load(saved, &saved_tables, None, &[a, b]).unwrap();
        // Valid at once, copy-on-write between the clone's spaces.
        let desc = c.lookup(a, 0x40_0000);
        assert_ne!(desc & pte::VALID, 0);
        assert_ne!(desc & pte::AP_RO, 0);
        let mut buf = [0u8; 6];
        c.read(b, 0x40_3000, &mut buf).unwrap();
        assert_eq!(&buf, b"second");
        assert_eq!(c.demand(a, 0x40_0000, Access::Write), Demand::Filled);
        c.write(a, 0x40_0000, b"FIRST").unwrap();
        c.read(b, 0x40_0000, &mut buf[..5]).unwrap();
        assert_eq!(&buf[..5], b"first");
        assert_eq!(c.loaded(), 0, "nothing is copied from an origin");
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

#[cfg(test)]
#[path = "mmu_trim_tests.rs"]
mod trim_tests;
