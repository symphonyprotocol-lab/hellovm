//! Tests of copies of address spaces (`Phys::fork`), copy-on-write and
//! frame reference counts, and a randomized test of `mmu` against a
//! simple model of what each address space should hold.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use super::*;

fn phys(tables: usize, ram: usize) -> Phys<Vec<u8>> {
    Phys::new(
        vec![0; tables * PAGE as usize],
        vec![0; ram * PAGE as usize],
    )
}

const RX: Prot = Prot(Prot::READ.0 | Prot::EXEC.0);

/// Checks every invariant of the pools against the trees at `roots`
/// (every live address space):
///
/// * each frame's count is the number of page descriptors that point at
///   it plus the shared objects that hold it, a frame is free exactly
///   when its count is 0, and the free lists have no duplicates;
/// * each shared object is named by as many descriptors as it counts,
///   and none is left that no descriptor names;
/// * each table is reachable once, its count of used entries is right,
///   and the pool holds exactly the reachable tables;
/// * a valid private page is writable in hardware only if its frame has
///   one user and its `PROT_*` allows writing; valid means backed and not
///   `PROT_NONE`; the hardware bits match the software ones.
fn check(p: &Phys<Vec<u8>>, roots: &[u64]) {
    let mut refs: HashMap<u64, u32> = HashMap::new();
    let mut tables = HashSet::new();
    let mut named: HashMap<u64, u64> = HashMap::new();
    fn walk(
        p: &Phys<Vec<u8>>,
        table: u64,
        level: u32,
        refs: &mut HashMap<u64, u32>,
        tables: &mut HashSet<u64>,
        named: &mut HashMap<u64, u64>,
    ) {
        assert!(tables.insert(table), "table {table:#x} reachable twice");
        let mut used = 0;
        let off = (table - TABLES_IPA) as usize;
        let (entries, _) = p.tables.bytes()[off..off + PAGE as usize].as_chunks::<8>();
        for &entry in entries {
            let desc = u64::from_le_bytes(entry);
            if desc != 0 {
                used += 1;
            }
            if !(level < 3 && desc & pte::VALID != 0) {
                if let Some(id) = leaf_object(desc) {
                    assert!(leaf_shared(desc), "a private page names a shared object");
                    *named.entry(id).or_default() += 1;
                }
            }
            if level < 3 {
                if desc & pte::VALID != 0 {
                    assert_eq!(desc & !pte::ADDR_MASK, pte::VALID | pte::TABLE_OR_PAGE);
                    walk(p, desc & pte::ADDR_MASK, level + 1, refs, tables, named);
                } else if desc != 0 {
                    assert_ne!(desc & pte::SW_MAPPED, 0, "junk in a table");
                    assert_eq!(leaf_frame(desc), None, "a reservation with memory");
                }
                continue;
            }
            if desc == 0 {
                continue;
            }
            assert_ne!(desc & pte::SW_MAPPED, 0, "junk in a table");
            let prot = leaf_prot(desc);
            let Some(frame) = leaf_frame(desc) else {
                assert_eq!(desc & pte::VALID, 0, "valid without memory");
                continue;
            };
            *refs.entry(frame).or_default() += 1;
            assert_eq!(
                desc & pte::VALID != 0,
                prot != Prot::NONE,
                "valid exactly when backed and accessible"
            );
            if desc & pte::VALID != 0 {
                let writable = desc & pte::AP_RO == 0;
                if writable {
                    assert!(prot.contains(Prot::WRITE), "writable against its prot");
                    if !leaf_shared(desc) {
                        assert!(
                            p.exclusive(frame),
                            "a private page is writable while its frame is shared"
                        );
                    }
                }
                assert_eq!(desc & pte::UXN == 0, prot.contains(Prot::EXEC));
                assert_ne!(desc & pte::PXN, 0);
                assert_ne!(desc & pte::NG, 0);
            }
        }
        assert_eq!(
            p.used[Phys::<Vec<u8>>::table_index(table)],
            used,
            "used count"
        );
    }
    for &root in roots {
        walk(p, root, 0, &mut refs, &mut tables, &mut named);
    }
    assert_eq!(p.objects.len(), named.len(), "a shared object nobody names");
    for (id, object) in &p.objects {
        assert_eq!(Some(&object.descs), named.get(id), "object {id}");
        for &frame in object.frames.values() {
            *refs.entry(frame).or_default() += 1;
        }
    }
    assert_eq!(p.table_pool.in_use(), tables.len() as u64, "tables leaked");
    p.ram_pool.check();
    p.table_pool.check();
    let ram_free = p.ram_pool.saved().free;
    let free: HashSet<u64> = ram_free.iter().copied().collect();
    assert_eq!(free.len(), ram_free.len(), "a frame freed twice");
    for (&frame, &count) in &refs {
        let i = Phys::<Vec<u8>>::frame_index(frame);
        assert!(
            (i as u64) < p.ram_pool.taken(),
            "frame {frame:#x} never handed out"
        );
        assert_eq!(p.refs[i], count, "count of frame {frame:#x}");
    }
    // Every other frame handed out is free, with a count of 0.
    let counted = p.refs[..p.ram_pool.taken() as usize]
        .iter()
        .filter(|&&n| n != 0)
        .count();
    assert_eq!(counted, refs.len(), "a frame with users that no page uses");
    assert_eq!(p.ram_pool.in_use(), refs.len() as u64, "frames leaked");
    for &frame in &ram_free {
        assert_eq!(
            p.refs[Phys::<Vec<u8>>::frame_index(frame)],
            0,
            "{frame:#x} free"
        );
    }
}

#[test]
fn fork_shares_frames_until_written() {
    let mut p = phys(32, 32);
    let parent = p.new_space().unwrap();
    p.map(parent, 0x40_0000, 4 * PAGE, Prot::RW, false).unwrap();
    p.write(parent, 0x40_0000, b"parent").unwrap();
    p.write(parent, 0x40_1000, b"second").unwrap();
    assert_eq!(p.ram_in_use(), 2 * PAGE);
    p.take_stale();
    let child = p.fork(parent).unwrap();
    assert_eq!(
        p.take_stale(),
        Stale::All,
        "writable pages became read only"
    );
    assert_eq!(p.ram_in_use(), 2 * PAGE, "no memory copied");
    check(&p, &[parent, child]);
    for root in [parent, child] {
        let desc = p.lookup(root, 0x40_0000);
        assert_ne!(desc & pte::VALID, 0);
        assert_ne!(desc & pte::AP_RO, 0, "copy-on-write");
        assert_eq!(leaf_prot(desc), Prot::RW);
    }
    // The child writes: it gets a copy, the parent keeps the original.
    assert_eq!(p.demand(child, 0x40_0003, Access::Write), Demand::Filled);
    assert_eq!(
        p.take_stale(),
        Stale::Page {
            root: child,
            va: 0x40_0000
        },
        "the page points at another frame now"
    );
    assert_eq!(p.ram_in_use(), 3 * PAGE);
    p.write(child, 0x40_0000, b"child!").unwrap();
    let mut buf = [0u8; 6];
    p.read(parent, 0x40_0000, &mut buf).unwrap();
    assert_eq!(&buf, b"parent");
    p.read(child, 0x40_0000, &mut buf).unwrap();
    assert_eq!(&buf, b"child!");
    // The parent's frame has one user again: writing just makes it
    // writable (the page's read-only entry is invalidated all the same).
    assert_eq!(p.demand(parent, 0x40_0000, Access::Write), Demand::Filled);
    assert_eq!(
        p.take_stale(),
        Stale::Page {
            root: parent,
            va: 0x40_0000
        }
    );
    assert_eq!(p.ram_in_use(), 3 * PAGE);
    assert_eq!(p.lookup(parent, 0x40_0000) & pte::AP_RO, 0);
    // A read of a copy-on-write page is not a write.
    assert_eq!(p.demand(child, 0x40_1000, Access::Read), Demand::Present);
    // Untouched pages stay without memory in both.
    assert_eq!(leaf_frame(p.lookup(child, 0x40_2000)), None);
    check(&p, &[parent, child]);
    p.destroy(parent);
    check(&p, &[child]);
    assert_eq!(p.ram_in_use(), 2 * PAGE, "the child's two pages");
    p.destroy(child);
    check(&p, &[]);
    assert_eq!(p.ram_in_use(), 0);
    assert_eq!(p.tables_in_use(), 0);
}

#[test]
fn forks_of_forks_free_each_frame_once() {
    let mut p = phys(64, 64);
    let a = p.new_space().unwrap();
    p.map(a, 0x10_0000, 8 * PAGE, Prot::RW, false).unwrap();
    for i in 0..8u64 {
        p.write(a, 0x10_0000 + i * PAGE, &[i as u8 + 1]).unwrap();
    }
    let b = p.fork(a).unwrap();
    let c = p.fork(b).unwrap();
    let d = p.fork(a).unwrap();
    check(&p, &[a, b, c, d]);
    assert_eq!(p.refs[0], 4);
    // Each writes a different page; everyone else still sees the original.
    for (i, root) in [a, b, c, d].into_iter().enumerate() {
        p.write(root, 0x10_0000 + i as u64 * PAGE, &[0x80 | i as u8])
            .unwrap();
    }
    check(&p, &[a, b, c, d]);
    for (i, root) in [a, b, c, d].into_iter().enumerate() {
        for page in 0..8u64 {
            let mut byte = [0u8];
            p.read(root, 0x10_0000 + page * PAGE, &mut byte).unwrap();
            let want = if page == i as u64 {
                0x80 | i as u8
            } else {
                page as u8 + 1
            };
            assert_eq!(byte[0], want, "space {i} page {page}");
        }
    }
    // Destroyed in a different order from their creation, with checks.
    p.destroy(b);
    check(&p, &[a, c, d]);
    p.destroy(a);
    check(&p, &[c, d]);
    let e = p.fork(c).unwrap();
    p.destroy(c);
    check(&p, &[d, e]);
    p.destroy(d);
    p.destroy(e);
    check(&p, &[]);
    assert_eq!((p.ram_in_use(), p.tables_in_use()), (0, 0));
}

#[test]
fn shared_mappings_stay_shared() {
    let mut p = phys(64, 1024);
    let a = p.new_space().unwrap();
    // A shared page that was touched, two that were not, and a shared
    // reservation (a whole 2 MiB entry) with no memory at all.
    p.map(a, 0x20_0000, 3 * PAGE, Prot::RW, true).unwrap();
    p.write(a, 0x20_0000, b"before").unwrap();
    p.map(a, 0x40_0000, 1 << 21, Prot::RW, true).unwrap();
    assert_eq!(p.tables_in_use(), 4 * PAGE);
    let b = p.fork(a).unwrap();
    check(&p, &[a, b]);
    // The copy took no memory and split nothing: the shared pages that
    // had none still have none, and the reservation is one descriptor.
    assert_eq!(p.ram_in_use(), PAGE);
    assert_eq!(p.tables_in_use(), 8 * PAGE);
    for root in [a, b] {
        let desc = p.lookup(root, 0x20_0000);
        assert_ne!(desc & pte::SW_SHARED, 0);
        assert_eq!(desc & pte::AP_RO, 0, "shared pages stay writable");
        assert_eq!(leaf_frame(p.lookup(root, 0x20_1000)), None);
    }
    // Writes by either side, by the core or by the app, reach the other,
    // whoever touches a page first.
    p.write(b, 0x20_0000, b"child ").unwrap();
    p.write(a, 0x20_1000, b"parent").unwrap();
    let mut early = [0u8; 6];
    p.read(b, 0x20_1000, &mut early).unwrap();
    assert_eq!(&early, b"parent", "read before b touched the page");
    assert_eq!(
        p.demand(b, 0x40_0000 + 77 * PAGE, Access::Write),
        Demand::Filled
    );
    p.write(b, 0x40_0000 + 77 * PAGE, b"far").unwrap();
    assert_eq!(
        p.demand(a, 0x40_0000 + 77 * PAGE, Access::Read),
        Demand::Filled,
        "a gets the frame b made"
    );
    check(&p, &[a, b]);
    let mut buf = [0u8; 6];
    p.read(a, 0x20_0000, &mut buf).unwrap();
    assert_eq!(&buf, b"child ");
    p.read(b, 0x20_1000, &mut buf).unwrap();
    assert_eq!(&buf, b"parent");
    p.read(a, 0x40_0000 + 77 * PAGE, &mut buf[..3]).unwrap();
    assert_eq!(&buf[..3], b"far");
    assert_eq!(p.ram_in_use(), 3 * PAGE, "one frame per page touched");
    // A fork of the fork shares the same frames.
    let c = p.fork(b).unwrap();
    p.write(c, 0x20_2000, b"third").unwrap();
    p.read(a, 0x20_2000, &mut buf[..5]).unwrap();
    assert_eq!(&buf[..5], b"third");
    check(&p, &[a, b, c]);
    // Read only for one of them: the others still write.
    p.protect(a, 0x20_0000, 3 * PAGE, Prot::READ).unwrap();
    assert_eq!(p.write(a, 0x20_0000, b"x"), Err(MmuError::BadAddress));
    p.write(b, 0x20_0000, b"y").unwrap();
    p.read(a, 0x20_0000, &mut buf[..1]).unwrap();
    assert_eq!(&buf[..1], b"y");
    // Unmapping it in one leaves it to the others.
    p.unmap(b, 0x20_0000, 3 * PAGE).unwrap();
    p.read(c, 0x20_0000, &mut buf[..1]).unwrap();
    assert_eq!(&buf[..1], b"y");
    check(&p, &[a, b, c]);
    // What one wrote and unmapped is still there for one that had not
    // touched the page: the shared object holds it.
    p.write(c, 0x40_0000 + 9 * PAGE, b"kept").unwrap();
    p.unmap(c, 0x40_0000, 1 << 21).unwrap();
    p.protect(a, 0x40_0000 + 9 * PAGE, PAGE, Prot::READ)
        .unwrap();
    p.read(a, 0x40_0000 + 9 * PAGE, &mut buf[..4]).unwrap();
    assert_eq!(&buf[..4], b"kept");
    assert_eq!(
        p.demand(a, 0x40_0000 + 9 * PAGE, Access::Read),
        Demand::Filled
    );
    check(&p, &[a, b, c]);
    // A huge shared reservation costs a fork nothing.
    let before = (p.ram_in_use(), p.tables_in_use());
    p.map(a, 1 << 39, 1 << 38, Prot::RW, true).unwrap();
    let d = p.fork(a).unwrap();
    assert_eq!(p.ram_in_use(), before.0);
    p.write(d, (1 << 39) + (5 << 30), b"deep").unwrap();
    p.read(a, (1 << 39) + (5 << 30), &mut buf[..4]).unwrap();
    assert_eq!(&buf[..4], b"deep");
    check(&p, &[a, b, c, d]);
    p.destroy(d);
    check(&p, &[a, b, c]);
    for root in [a, b, c] {
        p.destroy(root);
    }
    check(&p, &[]);
    assert_eq!((p.ram_in_use(), p.tables_in_use()), (0, 0));
}

#[test]
fn the_cores_writes_copy_and_its_reads_see_the_right_frame() {
    let mut p = phys(32, 32);
    let a = p.new_space().unwrap();
    p.map(a, 0x30_0000, 2 * PAGE, Prot::RW, false).unwrap();
    p.write(a, 0x30_0ffe, b"abcd").unwrap();
    let b = p.fork(a).unwrap();
    // A write by the core across two copy-on-write pages: both copied.
    p.write(b, 0x30_0fff, b"XY").unwrap();
    assert_eq!(p.ram_in_use(), 4 * PAGE);
    let mut buf = [0u8; 4];
    p.read(a, 0x30_0ffe, &mut buf).unwrap();
    assert_eq!(&buf, b"abcd");
    p.read(b, 0x30_0ffe, &mut buf).unwrap();
    assert_eq!(&buf, b"aXYd");
    // The core's write to a page that is no longer shared copies nothing.
    p.write(a, 0x30_0000, b"z").unwrap();
    assert_eq!(p.ram_in_use(), 4 * PAGE);
    check(&p, &[a, b]);
    // Not enough memory for the copies: nothing is written.
    let mut small = phys(16, 3);
    let a = small.new_space().unwrap();
    small.map(a, 0x30_0000, 2 * PAGE, Prot::RW, false).unwrap();
    small.write(a, 0x30_0000, &[1; 2 * PAGE as usize]).unwrap();
    let b = small.fork(a).unwrap();
    assert_eq!(
        small.write(b, 0x30_0000, &[2; 2 * PAGE as usize]),
        Err(MmuError::NoMemory)
    );
    small.read(b, 0x30_0000, &mut buf).unwrap();
    assert_eq!(buf, [1; 4], "nothing written");
    check(&small, &[a, b]);
    // A write fault with no memory left changes nothing either.
    small.write(b, 0x30_0000, b"q").unwrap();
    assert_eq!(small.demand(b, 0x30_1000, Access::Write), Demand::NoMemory);
    assert_ne!(small.lookup(b, 0x30_1000) & pte::AP_RO, 0);
    check(&small, &[a, b]);
}

#[test]
fn protection_changes_keep_copy_on_write() {
    let mut p = phys(32, 32);
    let a = p.new_space().unwrap();
    p.map(a, 0x50_0000, PAGE, Prot::RW, false).unwrap();
    p.write(a, 0x50_0000, b"data").unwrap();
    let b = p.fork(a).unwrap();
    // Through PROT_NONE and read only and back: still not writable in
    // hardware while the frame is shared.
    for prot in [Prot::NONE, Prot::READ, Prot::RW, Prot::ALL] {
        p.protect(b, 0x50_0000, PAGE, prot).unwrap();
        check(&p, &[a, b]);
    }
    assert_ne!(p.lookup(b, 0x50_0000) & pte::AP_RO, 0);
    // An executable copy-on-write page: the copy keeps it executable.
    assert_eq!(p.demand(b, 0x50_0000, Access::Write), Demand::Filled);
    let desc = p.lookup(b, 0x50_0000);
    assert_eq!(desc & (pte::AP_RO | pte::UXN), 0);
    let mut buf = [0u8; 4];
    p.read(b, 0x50_0000, &mut buf).unwrap();
    assert_eq!(&buf, b"data");
    // Once the other user is gone, read only to writable is writable.
    p.destroy(a);
    p.protect(b, 0x50_0000, PAGE, Prot::READ).unwrap();
    p.protect(b, 0x50_0000, PAGE, Prot::RW).unwrap();
    assert_eq!(p.lookup(b, 0x50_0000) & pte::AP_RO, 0);
    check(&p, &[b]);
}

#[test]
fn running_out_in_the_middle_of_a_fork_leaves_no_copy() {
    // The parent's tree has 5 tables (root, one per level down to its
    // first page, and another last-level one for its second); 9 tables
    // in all leave room for 4 more only.
    let mut p = phys(9, 8);
    let a = p.new_space().unwrap();
    p.map(a, 0x40_0000, PAGE, Prot::RW, false).unwrap();
    p.map(a, 0x60_0000, PAGE, Prot::RW, false).unwrap();
    p.write(a, 0x40_0000, b"keep").unwrap();
    p.write(a, 0x60_0000, b"this").unwrap();
    let before = (p.ram_in_use(), p.tables_in_use());
    p.take_stale();
    assert_eq!(p.fork(a), Err(MmuError::NoMemory));
    assert_eq!((p.ram_in_use(), p.tables_in_use()), before);
    assert_eq!(p.lookup(a, 0x40_0000) & pte::AP_RO, 0, "still writable");
    assert_eq!(p.take_stale(), Stale::Clean, "nothing changed");
    check(&p, &[a]);
    // If the copy itself runs out half way (the count above makes that
    // impossible through `fork`), what was copied is undone: here the
    // first page was copied (its frame had two users) before the second
    // last-level table could not be had.
    assert_eq!(p.copy_table(a, 0), Err(MmuError::NoMemory));
    assert_eq!((p.ram_in_use(), p.tables_in_use()), before);
    check(&p, &[a]);
    assert_eq!(p.refs[0], 1);
    p.write(a, 0x40_0000, b"more").unwrap();
    assert_eq!(
        p.ram_in_use(),
        before.0,
        "no copy: the frame is the parent's alone"
    );
    // Shared pages without memory take none at a fork, however little is
    // left; running out later fails that touch only.
    let mut p = phys(16, 2);
    let a = p.new_space().unwrap();
    p.map(a, 0x40_0000, 4 * PAGE, Prot::RW, true).unwrap();
    let b = p.fork(a).unwrap();
    assert_eq!(p.ram_in_use(), 0);
    assert_eq!(p.demand(b, 0x40_0000, Access::Write), Demand::Filled);
    assert_eq!(p.demand(a, 0x40_1000, Access::Write), Demand::Filled);
    assert_eq!(p.demand(b, 0x40_2000, Access::Write), Demand::NoMemory);
    assert_eq!(p.write(a, 0x40_3000, b"x"), Err(MmuError::NoMemory));
    // A page the other touched needs no new memory.
    assert_eq!(p.demand(a, 0x40_0000, Access::Read), Demand::Filled);
    assert_eq!(p.ram_in_use(), 2 * PAGE);
    check(&p, &[a, b]);
    p.destroy(a);
    check(&p, &[b]);
    p.destroy(b);
    check(&p, &[]);
    assert_eq!((p.ram_in_use(), p.tables_in_use()), (0, 0));
}

#[test]
fn reservations_are_copied_without_memory() {
    const GIB: u64 = 1 << 30;
    let mut p = phys(32, 8);
    let a = p.new_space().unwrap();
    p.map(a, 4 * GIB, 64 * GIB, Prot::NONE, false).unwrap();
    p.map(a, 0x40_0000, 1 << 21, Prot::RW, false).unwrap();
    let b = p.fork(a).unwrap();
    assert_eq!(p.ram_in_use(), 0);
    assert_eq!(p.tables_in_use(), 6 * PAGE, "three per space");
    assert_eq!(p.demand(b, 10 * GIB, Access::Read), Demand::Denied);
    assert_eq!(p.demand(b, 0x40_0000, Access::Write), Demand::Filled);
    assert_eq!(leaf_frame(p.lookup(a, 0x40_0000)), None, "only the child's");
    check(&p, &[a, b]);
}

// The randomized test.

/// A small xorshift generator: fixed seeds, no dependencies.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What one page holds in the model: private pages are values (cloned at
/// a fork, `Rc` only saves memory), shared pages are one object for all
/// the spaces that share them. An empty vector is a page of zeros.
#[derive(Clone)]
enum Data {
    Private(Rc<Vec<u8>>),
    Shared(Rc<RefCell<Vec<u8>>>),
}

#[derive(Clone)]
struct Page {
    prot: Prot,
    data: Data,
}

impl Page {
    fn bytes(&self) -> Vec<u8> {
        let bytes = match &self.data {
            Data::Private(data) => data.as_ref().clone(),
            Data::Shared(data) => data.borrow().clone(),
        };
        if bytes.is_empty() {
            vec![0; PAGE as usize]
        } else {
            bytes
        }
    }

    fn write(&mut self, off: usize, src: &[u8]) {
        let store = |bytes: &mut Vec<u8>| {
            if bytes.is_empty() {
                bytes.resize(PAGE as usize, 0);
            }
            bytes[off..off + src.len()].copy_from_slice(src);
        };
        match &mut self.data {
            Data::Private(data) => store(Rc::make_mut(data)),
            Data::Shared(data) => store(&mut data.borrow_mut()),
        }
    }
}

type Space = BTreeMap<u64, Page>;

/// Windows of address space the operations use: one that straddles 2 MiB
/// boundaries (with two whole 2 MiB entries, for reservations), one
/// across a 1 GiB boundary and one across a 512 GiB boundary.
const WINDOWS: [u64; 3] = [0x40_0000, (1 << 30) - (1 << 21), (1 << 39) - (1 << 21)];
const WINDOW: u64 = 4 << 20;

fn random_range(rng: &mut Rng) -> (u64, u64) {
    let window = WINDOWS[rng.below(3) as usize];
    let pages = WINDOW / PAGE;
    let start = match rng.below(4) {
        // 2 MiB aligned, to make and split reservations.
        0 => rng.below(2) * 512,
        _ => rng.below(pages),
    };
    let max = pages - start;
    let len = match rng.below(4) {
        0 => (512).min(max),
        1 => 1 + rng.below(max),
        _ => 1 + rng.below(8.min(max)),
    };
    (window + start * PAGE, len * PAGE)
}

/// A mapped page of `space` at or after a random place, if any.
fn mapped_page(rng: &mut Rng, space: &Space) -> Option<u64> {
    let (addr, _) = random_range(rng);
    space
        .range(addr..)
        .next()
        .or_else(|| space.iter().next())
        .map(|(&va, _)| va)
}

fn random_prot(rng: &mut Rng) -> Prot {
    [Prot::NONE, Prot::READ, Prot::RW, RX, Prot::ALL, Prot::WRITE][rng.below(6) as usize]
}

/// A simulated TLB: what the hardware may have cached for a page of an
/// address space since the last flush (all of it: a new entry need not
/// replace an older one for the same page).
#[derive(Default)]
struct Tlb {
    entries: HashMap<(u64, u64), Vec<u64>>,
}

impl Tlb {
    /// What the platform's flush before the app runs again does.
    fn flush(&mut self, stale: Stale) {
        match stale {
            Stale::Clean => {}
            Stale::Page { root, va } => {
                self.entries.remove(&(root, va));
            }
            Stale::All => self.entries.clear(),
        }
    }

    /// Every cached entry must still be as permissive as it claims: same
    /// frame, and not writable or executable where the page is not.
    fn check(&self, p: &Phys<Vec<u8>>, live: &[u64]) {
        for (&(root, va), cached) in &self.entries {
            for &cached in cached {
                Self::check_one(p, live, root, va, cached);
            }
        }
    }

    fn check_one(p: &Phys<Vec<u8>>, live: &[u64], root: u64, va: u64, cached: u64) {
        {
            assert!(
                live.contains(&root),
                "an entry of a destroyed space survived without a flush"
            );
            let now = p.lookup(root, va);
            assert_ne!(now & pte::VALID, 0, "{va:#x}: cached but no longer valid");
            assert_eq!(
                now & pte::ADDR_MASK,
                cached & pte::ADDR_MASK,
                "{va:#x}: cached for another frame"
            );
            if cached & pte::AP_RO == 0 {
                assert_eq!(now & pte::AP_RO, 0, "{va:#x}: cached writable");
            }
            if cached & pte::UXN == 0 {
                assert_eq!(now & pte::UXN, 0, "{va:#x}: cached executable");
            }
        }
    }
}

/// Compares one page of an address space with the model.
fn compare_page(p: &Phys<Vec<u8>>, root: u64, va: u64, page: Option<&Page>) {
    let desc = p.lookup(root, va);
    let Some(page) = page else {
        assert_eq!(desc & pte::SW_MAPPED, 0, "{va:#x} is mapped");
        return;
    };
    assert_ne!(desc & pte::SW_MAPPED, 0, "{va:#x} is not mapped");
    assert_eq!(leaf_prot(desc), page.prot, "{va:#x} protection");
    assert_eq!(
        leaf_shared(desc),
        matches!(page.data, Data::Shared(_)),
        "{va:#x} sharing"
    );
    // A shared page this address space has not touched reads as what
    // its shared object holds for it.
    let frame = leaf_frame(desc).or_else(|| p.object_frame(leaf_object(desc)?, va));
    let same = |bytes: &[u8]| match frame {
        Some(frame) if bytes.is_empty() => p.frame(frame).iter().all(|&b| b == 0),
        Some(frame) => p.frame(frame) == bytes,
        None => bytes.iter().all(|&b| b == 0),
    };
    let same = match &page.data {
        Data::Private(data) => same(data),
        Data::Shared(data) => same(&data.borrow()),
    };
    assert!(same, "{va:#x} contents");
}

fn compare_range(p: &Phys<Vec<u8>>, root: u64, space: &Space, addr: u64, len: u64) {
    let mut va = addr;
    while va < addr + len {
        compare_page(p, root, va, space.get(&va));
        va += PAGE;
    }
}

fn compare_all(p: &Phys<Vec<u8>>, spaces: &[(u64, Space)]) {
    for (root, space) in spaces {
        for window in WINDOWS {
            compare_range(p, *root, space, window, WINDOW);
        }
    }
}

/// Random map, unmap, protect, write, read, touch (an access by the
/// app), fork and destroy over a few address spaces, checked against the
/// model after every step: the touched pages of every space, the
/// invariants of `check`, and the simulated TLB; everything after each
/// fork and every 200 steps. The pools are large enough that nothing runs out.
fn model_run(seed: u64, steps: usize) {
    let mut rng = Rng(seed);
    let mut p = phys(1024, 8192);
    let mut spaces: Vec<(u64, Space)> = vec![(p.new_space().unwrap(), Space::new())];
    let mut tlb = Tlb::default();
    // Pages touched lately: touches go back to them half of the time, as
    // an app's accesses do, so that what the TLB holds gets changed.
    let mut hot: Vec<(u64, u64)> = Vec::new();
    let mut counts = [0usize; 8];
    let mut trimmed = 0;
    for step in 0..steps {
        let which = rng.below(spaces.len() as u64) as usize;
        let root = spaces[which].0;
        let op = match rng.below(100) {
            0..=14 => 0,  // map
            15..=21 => 1, // unmap
            22..=33 => 2, // protect
            34..=55 => 3, // write
            56..=67 => 4, // read
            68..=89 => 5, // touch
            90..=95 => 6, // fork
            _ => 7,       // destroy
        };
        counts[op] += 1;
        let (addr, len) = random_range(&mut rng);
        let context = format!("seed {seed} step {step} op {op} space {which} {addr:#x}+{len:#x}");
        // Pages outside `addr..addr + len` the step touched.
        let mut also = None;
        match op {
            0 => {
                let prot = random_prot(&mut rng);
                let shared = rng.below(4) == 0;
                p.map(root, addr, len, prot, shared).unwrap();
                let space = &mut spaces[which].1;
                for va in (addr..addr + len).step_by(PAGE as usize) {
                    let data = if shared {
                        // One object per page, shared by the copies.
                        Data::Shared(Rc::new(RefCell::new(Vec::new())))
                    } else {
                        Data::Private(Rc::new(Vec::new()))
                    };
                    space.insert(va, Page { prot, data });
                }
            }
            1 => {
                p.unmap(root, addr, len).unwrap();
                let space = &mut spaces[which].1;
                for va in (addr..addr + len).step_by(PAGE as usize) {
                    space.remove(&va);
                }
            }
            2 => {
                let prot = random_prot(&mut rng);
                let space = &mut spaces[which].1;
                let all = (addr..addr + len)
                    .step_by(PAGE as usize)
                    .all(|va| space.contains_key(&va));
                let result = p.protect(root, addr, len, prot);
                if all {
                    result.unwrap();
                    for va in (addr..addr + len).step_by(PAGE as usize) {
                        space.get_mut(&va).unwrap().prot = prot;
                    }
                } else {
                    assert_eq!(result, Err(MmuError::BadAddress), "{context}");
                }
            }
            3 => {
                let at = match (hot.len(), rng.below(3)) {
                    (n, 0) if n > 0 => hot[rng.below(n as u64) as usize].1,
                    (_, 1) => mapped_page(&mut rng, &spaces[which].1).unwrap_or(addr),
                    _ => addr,
                } + rng.below(len.min(2 * PAGE));
                let n = 1 + rng.below(2 * PAGE) as usize;
                let n = n.min((MAX_ADDR - at) as usize);
                let data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                let space = &mut spaces[which].1;
                let first = at & !(PAGE - 1);
                let ok = (first..at + n as u64).step_by(PAGE as usize).all(|va| {
                    space
                        .get(&va)
                        .is_some_and(|pg| pg.prot.contains(Prot::WRITE))
                });
                let result = p.write(root, at, &data);
                also = Some((first, (at + n as u64).next_multiple_of(PAGE) - first));
                if ok {
                    result.unwrap();
                    let mut done = 0;
                    while done < n {
                        let va = at + done as u64;
                        let off = (va % PAGE) as usize;
                        let k = (PAGE as usize - off).min(n - done);
                        space
                            .get_mut(&(va - off as u64))
                            .unwrap()
                            .write(off, &data[done..done + k]);
                        done += k;
                    }
                } else {
                    assert_eq!(result, Err(MmuError::BadAddress), "{context}");
                }
            }
            4 => {
                let at = addr + rng.below(len.min(2 * PAGE));
                let n = 1 + rng.below(2 * PAGE) as usize;
                let space = &spaces[which].1;
                let first = at & !(PAGE - 1);
                let ok = (first..at + n as u64)
                    .step_by(PAGE as usize)
                    .all(|va| space.get(&va).is_some_and(|pg| pg.prot != Prot::NONE));
                let mut buf = vec![0u8; n];
                let result = p.read(root, at, &mut buf);
                if ok {
                    result.unwrap();
                    let mut want = Vec::new();
                    let mut va = first;
                    while va < at + n as u64 {
                        want.extend(space[&va].bytes());
                        va += PAGE;
                    }
                    let off = (at - first) as usize;
                    assert!(buf == want[off..off + n], "{context}: read");
                } else {
                    assert_eq!(result, Err(MmuError::BadAddress), "{context}");
                }
            }
            5 => {
                // A hot page, in the space that touched it or in any.
                let again = match hot.len() {
                    n if n > 0 && rng.below(4) != 0 => {
                        let (root, va) = hot[rng.below(n as u64) as usize];
                        match spaces.iter().position(|(r, _)| *r == root) {
                            Some(which) if rng.below(2) == 0 => Some((which, root, va)),
                            _ => Some((which, spaces[which].0, va)),
                        }
                    }
                    _ => None,
                };
                let (which, root, va) = again.unwrap_or_else(|| {
                    let mapped = match rng.below(3) {
                        0 => None,
                        _ => mapped_page(&mut rng, &spaces[which].1),
                    };
                    (
                        which,
                        root,
                        mapped.unwrap_or(addr + rng.below(len) / PAGE * PAGE),
                    )
                });
                if hot.len() == 16 {
                    hot.remove(0);
                }
                hot.push((root, va));
                let access = [Access::Read, Access::Write, Access::Exec][rng.below(3) as usize];
                let page = spaces[which].1.get(&va);
                let got = p.demand(root, va + rng.below(PAGE), access);
                // The platform flushes before the app runs again, which
                // may then cache what the page is now.
                tlb.flush(p.take_stale());
                match page {
                    None => assert_eq!(got, Demand::Unmapped, "{context}"),
                    Some(page) if !access.allowed(page.prot) => {
                        assert_eq!(got, Demand::Denied, "{context}")
                    }
                    Some(_) => {
                        assert!(
                            matches!(got, Demand::Filled | Demand::Present),
                            "{context}: {got:?}"
                        );
                        // What the hardware sees now, it may cache.
                        let desc = p.lookup(root, va);
                        assert_ne!(desc & pte::VALID, 0, "{context}");
                        if access == Access::Write {
                            assert_eq!(desc & pte::AP_RO, 0, "{context}: not writable");
                        }
                        tlb.entries.entry((root, va)).or_default().push(desc);
                    }
                }
            }
            6 => {
                if spaces.len() < 6 {
                    let child = p.fork(root).unwrap();
                    let copy = spaces[which].1.clone();
                    // `clone` copies the `Rc`s: private data stays a value
                    // (copied on write by `make_mut`), shared data one
                    // object.
                    spaces.push((child, copy));
                    compare_all(&p, &spaces);
                }
            }
            _ => {
                if spaces.len() > 1 {
                    let (root, _) = spaces.remove(which);
                    p.destroy(root);
                } else {
                    // The last one: start over with an empty space.
                    p.destroy(root);
                    spaces[0] = (p.new_space().unwrap(), Space::new());
                }
            }
        }
        tlb.flush(p.take_stale());
        // Memory goes back to the host only after the flush; what was
        // given back reads as garbage until handed out again (and then
        // zeroed), which the comparisons below would see.
        if rng.below(4) == 0 {
            trimmed += p.trim(rng.below(8), rng.below(4)).ram;
        }
        let live: Vec<u64> = spaces.iter().map(|(root, _)| *root).collect();
        tlb.check(&p, &live);
        check(&p, &live);
        for (root, space) in &spaces {
            compare_range(&p, *root, space, addr, len);
            if let Some((addr, len)) = also {
                compare_range(&p, *root, space, addr, len);
            }
        }
        if step % 200 == 0 {
            compare_all(&p, &spaces);
        }
    }
    compare_all(&p, &spaces);
    eprintln!(
        "seed {seed}: {steps} steps (map, unmap, protect, write, read, touch, fork, \
         destroy: {counts:?}), {} spaces at the end, {} KiB of memory, {} tables, \
         {trimmed} host pages given back",
        spaces.len(),
        p.ram_in_use() / 1024,
        p.tables_in_use() / PAGE
    );
    for (root, _) in spaces.drain(..) {
        p.destroy(root);
    }
    check(&p, &[]);
    assert_eq!((p.ram_in_use(), p.tables_in_use()), (0, 0));
    assert!(trimmed > 0, "nothing was given back");
}

#[test]
fn random_operations_match_the_model() {
    for seed in [0x9e37_79b9_7f4a_7c15, 0x2545_f491_4f6c_dd1d, 7] {
        model_run(seed, 4000);
    }
}

/// The same operations with pools so small that they run out all the
/// time: whatever fails, the invariants hold after every step, and once
/// every space is destroyed every frame and table is back in its pool.
#[test]
fn random_operations_with_exhausted_pools_leak_nothing() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut p = phys(24, 48);
    let mut roots = vec![p.new_space().unwrap()];
    let (mut ok, mut failed) = (0, 0);
    for _ in 0..20000 {
        let which = rng.below(roots.len() as u64) as usize;
        let root = roots[which];
        let (addr, len) = random_range(&mut rng);
        let result = match rng.below(9) {
            0 => p
                .map(root, addr, len, random_prot(&mut rng), rng.below(3) == 0)
                .map(drop),
            1 => p.unmap(root, addr, len),
            2 => p.protect(root, addr, len, random_prot(&mut rng)),
            3 | 4 => p.write(root, addr, &[0x5a; 100]),
            5 | 6 => match p.demand(root, addr + rng.below(len), Access::Write) {
                Demand::NoMemory => Err(MmuError::NoMemory),
                _ => Ok(()),
            },
            7 => {
                if roots.len() < 8 {
                    p.fork(root).map(|child| roots.push(child))
                } else {
                    Ok(())
                }
            }
            _ => {
                if roots.len() > 1 {
                    p.destroy(roots.remove(which));
                }
                Ok(())
            }
        };
        match result {
            Ok(()) => ok += 1,
            Err(_) => failed += 1,
        }
        if rng.below(8) == 0 {
            p.take_stale();
            p.trim(rng.below(2), rng.below(2));
        }
        check(&p, &roots);
    }
    eprintln!("{ok} operations succeeded, {failed} failed");
    assert!(failed > 1000, "the pools did not run out often: {failed}");
    for root in roots {
        p.destroy(root);
    }
    check(&p, &[]);
    assert_eq!((p.ram_in_use(), p.tables_in_use()), (0, 0));
}
