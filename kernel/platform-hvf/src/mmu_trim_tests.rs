//! Memory given back to the host ([`Phys::trim`]), with a backing that
//! records what was given back and taken back.

use super::*;

/// App memory as a `Vec`, recording give-backs and take-backs. What was
/// given back holds garbage until taken back, and taking back anything
/// else is refused.
struct Counting {
    bytes: Vec<u8>,
    out: Vec<bool>,
    given: Vec<(usize, usize)>,
    taken: Vec<(usize, usize)>,
}

impl Counting {
    fn new(pages: usize) -> Counting {
        let len = pages * PAGE as usize;
        Counting {
            bytes: vec![0; len],
            out: vec![false; len.div_ceil(HOST_PAGE)],
            given: Vec::new(),
            taken: Vec::new(),
        }
    }
}

impl Backing for Counting {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn sync_icache(&mut self, _offset: usize, _len: usize) {}

    fn give_back(&mut self, offset: usize, len: usize) {
        assert!(offset.is_multiple_of(HOST_PAGE) && len.is_multiple_of(HOST_PAGE));
        for page in offset / HOST_PAGE..(offset + len) / HOST_PAGE {
            assert!(
                !std::mem::replace(&mut self.out[page], true),
                "given back twice"
            );
        }
        self.bytes[offset..offset + len].fill(0xdb);
        self.given.push((offset, len));
    }

    fn take_back(&mut self, offset: usize, len: usize) {
        assert!(offset.is_multiple_of(HOST_PAGE) && len.is_multiple_of(HOST_PAGE));
        for page in offset / HOST_PAGE..(offset + len) / HOST_PAGE {
            assert!(
                std::mem::replace(&mut self.out[page], false),
                "not given back"
            );
        }
        self.taken.push((offset, len));
    }

    fn write_at(&mut self, offset: usize, data: &[u8]) {
        assert!(!self.out[offset / HOST_PAGE], "written while given back");
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }

    fn zero_at(&mut self, offset: usize, len: usize) {
        assert!(!self.out[offset / HOST_PAGE], "zeroed while given back");
        self.bytes[offset..offset + len].fill(0);
    }
}

fn phys(tables: usize, ram: usize) -> Phys<Counting> {
    Phys::new(Counting::new(tables), Counting::new(ram))
}

const BASE: u64 = 0x40_0000;

/// Maps and touches `pages` pages at [`BASE`] with a byte each.
fn touch(p: &mut Phys<Counting>, root: u64, pages: u64) {
    p.map(root, BASE, pages * PAGE, Prot::RW, false).unwrap();
    for i in 0..pages {
        p.write(root, BASE + i * PAGE, &[0x5a]).unwrap();
    }
}

#[test]
fn whole_free_host_pages_go_back_in_runs_and_come_back_zero() {
    let mut p = phys(64, 256);
    let root = p.new_space().unwrap();
    touch(&mut p, root, 64);
    p.unmap(root, BASE, 64 * PAGE).unwrap();
    assert_eq!(p.whole_free(), 64 * PAGE);
    // The sixteen host pages are adjacent: one call.
    let trimmed = p.trim(0, 64);
    assert_eq!(trimmed.ram, 16);
    assert_eq!(trimmed.calls, 1);
    assert_eq!(p.ram.given, [(0, 16 * HOST_PAGE)]);
    assert_eq!(p.whole_free(), 0);
    assert_eq!(p.trimmed().ram, 16);
    // Nothing more to give back.
    assert_eq!(p.trim(0, 64).ram, 0);
    // Touched again: the host pages are taken back, adjacent ones in one
    // call, before the first frame of them is used, and every page reads
    // zero (the backing holds garbage).
    p.map(root, BASE, 64 * PAGE, Prot::RW, false).unwrap();
    for i in 0..64 {
        let mut buf = [1u8; 16];
        p.read(root, BASE + i * PAGE, &mut buf).unwrap();
        assert_eq!(buf, [0; 16], "before the touch");
        assert_eq!(
            p.demand(root, BASE + i * PAGE, Access::Read),
            Demand::Filled
        );
        p.read(root, BASE + i * PAGE + 4000, &mut buf[..8]).unwrap();
        assert_eq!(buf[..8], [0; 8], "page {i}");
    }
    assert_eq!(p.ram.taken, [(0, 16 * HOST_PAGE)]);
    p.ram_pool.check();
    p.destroy(root);
}

#[test]
fn a_host_page_with_a_frame_in_use_stays() {
    let mut p = phys(64, 64);
    let root = p.new_space().unwrap();
    touch(&mut p, root, 8);
    // Frees all but the first page of each host page.
    for i in 0..8 {
        if i % 4 != 0 {
            p.unmap(root, BASE + i * PAGE, PAGE).unwrap();
        }
    }
    assert_eq!(p.whole_free(), 0);
    assert_eq!(p.trim(0, 64).ram, 0);
    // New frames fill those host pages, not new ones.
    p.map(root, BASE + PAGE, PAGE, Prot::RW, false).unwrap();
    p.write(root, BASE + PAGE, &[1]).unwrap();
    let frame = p.lookup(root, BASE + PAGE) & pte::ADDR_MASK;
    assert!(frame < RAM_IPA + 2 * HOST_PAGE as u64, "{frame:#x}");
    p.ram_pool.check();
}

/// Memory goes back once it has been free for the age given, the
/// oldest first, beyond the reserve; what was freed later waits, and
/// `trim_aged` says until when.
#[test]
fn trim_aged_gives_back_what_has_been_free_long_enough() {
    let early = 100 * CHUNK;
    let late = (RAM_KEEP + 50) * CHUNK;
    let mut p = phys(64, (early + late + 64) as usize);
    let root = p.new_space().unwrap();
    p.map(root, BASE, (early + late) * PAGE, Prot::RW, false)
        .unwrap();
    for i in 0..early + late {
        p.write(root, BASE + i * PAGE, &[1]).unwrap();
    }
    p.set_clock(1000);
    p.unmap(root, BASE, early * PAGE).unwrap();
    p.set_clock(1500);
    p.unmap(root, BASE + early * PAGE, late * PAGE).unwrap();
    // Nothing is old enough yet: due when the first ones are.
    let (trimmed, due) = p.trim_aged(1050, 100);
    assert_eq!(trimmed.ram, 0);
    assert_eq!(due, Some(1100));
    // The early ones are; the late ones (more than the reserve) wait.
    let (trimmed, due) = p.trim_aged(1100, 100);
    assert_eq!(trimmed.ram, early / CHUNK);
    assert_eq!(due, Some(1600));
    assert_eq!(p.ram.given, [(0, (early / CHUNK) as usize * HOST_PAGE)]);
    // Then the late ones, down to the reserve, which stays.
    let (trimmed, due) = p.trim_aged(5000, 100);
    assert_eq!(trimmed.ram, late / CHUNK - RAM_KEEP);
    assert_eq!(due, None);
    assert_eq!(p.ram_pool.whole_count, RAM_KEEP);
    // The reserve is used first; then the host pages given back.
    touch(&mut p, root, RAM_KEEP * CHUNK + 1);
    assert_eq!(p.ram.taken.len(), 1);
    p.ram_pool.check();
}

#[test]
fn page_tables_go_back_too() {
    let mut p = phys(256, 64);
    let root = p.new_space().unwrap();
    // A page every 2 MiB: one last-level table each, freed with its page.
    for i in 0..64 {
        let va = BASE + i * (2 << 20);
        p.map(root, va, PAGE, Prot::RW, false).unwrap();
    }
    let tables = p.tables_in_use();
    p.unmap(root, BASE, 128 << 20).unwrap();
    assert!(p.tables_in_use() < tables);
    let trimmed = p.trim(0, 0);
    assert!(trimmed.tables >= 15, "{trimmed:?}");
    // New tables from host pages given back are zero.
    for i in 0..64 {
        let va = BASE + i * (2 << 20);
        p.map(root, va, PAGE, Prot::RW, false).unwrap();
        p.write(root, va, &[7]).unwrap();
    }
    for i in 0..64 {
        let mut b = [0u8];
        p.read(root, BASE + i * (2 << 20), &mut b).unwrap();
        assert_eq!(b, [7]);
        let mut z = [1u8; 8];
        p.read(root, BASE + i * (2 << 20) + PAGE, &mut z)
            .unwrap_err();
    }
    p.table_pool.check();
    p.destroy(root);
    p.trim(0, 0);
    assert_eq!(p.tables_in_use(), 0);
}

/// A template that gave memory back saves only what is in use; a clone of
/// it hands out zeroed frames, also from host pages the template had
/// given back.
#[test]
fn a_template_after_trim_saves_only_what_is_used() {
    let (tables, ram) = (64usize, 64usize);
    let mut t = phys(tables, ram);
    t.shim_space().unwrap();
    let root = t.new_space().unwrap();
    touch(&mut t, root, 32);
    t.unmap(root, BASE + 16 * PAGE, 16 * PAGE).unwrap();
    assert_eq!(t.trim(0, 0).ram, 4);
    let mut saved_tables = vec![0u8; tables * PAGE as usize];
    let mut saved_ram = vec![0u8; ram * PAGE as usize];
    let mut w = hellovm_core::snap::Writer::new();
    let stats = t.save(&mut saved_tables, &mut saved_ram, &mut w);
    assert_eq!((stats.frames, stats.stored), (16, 16));
    assert!(
        saved_ram[16 * PAGE as usize..].iter().all(|&b| b == 0),
        "a free frame was saved"
    );
    saved_tables.truncate(stats.tables as usize);
    let meta = w.into_inner();
    let mut r = hellovm_core::snap::Reader::new(&meta);
    let saved = <Saved as hellovm_core::snap::Snap>::get(&mut r).unwrap();

    struct VecOrigin(Vec<u8>);
    impl Origin for VecOrigin {
        fn read_frame(&self, index: usize, out: &mut [u8]) {
            let off = index * PAGE as usize;
            out.copy_from_slice(&self.0[off..off + PAGE as usize]);
        }
    }
    let mut c = phys(tables, ram);
    c.shim_space().unwrap();
    // The clone's memory where the template had frames holds garbage, as
    // if it had been used (beyond that it is untouched: zero).
    c.ram.bytes[..32 * PAGE as usize].fill(0xee);
    c.load(
        saved,
        &saved_tables,
        Box::new(VecOrigin(saved_ram)),
        &[root],
    )
    .unwrap();
    // Its free memory was never touched: as good as given back.
    for (pool, backing) in [(&c.ram_pool, &mut c.ram), (&c.table_pool, &mut c.tables)] {
        for k in 0..pool.chunks() {
            backing.out[k as usize] = pool.returned(k);
        }
    }
    c.ram_pool.check();
    c.table_pool.check();
    assert_eq!(c.ram_in_use(), 16 * PAGE);
    c.map(root, BASE + 16 * PAGE, 48 * PAGE, Prot::RW, false)
        .unwrap();
    for i in 16..64 {
        let va = BASE + i * PAGE;
        assert_eq!(c.demand(root, va, Access::Read), Demand::Filled);
        let mut buf = [1u8; 32];
        c.read(root, va + 2000, &mut buf).unwrap();
        assert_eq!(buf, [0; 32], "page {i}");
    }
    let mut b = [0u8];
    c.read(root, BASE, &mut b).unwrap();
    assert_eq!(b, [0x5a]);
}
