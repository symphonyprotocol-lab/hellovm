//! A probe of what `madvise` does to app memory that is mapped into the
//! VM (P1g). Runs only with `HELLOVM_P1G_PROBE` set to the advice to try
//! (`reusable` or `free`): one VM, one vCPU, stopped at a system call
//! while one 16 KiB host page of app memory is advised. Each step is
//! logged to `target/p1g/probe.log` and synced before it runs.

use std::io::Write as _;

use super::*;
use crate::layout::pte;
use crate::sys::HOST_PAGE;

const CODE: u64 = 0x10_000;
const DATA: u64 = 0x20_000;
const DATA_PAGES: u64 = 8;

struct Log(std::fs::File);

impl Log {
    fn open() -> Log {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/p1g");
        std::fs::create_dir_all(dir).unwrap();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{dir}/probe.log"))
            .unwrap();
        Log(file)
    }

    /// Records `step` on disk before it is taken.
    fn step(&mut self, step: &str) {
        writeln!(self.0, "{step}").unwrap();
        self.0.sync_all().unwrap();
        // SAFETY: no arguments.
        unsafe { libc::sync() };
        eprintln!("probe: {step}");
    }
}

fn footprint() -> (u64, u64) {
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: our own pid and a buffer of the flavor's type.
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            (&mut info as *mut libc::rusage_info_v4).cast(),
        )
    };
    assert_eq!(rc, 0);
    (info.ri_phys_footprint, info.ri_resident_size)
}

fn resident(ptr: *const u8) -> bool {
    let mut vec = [0 as libc::c_char; 1];
    // SAFETY: one host page of our own mapping.
    let rc = unsafe { libc::mincore(ptr.cast(), HOST_PAGE, vec.as_mut_ptr()) };
    assert_eq!(rc, 0);
    vec[0] & libc::MINCORE_INCORE as libc::c_char != 0
}

fn word(trap: Trap) -> u64 {
    match trap {
        Trap::Syscall(SyscallTrap { args, .. }) => args[0],
        other => panic!("not a syscall: {other:?}"),
    }
}

#[test]
fn madvise_of_mapped_app_memory() {
    let Ok(advice) = std::env::var("HELLOVM_P1G_PROBE") else {
        eprintln!("SKIPPING: HELLOVM_P1G_PROBE not set");
        return;
    };
    let advice = match advice.as_str() {
        "reusable" => libc::MADV_FREE_REUSABLE,
        "free" => libc::MADV_FREE,
        other => panic!("unknown advice {other}"),
    };
    let mut log = Log::open();
    log.step(&format!("start, advice {advice}"));
    let _guard = super::vm_tests::VM
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut p = HvfPlatform::new(HvfConfig {
        vcpus: 1,
        ..HvfConfig::default()
    })
    .unwrap();
    let t = p.spawn().unwrap();
    p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
    // Loop: x0 = [x1]; svc; [x1] = x2; svc.
    let code: Vec<u8> = [
        0xf940_0020u32,
        0xd400_0001,
        0xf900_0022,
        0xd400_0001,
        0x17ff_fffc,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    p.write(t, CODE, &code).unwrap();
    p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
        .unwrap();
    p.map(t, DATA, DATA_PAGES * PAGE, Prot::RW, Sharing::Private)
        .unwrap();
    for i in 0..DATA_PAGES {
        p.write(t, DATA + i * PAGE, &[1]).unwrap();
    }
    // A host page all of whose four frames are data pages.
    let root = {
        let sched = p.lock();
        sched.spaces[&sched.tasks[&t].space].root
    };
    let (host_off, va) = {
        let phys = p.smp.phys();
        let frames: Vec<(u64, u64)> = (0..DATA_PAGES)
            .map(|i| {
                let va = DATA + i * PAGE;
                (phys.lookup(root, va) & pte::ADDR_MASK, va)
            })
            .collect();
        let per = HOST_PAGE as u64 / PAGE;
        let (frame, va) = *frames
            .iter()
            .find(|(f, _)| {
                (f - layout::RAM_IPA).is_multiple_of(HOST_PAGE as u64)
                    && (0..per).all(|k| frames.iter().any(|(g, _)| *g == f + k * PAGE))
            })
            .expect("a host page of data frames");
        ((frame - layout::RAM_IPA) as usize, va)
    };
    let host = unsafe { p.smp.phys().ram_backing().ptr().add(host_off) };
    log.step(&format!(
        "host page at offset {host_off:#x}, guest va {va:#x}"
    ));

    let pattern = |b: u8| vec![b; HOST_PAGE];
    let fill = |p: &mut HvfPlatform, b: u8| {
        p.smp
            .phys()
            .ram_backing_mut_for_probe()
            .write_at(host_off, &pattern(b));
    };
    let host_word = |p: &HvfPlatform| {
        let mut buf = [0u8; 8];
        p.smp.phys().ram_backing().read_at(host_off, &mut buf);
        u64::from_le_bytes(buf)
    };
    let host_all = |p: &HvfPlatform| {
        let mut buf = vec![0u8; HOST_PAGE];
        p.smp.phys().ram_backing().read_at(host_off, &mut buf);
        buf
    };

    // A: the guest reads what the host wrote (stage 2 now maps the page).
    fill(&mut p, 0xaa);
    let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
        unreachable!()
    };
    ctx.pc = CODE;
    ctx.x[1] = va;
    ctx.x[2] = 0x7777_7777_7777_7777;
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    log.step("A: guest reads 0xaa");
    p.resume(t, Resume::Continue).unwrap();
    let ev = p.wait(None).unwrap().unwrap();
    let a = word(ev.trap);
    log.step(&format!(
        "A: guest read {a:#x}; resident {}",
        resident(host)
    ));
    assert_eq!(a, 0xaaaa_aaaa_aaaa_aaaa);

    // B: madvise with the vCPU stopped at the svc.
    let before = footprint();
    log.step(&format!(
        "B: madvise {advice} of one host page, vCPU stopped; footprint/resident before {before:?}"
    ));
    // SAFETY: one host page of the app pool, no other use of it now.
    let rc = unsafe { libc::madvise(host.cast(), HOST_PAGE, advice) };
    let after = footprint();
    log.step(&format!(
        "B: rc {rc} errno {}; footprint/resident after {after:?}; resident {}",
        std::io::Error::last_os_error(),
        resident(host)
    ));
    assert_eq!(rc, 0);

    // C: the guest writes x2 (it is at the first svc: the next store is
    // its write), then reads again; host and guest must agree.
    log.step("C: guest writes 0x7777..., host reads");
    p.resume(t, Resume::Continue).unwrap();
    p.wait(None).unwrap().unwrap();
    let h = host_word(&p);
    log.step(&format!(
        "C: host read {h:#x}; footprint/resident {:?}",
        footprint()
    ));
    assert_eq!(
        h, 0x7777_7777_7777_7777,
        "the host does not see the guest's write"
    );
    let rest = host_all(&p);
    let others: std::collections::BTreeSet<u8> = rest[8..].iter().copied().collect();
    log.step(&format!("C: the rest of the host page holds {others:?}"));

    // D: reuse, the host writes 0x55, the guest reads it.
    if advice == libc::MADV_FREE_REUSABLE {
        log.step("D: madvise MADV_FREE_REUSE");
        // SAFETY: as above.
        let rc = unsafe { libc::madvise(host.cast(), HOST_PAGE, libc::MADV_FREE_REUSE) };
        log.step(&format!("D: rc {rc}; footprint/resident {:?}", footprint()));
        assert_eq!(rc, 0);
    }
    fill(&mut p, 0x55);
    log.step("D: guest reads after the host wrote 0x55");
    p.resume(t, Resume::Continue).unwrap();
    let d = word(p.wait(None).unwrap().unwrap().trap);
    log.step(&format!(
        "D: guest read {d:#x}; footprint/resident {:?}",
        footprint()
    ));
    assert_eq!(
        d, 0x5555_5555_5555_5555,
        "the guest does not see the host's write"
    );

    // E: madvise again, the host does not touch it; the guest reads.
    // What the guest sees must be what the host then sees.
    p.resume(t, Resume::Continue).unwrap();
    p.wait(None).unwrap().unwrap(); // its store of x2
    fill(&mut p, 0x33);
    log.step(&format!(
        "E: madvise {advice} again, then the guest reads first"
    ));
    // SAFETY: as above.
    let rc = unsafe { libc::madvise(host.cast(), HOST_PAGE, advice) };
    assert_eq!(rc, 0);
    p.resume(t, Resume::Continue).unwrap();
    let e = word(p.wait(None).unwrap().unwrap().trap);
    let h = host_word(&p);
    log.step(&format!(
        "E: guest read {e:#x}, host reads {h:#x}; resident {}",
        resident(host)
    ));
    assert_eq!(e, h, "guest and host disagree");
    p.kill(t).unwrap();
    log.step("done");
}
