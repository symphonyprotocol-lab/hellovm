//! Hooks and shared test bodies for the backends' tests (the `testing`
//! feature, which only their dev-dependencies turn on).
//!
//! The functions at the end are tests of the shared platform that need a
//! real VM: each backend's tests call them with a function that makes its
//! platform, or returns `None` (and has said why) when the hypervisor is
//! not available.

use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm_core::arch::Arch;
use hellovm_core::platform::{
    Context, Platform, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap,
};

use super::{State, VmConfig, VmPlatform};
use crate::backend::Hypervisor;
use crate::layout::PAGE;
use crate::mmu::Phys;

impl<H: Hypervisor> VmPlatform<H> {
    /// vCPU 0, the event loop's.
    pub fn vcpu0(&mut self) -> &mut H::Vcpu {
        &mut self.runner.vcpu
    }

    /// The pools and the page tables.
    pub fn phys_for_tests(&self) -> MutexGuard<'_, Phys<H::Mem>> {
        self.smp.phys()
    }

    /// The root of the tables of `key`'s address space.
    pub fn root_of(&self, key: TaskKey) -> u64 {
        let sched = self.lock();
        sched.spaces[&sched.tasks[&key].space].root
    }

    /// Gives back to the host all the free memory the pools hold.
    pub fn trim_all_for_tests(&self) {
        self.trim_all()
    }
}

/// How long free memory stays before it goes back while the sandbox is busy.
pub const GIVE_BACK_AGE: Duration = super::GIVE_BACK_AGE;
pub use crate::mmu::{RAM_KEEP, TABLES_KEEP};

const CODE: u64 = 0x10_000;
const DATA: u64 = 0x20_000;

fn word(trap: Trap) -> u64 {
    match trap {
        Trap::Syscall(SyscallTrap { args, .. }) => args[0],
        other => panic!("not a syscall: {other:?}"),
    }
}

/// The core answers a system call of a task whose registers are in
/// another vCPU, and reads the registers before that vCPU has run the
/// task again (as it does to deliver a signal that came in between):
/// they have the result, and so does the app when it runs.
pub fn registers_read_before_the_task_runs_again_have_the_result<H: Hypervisor>(
    make: impl FnOnce(VmConfig) -> Option<VmPlatform<H>>,
) {
    let Some(mut p) = make(VmConfig {
        vcpus: 2,
        ..VmConfig::default()
    }) else {
        return;
    };
    let t = p.spawn().unwrap();
    p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
    // Loop: svc.
    let code: Vec<u8> = [0xd400_0001u32, 0x17ff_ffff]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    p.write(t, CODE, &code).unwrap();
    p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
        .unwrap();
    let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
        unreachable!()
    };
    ctx.pc = CODE;
    ctx.x[0] = 0x1111;
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    // Runnable without a call of `wait`, so that vCPU 1 runs it, not
    // the event loop's.
    // (A first `wait` starts the vCPU threads of a backend that defers
    // them.)
    assert!(p.wait(Some(Duration::ZERO)).unwrap().is_none());
    {
        let mut sched = p.lock();
        sched.tasks.get_mut(&t).unwrap().state = State::Runnable;
        p.smp.wake(1);
    }
    let start = Instant::now();
    while p.lock().events.is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "vCPU 1 ran nothing"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x1111);
    assert_eq!(p.lock().tasks[&t].loaded, Some(1));
    p.set_x0(t, 0x7777).unwrap();
    let Context::Aarch64(ctx) = p.context(t).unwrap() else {
        unreachable!()
    };
    assert_eq!(ctx.x[0], 0x7777, "the result is in the registers read");
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    p.resume(t, Resume::Continue).unwrap();
    assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x7777);
    p.kill(t).unwrap();
}

/// With ASIDs used up, new spaces share ASID 0, and switching between
/// two of them flushes: each process still reads its own page.
pub fn spaces_beyond_the_asids_share_one_and_flush<H: Hypervisor>(
    make: impl FnOnce(VmConfig) -> Option<VmPlatform<H>>,
) {
    let Some(mut p) = make(VmConfig {
        vcpus: 1,
        ..VmConfig::default()
    }) else {
        return;
    };
    // ASID 1 only; every other space gets 0.
    p.lock().asid_limit = 2;
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
    p.map(t, DATA, PAGE, Prot::RW, Sharing::Private).unwrap();
    let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
        unreachable!()
    };
    ctx.pc = CODE;
    ctx.x[1] = DATA;
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    p.resume(t, Resume::Continue).unwrap();
    let ev = p.wait(None).unwrap().unwrap();
    assert_eq!(word(ev.trap), 0);
    let mut tasks = vec![t];
    for _ in 0..3 {
        tasks.push(p.clone_task(t, false).unwrap());
    }
    let asids: Vec<u16> = tasks
        .iter()
        .map(|t| {
            let sched = p.lock();
            sched.spaces[&sched.tasks[t].space].asid
        })
        .collect();
    assert_eq!(asids, [1, 0, 0, 0]);
    // Each stores its own value, then all read theirs, in turn, many
    // times.
    for (i, &t) in tasks.iter().enumerate() {
        let mut ctx = match p.context(t).unwrap() {
            Context::Aarch64(c) => c,
            Context::X86_64(_) => unreachable!(),
        };
        ctx.x[2] = 0x100 + i as u64;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    }
    let step = |p: &mut VmPlatform<H>, t: TaskKey| {
        p.resume(t, Resume::Continue).unwrap();
        let ev = p.wait(None).unwrap().unwrap();
        assert_eq!(ev.task, t);
        ev.trap
    };
    for &t in &tasks {
        step(&mut p, t);
    }
    for round in 0..50 {
        for (i, &t) in tasks.iter().enumerate() {
            assert_eq!(word(step(&mut p, t)), 0x100 + i as u64, "round {round}");
            step(&mut p, t);
        }
    }
    for t in tasks {
        p.kill(t).unwrap();
    }
}

/// The timer can end a slice while the vCPU is in an exception vector,
/// on its way out with an exception of the app. When that exception
/// needs nothing from the core (here a page that gets its memory on
/// first touch), the run still ends there; before, the app went on
/// with no timer and kept the vCPU until something else stopped it.
pub fn a_slice_that_ends_in_a_vector_still_ends<H: Hypervisor>(
    make: impl FnOnce(VmConfig) -> Option<VmPlatform<H>>,
) {
    let Some(mut p) = make(VmConfig {
        vcpus: 1,
        ..VmConfig::default()
    }) else {
        return;
    };
    const BASE: u64 = 0x1000_0000;
    const LEN: u64 = 64 << 20;
    let t = p.spawn().unwrap();
    p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
    // Touch every page: str x2, [x1]; add x1, x1, #4096; cmp x1, x3;
    // b.ne back; then spin: b .
    let code: Vec<u8> = [
        0xf900_0022u32,
        0x9140_0421,
        0xeb03_003f,
        0x54ff_ffa1,
        0x1400_0000,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    p.write(t, CODE, &code).unwrap();
    p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
        .unwrap();
    p.map(t, BASE, LEN, Prot::RW, Sharing::Private).unwrap();
    let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
        unreachable!()
    };
    ctx.pc = CODE;
    ctx.x[1] = BASE;
    ctx.x[3] = BASE + LEN;
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    p.resume(t, Resume::Continue).unwrap();
    // A waker, should a run not end by itself.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let (waker, done) = (p.waker(), Arc::clone(&done));
        std::thread::spawn(move || {
            let lock = Mutex::new(());
            let cv = Condvar::new();
            let mut guard = lock.lock().unwrap();
            while !done.load(SeqCst) {
                guard = cv
                    .wait_timeout(guard, Duration::from_millis(500))
                    .unwrap()
                    .0;
                waker.wake();
            }
        })
    };
    let start = Instant::now();
    let mut slowest = Duration::ZERO;
    // For a second, and until the app touched every page (which takes
    // longer under nested virtualization), at most 30 s.
    while start.elapsed() < Duration::from_secs(1)
        || (p.memory_in_use().0 < LEN && start.elapsed() < Duration::from_secs(30))
    {
        let before = Instant::now();
        assert!(p.wait(Some(Duration::from_micros(20))).unwrap().is_none());
        slowest = slowest.max(before.elapsed());
    }
    done.store(true, SeqCst);
    watchdog.join().unwrap();
    assert!(p.memory_in_use().0 >= LEN, "the app touched every page");
    assert!(
        slowest < Duration::from_millis(100),
        "a wait of 20 us took {slowest:?}"
    );
    p.kill(t).unwrap();
}
