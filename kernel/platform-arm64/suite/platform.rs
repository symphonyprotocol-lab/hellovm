// The shared suite of the arm64 VM platforms, included by
// `platform-hvf/tests/hvf.rs` and `platform-kvm/tests/kvm.rs`, which
// define `TestPlatform`, `TestConfig`, `NAME` (the platform's name in
// messages), `VCPUS_VAR` and `GUESTS_VAR` (the environment variables
// that set the vCPU count and the guest image) first.
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use hellovm_core::{ExitStatus, Kernel};
use hellovm_host::{CaptureHost, ImageDir};

/// One VM per process: the tests take turns.
static VM: Mutex<()> = Mutex::new(());

/// `VCPUS_VAR` (`HELLOVM_HVF_VCPUS`, `HELLOVM_KVM_VCPUS`), if set, overrides the vCPU count of a config that
/// leaves it to the default, so that the whole suite runs with one vCPU
/// or with several.
fn with_test_vcpus(mut config: TestConfig) -> TestConfig {
    if config.vcpus == 0 {
        if let Some(n) = std::env::var(VCPUS_VAR)
            .ok()
            .and_then(|n| n.parse().ok())
        {
            config.vcpus = n;
        }
    }
    config
}

fn platform() -> Option<(MutexGuard<'static, ()>, TestPlatform)> {
    platform_with(TestConfig::default())
}

fn platform_with(config: TestConfig) -> Option<(MutexGuard<'static, ()>, TestPlatform)> {
    let guard = VM.lock().unwrap_or_else(|e| e.into_inner());
    // Empty when this Mac lacks the tools to build them (see
    // `test-guest/build.rs`).
    if hellovm_test_guest::HELLO.is_empty() {
        if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") {
            panic!("HELLOVM_REQUIRE_E2E=1 but the test guests were not built");
        }
        eprintln!("SKIPPING: the test guests were not built on this Mac");
        return None;
    }
    match TestPlatform::new(with_test_vcpus(config)) {
        Ok(p) => Some((guard, p)),
        Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
            panic!("HELLOVM_REQUIRE_E2E=1 but the {NAME} platform is unavailable: {err}")
        }
        Err(err) => {
            eprintln!("SKIPPING: the {NAME} platform is unavailable: {err}");
            None
        }
    }
}

fn image(files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hellovm-{}-{}-{:?}",
        NAME.to_lowercase(),
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in files {
        std::fs::copy(src, dir.join(name)).unwrap();
    }
    dir
}

fn run(p: &mut TestPlatform, root: &PathBuf, argv: &[&str]) -> (ExitStatus, CaptureHost) {
    let host = CaptureHost::new(Some(ImageDir::open(root).unwrap()));
    let mut kernel = Kernel::new(host);
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
    kernel.exec(p, &argv[0], &argv, &[]).expect("exec");
    let status = kernel.run(p).expect("run");
    (status, kernel.into_host())
}

#[test]
fn hello_world() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("hello", hellovm_test_guest::HELLO)]);
    let (status, host) = run(&mut p, &root, &["/hello"]);
    assert_eq!(
        String::from_utf8_lossy(&host.stdout),
        hellovm_test_guest::HELLO_STDOUT
    );
    assert_eq!(
        String::from_utf8_lossy(&host.stderr),
        hellovm_test_guest::HELLO_STDERR
    );
    assert_eq!(
        status,
        ExitStatus::Exited(hellovm_test_guest::HELLO_EXIT_CODE)
    );
}

#[test]
fn a_fault_kills_with_sigsegv() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("segv", hellovm_test_guest::SEGV)]);
    let (status, _) = run(&mut p, &root, &["/segv"]);
    assert_eq!(status, ExitStatus::Signaled(11));
}

#[test]
fn odd_syscall_registers_do_not_hurt_the_kernel() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("odd", hellovm_test_guest::ODD_REGS)]);
    let (status, host) = run(&mut p, &root, &["/odd"]);
    assert_eq!(String::from_utf8_lossy(&host.stdout), "survived\n");
    assert_eq!(status, ExitStatus::Signaled(11));
}

#[test]
fn getpid_loop() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("loop", hellovm_test_guest::GETPID_LOOP)]);
    let (status, _) = run(&mut p, &root, &["/loop", "1000"]);
    assert_eq!(status, ExitStatus::Exited(0));
}

/// What language runtimes do with address space: a 64 GiB `PROT_NONE`
/// reservation used in the middle, then pages mapped and unmapped at
/// thousands of places. Neither may use up the page tables.
#[test]
fn address_space_is_reserved_and_reused_without_using_up_tables() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("reserve", hellovm_test_guest::RESERVE)]);
    let (status, _) = run(&mut p, &root, &["/reserve"]);
    assert_eq!(status, ExitStatus::Exited(0));
}

/// `ic ivau` and `dc cvau` over read-only code that has no memory yet are
/// not writes (`__clear_cache`).
#[test]
fn cache_maintenance_over_untouched_code_is_no_fault() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("icache", hellovm_test_guest::ICACHE)]);
    let (status, _) = run(&mut p, &root, &["/icache"]);
    assert_eq!(status, ExitStatus::Exited(0));
}

/// `PSTATE.DIT` is the app's: a system call does not clear it.
#[test]
fn dit_survives_a_system_call() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let root = image(&[("dit", hellovm_test_guest::DIT)]);
    let (status, _) = run(&mut p, &root, &["/dit"]);
    assert_eq!(status, ExitStatus::Exited(0));
}

// Raw tasks: code written straight into a task's memory, driven through
// the `Platform` trait without the kernel core.

use hellovm_core::platform::{
    Context, Event, Fault, Platform, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap,
};
use std::time::{Duration, Instant};

const PAGE: u64 = 4096;
const CODE: u64 = 0x10_000;
const DATA: u64 = 0x20_000;
const STACK_TOP: u64 = 0x40_000;
const SHIM_VA: u64 = 0xffff_0000_0000_0000;

const SVC: u32 = 0xd400_0001;
const B_SELF: u32 = 0x1400_0000;
const NOP: u32 = 0xd503_201f;
/// `ldr x0, [x1]`, `str x0, [x1]`, `br x1`.
const LDR_X0_X1: u32 = 0xf940_0020;
const STR_X0_X1: u32 = 0xf900_0020;
const BR_X1: u32 = 0xd61f_0020;
const LDR_X0_SP: u32 = 0xf940_03e0;

/// A task running `code` from its start, with a stack.
fn spawn_code(p: &mut TestPlatform, code: &[u32]) -> TaskKey {
    let t = new_code(p, code);
    p.resume(
        t,
        Resume::Start {
            entry: CODE,
            stack: STACK_TOP,
        },
    )
    .unwrap();
    t
}

/// A stopped task with `code` and a stack mapped, never run.
fn new_code(p: &mut TestPlatform, code: &[u32]) -> TaskKey {
    let t = p.spawn().unwrap();
    p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
    let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
    p.write(t, CODE, &bytes).unwrap();
    p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
        .unwrap();
    p.map(t, DATA, PAGE, Prot::RW, Sharing::Private).unwrap();
    p.map(
        t,
        STACK_TOP - 4 * PAGE,
        4 * PAGE,
        Prot::RW,
        Sharing::Private,
    )
    .unwrap();
    t
}

/// Sets a stopped task's context and resumes it.
fn run_with(p: &mut TestPlatform, t: TaskKey, ctx: &hellovm_core::platform::Aarch64Context) {
    p.set_context(t, &Context::Aarch64(Box::new(ctx.clone())))
        .unwrap();
    p.resume(t, Resume::Continue).unwrap();
}

fn next(p: &mut TestPlatform) -> Event {
    p.wait(Some(Duration::from_secs(10)))
        .expect("wait")
        .expect("an event within 10 s")
}

fn aarch64(c: Context) -> Box<hellovm_core::platform::Aarch64Context> {
    match c {
        Context::Aarch64(c) => c,
        Context::X86_64(_) => panic!("x86_64 context"),
    }
}

fn fault(signal: u32, code: i32, addr: Option<u64>) -> Trap {
    Trap::Fault(Fault { signal, code, addr })
}

/// `movz x1, #imm16, lsl #shift`.
fn movz_x1(imm: u16, shift: u32) -> u32 {
    0xd280_0001 | ((shift / 16) << 21) | (u32::from(imm) << 5)
}

#[test]
fn unmapped_memory_is_a_fault_event() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Loads from 0x4000_0000 (where the page tables are in guest-physical
    // memory; nothing is mapped there virtually), then makes a syscall.
    let t = spawn_code(&mut p, &[movz_x1(0x4000, 16), LDR_X0_X1, SVC]);
    let ev = next(&mut p);
    assert_eq!(ev.task, t);
    assert_eq!(ev.trap, fault(11, 1, Some(0x4000_0000)));
    let mut ctx = aarch64(p.context(t).unwrap());
    assert_eq!(ctx.pc, CODE + 4, "stopped at the load");
    // Resuming unchanged faults again; skipping the load goes on.
    p.resume(t, Resume::Continue).unwrap();
    assert_eq!(next(&mut p).trap, fault(11, 1, Some(0x4000_0000)));
    ctx.pc += 4;
    p.set_context(t, &Context::Aarch64(ctx)).unwrap();
    p.resume(t, Resume::Continue).unwrap();
    assert!(matches!(next(&mut p).trap, Trap::Syscall(_)));
}

#[test]
fn protection_changes_reach_the_app() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // x1 = DATA; store, syscall, store, syscall, load, syscall.
    let t = spawn_code(
        &mut p,
        &[
            movz_x1((DATA >> 16) as u16, 16),
            STR_X0_X1,
            SVC,
            STR_X0_X1,
            SVC,
            LDR_X0_X1,
            SVC,
        ],
    );
    let ev = next(&mut p);
    assert!(matches!(ev.trap, Trap::Syscall(_)), "{ev:?}");
    // The store went through a writable mapping the TLB may still hold.
    p.protect(t, DATA, PAGE, Prot::READ).unwrap();
    p.resume(t, Resume::Return(0)).unwrap();
    assert_eq!(next(&mut p).trap, fault(11, 2, Some(DATA)));
    p.protect(t, DATA, PAGE, Prot::RW).unwrap();
    p.resume(t, Resume::Continue).unwrap();
    assert!(matches!(next(&mut p).trap, Trap::Syscall(_)));
    let mut word = [0u8; 8];
    p.read(t, DATA, &mut word).unwrap();
    assert_eq!(u64::from_le_bytes(word), 0, "x0 was 0 at the stores");
    p.unmap(t, DATA, PAGE).unwrap();
    p.resume(t, Resume::Return(0)).unwrap();
    assert_eq!(next(&mut p).trap, fault(11, 1, Some(DATA)));
}

#[test]
fn el1_state_and_the_shim_are_out_of_reach() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let sigill = |pc| fault(4, 1, Some(pc));
    let shim_hi = movz_x1(0xffff, 48);
    // (name, code, expected trap given the faulting pc)
    type Expect = Box<dyn Fn(u64) -> Trap>;
    let cases: Vec<(&str, Vec<u32>, Expect)> = vec![
        ("mrs sctlr_el1", vec![0xd538_1000], Box::new(sigill)),
        ("msr vbar_el1", vec![0xd518_c000], Box::new(sigill)),
        ("msr ttbr0_el1", vec![0xd518_2000], Box::new(sigill)),
        ("mrs tpidr_el1", vec![0xd538_d080], Box::new(sigill)),
        ("tlbi vmalle1", vec![0xd508_871f], Box::new(sigill)),
        ("hvc #0", vec![0xd400_0002], Box::new(sigill)),
        ("eret", vec![0xd69f_03e0], Box::new(sigill)),
        ("mrs cntv_ctl_el0", vec![0xd53b_e320], Box::new(sigill)),
        ("msr daifclr", vec![0xd503_4fff], Box::new(sigill)),
        (
            "load from the shim",
            vec![shim_hi, LDR_X0_X1],
            Box::new(|_| fault(11, 2, Some(SHIM_VA))),
        ),
        (
            "store to the shim",
            vec![shim_hi, STR_X0_X1],
            Box::new(|_| fault(11, 2, Some(SHIM_VA))),
        ),
        (
            "jump into the vectors",
            vec![shim_hi, 0x9110_0021 /* add x1, x1, #0x400 */, BR_X1],
            Box::new(|_| fault(11, 2, Some(SHIM_VA + 0x400))),
        ),
        (
            "jump into the flush routine",
            vec![shim_hi, 0x9120_0021 /* add x1, x1, #0x800 */, BR_X1],
            Box::new(|_| fault(11, 2, Some(SHIM_VA + 0x800))),
        ),
        (
            "load from app memory's guest-physical address",
            vec![movz_x1(1, 32), LDR_X0_X1],
            Box::new(|_| fault(11, 1, Some(0x1_0000_0000))),
        ),
    ];
    for (name, mut code, expected) in cases {
        code.push(SVC);
        let t = spawn_code(&mut p, &code);
        let ev = next(&mut p);
        let pc = aarch64(p.context(t).unwrap()).pc;
        let want = expected(pc);
        let want = match want {
            // A jump faults at its target.
            Trap::Fault(f) if name.starts_with("jump") => {
                assert_eq!(Some(pc), f.addr, "{name}");
                Trap::Fault(f)
            }
            other => {
                assert_eq!(pc, CODE + 4 * (code.len() as u64 - 2), "{name}");
                other
            }
        };
        assert_eq!(ev.trap, want, "{name}");
        p.kill(t).unwrap();
    }
    // The pages after the shim: on KVM the vCPUs' register frames (at
    // +0x1000, one page each) and the exit page (+0x10_0000), mapped for
    // EL1 only; on HVF nothing. Either way EL0 gets SIGSEGV at the address
    // (SEGV_ACCERR where they are mapped, SEGV_MAPERR where not).
    for (name, offset, store) in [
        ("load from vCPU 0's frame", 0x1000u64, false),
        ("store to vCPU 0's frame", 0x1000, true),
        ("store to vCPU 1's frame", 0x2000, true),
        ("load from the exit page", 0x10_0000, false),
        ("store to the exit page", 0x10_0000, true),
    ] {
        let code = vec![
            shim_hi,
            add_x1_pages(offset),
            if store { STR_X0_X1 } else { LDR_X0_X1 },
            SVC,
        ];
        let t = spawn_code(&mut p, &code);
        match next(&mut p).trap {
            Trap::Fault(f) => {
                assert_eq!((f.signal, f.addr), (11, Some(SHIM_VA + offset)), "{name}");
                assert!(matches!(f.code, 1 | 2), "{name}: {f:?}");
            }
            other => panic!("{name}: {other:?}"),
        }
        p.kill(t).unwrap();
    }
}

/// `add x1, x1, #(offset >> 12), lsl #12`: adds `offset` (a multiple of
/// 4 KiB below 16 MiB) to `x1`.
fn add_x1_pages(offset: u64) -> u32 {
    // add x1, x1, #(offset >> 12), lsl #12
    0x9140_0021 | (((offset >> 12) as u32) & 0xfff) << 10
}

fn patterned(seed: u64) -> Box<hellovm_core::platform::Aarch64Context> {
    let mut c = aarch64(Context::zeroed(hellovm_core::arch::Arch::Aarch64));
    for (i, x) in c.x.iter_mut().enumerate() {
        *x = seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(i as u32)
            ^ i as u64;
    }
    for (i, v) in c.v.iter_mut().enumerate() {
        *v = (u128::from(seed) << 64 | i as u128).wrapping_mul(0x1234_5678_9abc_def1_0fed_cba9);
    }
    c.sp = STACK_TOP - 16 * (seed % 8 + 1);
    c.pc = CODE;
    c.pstate = 0xa000_0000; // N and C
    c.fpcr = 0x0200_0000; // DN
    c.fpsr = 0x1f; // the cumulative exception flags
    c.tpidr = seed ^ 0x5555_aaaa_5555_aaaa;
    c
}

#[test]
fn registers_survive_exits() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Two tasks, each a loop of syscalls, interleaved on the one vCPU.
    let code = [SVC, NOP, SVC, B_SELF];
    let a = new_code(&mut p, &code);
    let b = new_code(&mut p, &code);
    for (t, seed) in [(a, 1), (b, 2)] {
        let ctx = patterned(seed);
        p.set_context(t, &Context::Aarch64(ctx.clone())).unwrap();
        assert_eq!(aarch64(p.context(t).unwrap()), ctx, "before running");
        p.resume(t, Resume::Continue).unwrap();
    }
    // Both run to their first syscall (the order is the platform's).
    let mut stopped = Vec::new();
    for _ in 0..2 {
        let ev = next(&mut p);
        stopped.push(ev.task);
        let seed = if ev.task == a { 1 } else { 2 };
        let want = patterned(seed);
        assert_eq!(
            ev.trap,
            Trap::Syscall(SyscallTrap {
                nr: want.x[8],
                args: [want.x[0], want.x[1], want.x[2], want.x[3], want.x[4], want.x[5]],
            })
        );
        let mut want = want;
        want.pc = CODE + 4;
        assert_eq!(
            aarch64(p.context(ev.task).unwrap()),
            want,
            "at the first syscall"
        );
    }
    stopped.sort();
    assert_eq!(stopped, [a, b]);
    // Return a value to each; at the next syscall only x0 changed.
    p.resume(a, Resume::Return(-38)).unwrap();
    p.resume(b, Resume::Return(77)).unwrap();
    for _ in 0..2 {
        let ev = next(&mut p);
        let (seed, ret) = if ev.task == a { (1, -38i64) } else { (2, 77) };
        let mut want = patterned(seed);
        want.pc = CODE + 12;
        want.x[0] = ret as u64;
        assert_eq!(
            aarch64(p.context(ev.task).unwrap()),
            want,
            "at the second syscall"
        );
    }
    // A context set while the task's registers are in the vCPU.
    let mut ctx = patterned(3);
    ctx.pc = CODE;
    run_with(&mut p, b, &ctx);
    assert_eq!(next(&mut p).task, b);
    ctx.pc = CODE + 4;
    assert_eq!(aarch64(p.context(b).unwrap()), ctx);
}

#[test]
fn odd_register_values_at_exits() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Every privileged PSTATE bit set: the app still runs at EL0 (it
    // cannot read SCTLR_EL1).
    let t = new_code(&mut p, &[0xd538_1000, SVC]);
    let mut ctx = patterned(9);
    ctx.pstate = u64::MAX;
    run_with(&mut p, t, &ctx);
    assert_eq!(next(&mut p).trap, fault(4, 1, Some(CODE)));
    // Of all that, the app keeps the condition flags and DIT.
    assert_eq!(aarch64(p.context(t).unwrap()).pstate, 0xf100_0000);
    p.kill(t).unwrap();

    // Odd program counters and stack pointers.
    let cases: [(u64, u64, Trap); 6] = [
        (CODE + 2, STACK_TOP, fault(7, 1, Some(CODE + 2))),
        (0, STACK_TOP, fault(11, 1, Some(0))),
        (SHIM_VA, STACK_TOP, fault(11, 2, Some(SHIM_VA))),
        (!3, STACK_TOP, fault(11, 1, Some(!3))),
        (
            0x0001_0000_0000_0000,
            STACK_TOP,
            fault(11, 1, Some(1 << 48)),
        ),
        // `ldr x0, [sp]` with a misaligned stack pointer.
        (CODE + 4, STACK_TOP - 9, fault(7, 1, Some(STACK_TOP - 9))),
    ];
    for (pc, sp, want) in cases {
        let t = new_code(&mut p, &[NOP, LDR_X0_SP, SVC]);
        let mut ctx = patterned(4);
        ctx.pc = pc;
        ctx.sp = sp;
        run_with(&mut p, t, &ctx);
        assert_eq!(next(&mut p).trap, want, "pc {pc:#x} sp {sp:#x}");
        p.kill(t).unwrap();
    }

    // Random everything: the platform reports something, never fails.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut rand = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..300 {
        let t = new_code(&mut p, &[SVC, LDR_X0_X1, STR_X0_X1, BR_X1]);
        let mut ctx = patterned(rand());
        for r in ctx.x.iter_mut() {
            *r = rand();
        }
        ctx.sp = rand();
        ctx.pstate = rand();
        ctx.fpcr = rand() as u32;
        ctx.fpsr = rand() as u32;
        ctx.tpidr = rand();
        ctx.pc = match rand() % 4 {
            0 => CODE + 4 * (rand() % 4),
            1 => rand(),
            2 => rand() & 0x0000_ffff_ffff_fffc,
            _ => SHIM_VA + (rand() & 0xffc),
        };
        run_with(&mut p, t, &ctx);
        let ev = p.wait(Some(Duration::from_secs(5))).unwrap();
        match ev.map(|e| e.trap) {
            Some(Trap::Syscall(_) | Trap::Fault(_)) | None => {}
            other => panic!("unexpected {other:?}"),
        }
        p.kill(t).unwrap();
    }
}

#[test]
fn timeouts_wakers_interrupts_and_the_killer() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let t = spawn_code(&mut p, &[B_SELF]);
    // A spinning app does not keep `wait` past its timeout.
    let start = Instant::now();
    assert_eq!(p.wait(Some(Duration::from_millis(50))).unwrap(), None);
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(45), "{took:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    // A waker on another thread ends a wait with no timeout.
    let waker = p.waker();
    let start = Instant::now();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        waker.wake();
    });
    assert_eq!(p.wait(None).unwrap(), None);
    assert!(start.elapsed() >= Duration::from_millis(45));
    thread.join().unwrap();
    // A wake-up before the wait is not lost.
    p.waker().wake();
    assert_eq!(p.wait(None).unwrap(), None);
    // Interrupt: the task stops with its context intact.
    p.interrupt(t).unwrap();
    let ev = next(&mut p);
    assert_eq!((ev.task, ev.trap), (t, Trap::Interrupted));
    assert_eq!(aarch64(p.context(t).unwrap()).pc, CODE);
    p.resume(t, Resume::Continue).unwrap();
    // The killer ends every task from another thread.
    let killer = p.killer();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        killer.kill();
    });
    let mut gone = None;
    for _ in 0..10 {
        if let Some(ev) = p.wait(None).unwrap() {
            gone = Some(ev);
            break;
        }
    }
    assert_eq!(
        gone,
        Some(Event {
            task: t,
            trap: Trap::Gone
        })
    );
    thread.join().unwrap();
    assert!(p.context(t).is_err(), "the task is gone");
}

/// The cost of one system call round trip (README, "The HVF platform",
/// and "The KVM platform": `-p hellovm-platform-kvm --test kvm`).
/// Run with `cargo test --release -p hellovm-platform-hvf --test hvf --
/// --ignored --nocapture syscall_round_trip`.
#[test]
#[ignore = "benchmark"]
fn syscall_round_trip() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    const N: u64 = 1_000_000;
    // The platform alone: `svc; b .-4`, each trap answered at once.
    let t = spawn_code(&mut p, &[SVC, 0x17ff_ffff]);
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..N {
            let ev = p.wait(None).unwrap().unwrap();
            debug_assert!(matches!(ev.trap, Trap::Syscall(_)));
            p.resume(t, Resume::Return(0)).unwrap();
        }
        best = best.min(start.elapsed());
    }
    eprintln!(
        "platform only: {:.0} ns per syscall round trip (best of 5 x {N})",
        best.as_nanos() as f64 / N as f64
    );
    p.kill(t).unwrap();
    drop(p);
    drop(_guard);

    // Through the kernel core: `getpid` in a loop.
    let root = image(&[("loop", hellovm_test_guest::GETPID_LOOP)]);
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let Some((_guard, mut p)) = platform() else {
            return;
        };
        let start = Instant::now();
        let (status, _) = run(&mut p, &root, &["/loop", &N.to_string()]);
        best = best.min(start.elapsed());
        assert_eq!(status, ExitStatus::Exited(0));
    }
    eprintln!(
        "getpid through the kernel: {:.0} ns per call (best of 5 runs of {N}, \
         including VM setup and loading)",
        best.as_nanos() as f64 / N as f64
    );
}

#[test]
fn stopping_from_outside_keeps_the_apps_progress() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Counts x0 up to x1, then makes a syscall. Restarting from the top
    // after a stop would never finish.
    let t = new_code(
        &mut p,
        &[
            0xd280_0000, // movz x0, #0
            0x9100_0400, // add x0, x0, #1
            0xeb01_001f, // cmp x0, x1
            0x54ff_ffc1, // b.ne .-8
            SVC,
        ],
    );
    let mut ctx = patterned(5);
    ctx.pc = CODE;
    ctx.x[1] = 200_000_000;
    run_with(&mut p, t, &ctx);
    // Short timeouts, and a waker firing all the time from another thread.
    let waker = p.waker();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let kicker = {
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                waker.wake();
                std::thread::sleep(Duration::from_micros(300));
            }
        })
    };
    let start = Instant::now();
    let mut stops = 0;
    let ev = loop {
        match p.wait(Some(Duration::from_millis(1))).unwrap() {
            Some(ev) => break ev,
            None => stops += 1,
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no progress");
    };
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    kicker.join().unwrap();
    assert!(matches!(ev.trap, Trap::Syscall(_)), "{ev:?}");
    assert!(stops > 10, "only {stops} stops");
    let ctx = aarch64(p.context(t).unwrap());
    assert_eq!(ctx.x[0], 200_000_000);
    assert_eq!(ctx.pc, CODE + 20);
}

// Copies of address spaces through the trait, and what the TLB may hold.

/// `str x2, [x1]`.
const STR_X2_X1: u32 = 0xf900_0022;
/// `b .-16`.
const B_BACK_16: u32 = 0x17ff_fffc;

fn syscall_arg0(trap: Trap) -> u64 {
    match trap {
        Trap::Syscall(SyscallTrap { args, .. }) => args[0],
        other => panic!("not a syscall: {other:?}"),
    }
}

/// Runs `t` to its next trap; every other task is stopped.
fn step(p: &mut TestPlatform, t: TaskKey, resume: Resume) -> Trap {
    p.resume(t, resume).unwrap();
    let ev = next(p);
    assert_eq!(ev.task, t);
    ev.trap
}

/// After `fork`, each process writes its own copy of a page whose
/// writable entry the parent's TLB held before the fork, and both keep
/// reading their own copy across many switches between their address
/// spaces (each has its ASID, so a switch flushes nothing).
#[test]
fn fork_keeps_address_spaces_apart_in_the_tlb() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Loop: x0 = [x1]; svc; [x1] = x2; svc.
    let code = [LDR_X0_X1, SVC, STR_X2_X1, SVC, B_BACK_16];
    let t = new_code(&mut p, &code);
    p.write(t, DATA, &0x1111u64.to_le_bytes()).unwrap();
    let mut ctx = patterned(1);
    ctx.pc = CODE;
    ctx.x[1] = DATA;
    ctx.x[2] = 0xaaaa;
    run_with(&mut p, t, &ctx);
    // The parent read the page: its TLB may hold it, writable.
    assert_eq!(syscall_arg0(next(&mut p).trap), 0x1111);
    let c = p.clone_task(t, false).unwrap();
    let mut child = aarch64(p.context(c).unwrap());
    assert_eq!(
        child.pc,
        CODE + 8,
        "the child continues where the parent was"
    );
    child.x[2] = 0xbbbb;
    p.set_context(c, &Context::Aarch64(child)).unwrap();
    // The parent stores through what its TLB may still hold: the store
    // must fault and copy, not reach the frame the child shares.
    assert!(matches!(
        step(&mut p, t, Resume::Return(0)),
        Trap::Syscall(_)
    ));
    let mut word = [0u8; 8];
    p.read(c, DATA, &mut word).unwrap();
    assert_eq!(u64::from_le_bytes(word), 0x1111, "the child's copy");
    assert!(matches!(
        step(&mut p, c, Resume::Continue),
        Trap::Syscall(_)
    ));
    let before = p.flushes();
    for round in 0..200 {
        for (task, want) in [(t, 0xaaaa), (c, 0xbbbb)] {
            let trap = step(&mut p, task, Resume::Return(0));
            assert_eq!(syscall_arg0(trap), want, "round {round}");
            assert!(matches!(
                step(&mut p, task, Resume::Return(0)),
                Trap::Syscall(_)
            ));
        }
    }
    let after = p.flushes();
    // Each other vCPU may still have had the fork's invalidations to do
    // when it first ran one of them; switching flushed nothing.
    let extra = (after.all + after.page) - (before.all + before.page);
    assert!(
        extra < p.vcpus() as u64,
        "switching address spaces flushed: {before:?} then {after:?}"
    );
    for (task, want) in [(t, 0xaaaau64), (c, 0xbbbb)] {
        p.read(task, DATA, &mut word).unwrap();
        assert_eq!(u64::from_le_bytes(word), want);
    }
    // The core writes into the parent's page, which is its alone now.
    p.write(t, DATA, &0xccccu64.to_le_bytes()).unwrap();
    assert_eq!(syscall_arg0(step(&mut p, t, Resume::Return(0))), 0xcccc);
    assert_eq!(syscall_arg0(step(&mut p, c, Resume::Return(0))), 0xbbbb);
    p.kill(c).unwrap();
    p.kill(t).unwrap();
    assert_eq!(p.memory_in_use().0, 0);
}

/// A frame freed with its address space and handed out again is never
/// reached through what the TLB held for the space that is gone, even
/// when the new space gets the same ASID and maps the same address.
#[test]
fn a_freed_frame_is_not_reached_through_a_stale_entry() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    for round in 0..20u64 {
        // X: reads its page (its TLB holds it) and stops.
        let x = new_code(&mut p, &[LDR_X0_X1, SVC]);
        let secret = 0x5ec7_e700 + round;
        p.write(x, DATA, &secret.to_le_bytes()).unwrap();
        let mut ctx = patterned(round);
        ctx.pc = CODE;
        ctx.x[1] = DATA;
        run_with(&mut p, x, &ctx);
        assert_eq!(syscall_arg0(next(&mut p).trap), secret);
        p.kill(x).unwrap();
        // Y: its first frame is X's page's (frames are reused last freed
        // first), at another address, holding something else; its own
        // page at X's address is new and must read as zero.
        let y = p.spawn().unwrap();
        const OTHER: u64 = 0x30_000;
        p.map(y, OTHER, PAGE, Prot::RW, Sharing::Private).unwrap();
        p.write(y, OTHER, &0xfeedu64.to_le_bytes()).unwrap();
        p.map(y, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        let bytes: Vec<u8> = [LDR_X0_X1, SVC]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(y, CODE, &bytes).unwrap();
        p.protect(y, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        p.map(y, DATA, PAGE, Prot::RW, Sharing::Private).unwrap();
        run_with(&mut p, y, &ctx);
        assert_eq!(syscall_arg0(next(&mut p).trap), 0, "round {round}");
        p.kill(y).unwrap();
    }
}

/// Shared memory across `clone` without a copy (threads, `vfork`): a
/// store by one task is what the other loads.
#[test]
fn clone_with_shared_memory_shares_it() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    let code = [LDR_X0_X1, SVC, STR_X2_X1, SVC, B_BACK_16];
    let t = new_code(&mut p, &code);
    let mut ctx = patterned(3);
    ctx.pc = CODE;
    ctx.x[1] = DATA;
    ctx.x[2] = 0x7777;
    run_with(&mut p, t, &ctx);
    assert_eq!(syscall_arg0(next(&mut p).trap), 0);
    let c = p.clone_task(t, true).unwrap();
    let mut child = aarch64(p.context(c).unwrap());
    child.x[2] = 0x8888;
    p.set_context(c, &Context::Aarch64(child)).unwrap();
    assert!(matches!(
        step(&mut p, t, Resume::Return(0)),
        Trap::Syscall(_)
    ));
    // The child loads what the parent stored, then stores its own.
    assert!(matches!(
        step(&mut p, c, Resume::Continue),
        Trap::Syscall(_)
    ));
    assert_eq!(syscall_arg0(step(&mut p, c, Resume::Return(0))), 0x8888);
    assert_eq!(syscall_arg0(step(&mut p, t, Resume::Return(0))), 0x8888);
    // The address space goes with its last task.
    p.kill(t).unwrap();
    let mut word = [0u8; 8];
    p.read(c, DATA, &mut word).unwrap();
    assert_eq!(u64::from_le_bytes(word), 0x8888);
    p.kill(c).unwrap();
    assert_eq!(p.memory_in_use().0, 0);
}

/// Preemption: tasks that never trap share the vCPU, and one that makes
/// system calls is not kept waiting behind them.
#[test]
fn spinning_tasks_do_not_starve_others() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Counts in x0 forever, with a syscall every 2^20 increments.
    let counter = [
        0x9100_0400, // add x0, x0, #1
        0xf240_4c1f, // tst x0, #0xfffff
        0x54ff_ffc1, // b.ne .-8
        SVC,
        B_BACK_16,
    ];
    let spinner = spawn_code(&mut p, &[B_SELF]);
    let a = spawn_code(&mut p, &counter);
    let b = spawn_code(&mut p, &counter);
    let caller = spawn_code(&mut p, &[SVC, 0x17ff_ffff]);
    let mut counts = std::collections::HashMap::new();
    let start = Instant::now();
    let mut caller_calls = 0;
    while start.elapsed() < Duration::from_millis(500) {
        let ev = next(&mut p);
        assert!(matches!(ev.trap, Trap::Syscall(_)), "{ev:?}");
        *counts.entry(ev.task).or_insert(0u64) += 1;
        if ev.task == caller {
            caller_calls += 1;
        }
        p.resume(ev.task, Resume::Continue).unwrap();
    }
    let (na, nb) = (
        counts.get(&a).copied().unwrap_or(0),
        counts.get(&b).copied().unwrap_or(0),
    );
    eprintln!("in 500 ms: counters {na} and {nb} rounds, the caller {caller_calls} calls");
    assert!(na > 0 && nb > 0, "a counter did not run: {na} {nb}");
    assert!(na * 3 > nb && nb * 3 > na, "unfair: {na} {nb}");
    // The caller runs whenever it is runnable: it gets far more round
    // trips than one per slice of each spinner (which would be ~33).
    assert!(caller_calls > 1000, "the caller made {caller_calls} calls");
    for t in [spinner, a, b, caller] {
        p.kill(t).unwrap();
    }
}

/// The core writes into a copy-on-write page whose read-only entry the
/// app's TLB holds: the page gets a copy, and the app's next load reads
/// the copy, not the frame it shared (the page's entry was invalidated).
#[test]
fn the_cores_write_to_a_shared_page_reaches_only_its_process() {
    let Some((_guard, mut p)) = platform() else {
        return;
    };
    // Loop: x0 = [x1]; svc.
    let t = new_code(&mut p, &[LDR_X0_X1, SVC, 0x17ff_fffe /* b .-8 */]);
    p.write(t, DATA, &1u64.to_le_bytes()).unwrap();
    let mut ctx = patterned(4);
    ctx.pc = CODE;
    ctx.x[1] = DATA;
    run_with(&mut p, t, &ctx);
    assert_eq!(syscall_arg0(next(&mut p).trap), 1);
    for value in 2..50u64 {
        let c = p.clone_task(t, false).unwrap();
        // The child loads the shared frame: its TLB may hold it.
        assert_eq!(syscall_arg0(step(&mut p, c, Resume::Continue)), value - 1);
        // The core writes the child's page: a copy, at once.
        p.write(c, DATA, &value.to_le_bytes()).unwrap();
        assert_eq!(syscall_arg0(step(&mut p, c, Resume::Return(0))), value);
        assert_eq!(syscall_arg0(step(&mut p, t, Resume::Return(0))), value - 1);
        // The parent's page is its alone again: written in place.
        p.write(t, DATA, &value.to_le_bytes()).unwrap();
        assert_eq!(syscall_arg0(step(&mut p, t, Resume::Return(0))), value);
        p.kill(c).unwrap();
    }
    p.kill(t).unwrap();
}
