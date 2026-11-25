//! Tests of the HVF platform that need its internals: the shared
//! platform's tests that need a VM (`hellovm_platform_arm64::testing`),
//! the HVF backend's own, the cost of an exit, and memory given back to
//! macOS.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use hellovm_core::arch::Arch;
use hellovm_core::platform::{
    Context, Platform, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap,
};
use hellovm_platform_arm64::layout::{self, FLUSH_PAGE_OFFSET, PAGE, SHIM_VA};
use hellovm_platform_arm64::{testing, Stopped};

use crate::sys::{sysreg, HV_REG_CPSR, HV_REG_PC};
use crate::{HvfConfig, HvfPlatform};

#[path = "madvise_probe.rs"]
mod madvise_probe;

mod breakdown {
    use super::*;

    #[test]
    #[ignore = "benchmark"]
    fn exit_cost_breakdown() {
        let _guard = crate::tests::vm_tests::VM
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, 0x10000, PAGE, Prot::ALL, Sharing::Private)
            .unwrap();
        let code: Vec<u8> = [0xd400_0001u32, 0x17ff_ffff]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(t, 0x10000, &code).unwrap();
        p.resume(
            t,
            Resume::Start {
                entry: 0x10000,
                stack: 0,
            },
        )
        .unwrap();
        p.wait(None).unwrap().unwrap();
        const N: u32 = 1_000_000;
        // Bare: set PC, run, nothing read.
        let start = Instant::now();
        for _ in 0..N {
            p.vcpu0().vcpu.set_reg(HV_REG_PC, 0x10000).unwrap();
            p.vcpu0().vcpu.set_reg(HV_REG_CPSR, 0).unwrap();
            p.vcpu0().vcpu.run().unwrap();
        }
        let bare = start.elapsed() / N;
        let start = Instant::now();
        let mut sum = 0u64;
        for _ in 0..N {
            sum = sum.wrapping_add(p.vcpu0().vcpu.reg(3).unwrap());
        }
        let get = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            sum = sum.wrapping_add(p.vcpu0().vcpu.sys_reg(sysreg::ELR_EL1).unwrap());
        }
        let sys = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            p.vcpu0().vcpu.set_reg(0, sum).unwrap();
        }
        let set = start.elapsed() / N;
        eprintln!("bare exit {bare:?}, get_reg {get:?}, get_sys_reg {sys:?}, set_reg {set:?}");
    }
}

/// Memory given back to the host, with the VM running (P1g).
mod give_back_tests {
    use super::*;

    const CODE: u64 = 0x10_000;
    const REGION: u64 = 0x1000_0000;
    const LEN: u64 = 64 << 20;
    /// Each spinner's page.
    const SPIN_DATA: u64 = 0x20_000;

    fn footprint() -> u64 {
        // SAFETY: zeroed plain-old-data; the call fills it.
        let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: our own pid and a buffer of the flavor's type.
        let rc = unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                (&mut info as *mut libc::rusage_info_v2).cast(),
            )
        };
        assert_eq!(rc, 0);
        info.ri_phys_footprint
    }

    fn word(trap: Trap) -> u64 {
        match trap {
            Trap::Syscall(SyscallTrap { args, .. }) => args[0],
            other => panic!("not a syscall: {other:?}"),
        }
    }

    fn resident_kib() -> String {
        // SAFETY: as in `footprint`.
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: as in `footprint`.
        unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V4,
                (&mut info as *mut libc::rusage_info_v4).cast(),
            )
        };
        format!(
            "{} KiB, wired {} KiB",
            info.ri_resident_size >> 10,
            info.ri_wired_size >> 10
        )
    }

    /// Lets the platform run (`t` is stopped) until what the pools keep
    /// went back, for 5 s at most: what they keep then, and how long
    /// it took.
    fn given_back(p: &mut HvfPlatform, t: TaskKey) -> (u64, Duration) {
        let timer = Instant::now();
        loop {
            let (kept, _) = p.memory_kept();
            if kept <= 512 << 10 || timer.elapsed() > Duration::from_secs(5) {
                return (kept, timer.elapsed());
            }
            if let Some(ev) = p.wait(Some(Duration::from_millis(30))).unwrap() {
                assert_ne!(ev.task, t, "the program is stopped");
                p.resume(ev.task, Resume::Continue).unwrap();
            }
        }
    }

    /// A program touches 64 MiB; the host unmaps it, and it goes back
    /// within `GIVE_BACK_AGE` (here, the program being stopped, once the
    /// event loop is idle); the footprint falls back. Mapped again, all of
    /// it reads zero although the host pages it gets were the ones given
    /// back (their old bytes may still be there). Five rounds; with more
    /// than one vCPU, three threads of the same process write their own
    /// pages without a system call meanwhile, on the other vCPUs.
    fn run(vcpus: usize) {
        let _guard = crate::tests::vm_tests::VM
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // touch: [x1] = x3 every page up to x2; svc; then x0 = OR of the
        // first and last word of every page from x5 up to x2; svc.
        // spin: [x6] = x3++ for ever.
        let code: Vec<u8> = [
            0xf900_0023u32,
            0x9140_0421,
            0xeb02_003f,
            0x54ff_ffa3,
            0xd400_0001,
            0xd280_0000,
            0xf940_00a4,
            0xaa04_0000,
            0xf947_fca4,
            0xaa04_0000,
            0x9140_04a5,
            0xeb02_00bf,
            0x54ff_ff43,
            0xd400_0001,
            0x1400_0000,
            0xf900_00c3,
            0x9100_0463,
            0x17ff_fffe,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        p.map(t, SPIN_DATA, 4 * PAGE, Prot::RW, Sharing::Private)
            .unwrap();
        let mut spinners = Vec::new();
        for i in 1..vcpus.min(4) as u64 {
            let s = p.clone_task(t, true).unwrap();
            let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
                unreachable!()
            };
            ctx.pc = CODE + 0x3c;
            ctx.x[6] = SPIN_DATA + i * PAGE;
            p.set_context(s, &Context::Aarch64(ctx)).unwrap();
            p.resume(s, Resume::Continue).unwrap();
            spinners.push(s);
        }
        let start = footprint();
        let next = |p: &mut HvfPlatform| loop {
            let ev = p.wait(None).unwrap().unwrap();
            if ev.task == t {
                return word(ev.trap);
            }
            // A spinner's slice: on with it.
            p.resume(ev.task, Resume::Continue).unwrap();
        };
        for round in 0..5u64 {
            p.map(t, REGION, LEN, Prot::RW, Sharing::Private).unwrap();
            let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
                unreachable!()
            };
            ctx.pc = CODE;
            ctx.x[1] = REGION;
            ctx.x[2] = REGION + LEN;
            ctx.x[3] = 0xa5a5_0000 + round + 1;
            ctx.x[5] = REGION;
            p.set_context(t, &Context::Aarch64(ctx)).unwrap();
            let untouched = footprint();
            p.resume(t, Resume::Continue).unwrap();
            next(&mut p);
            let touched = footprint();
            // The footprints are this test process's, in which other
            // tests allocate meanwhile: they are reported, and what is
            // checked is what the platform counts (the command-line tests
            // check the footprint, from outside the process).
            assert!(
                p.memory_in_use().0 >= LEN,
                "round {round}: {} in use after the touch",
                p.memory_in_use().0
            );
            // Freed, then mapped again with nothing in it.
            let (_, before) = p.memory_kept();
            let timer = Instant::now();
            p.unmap(t, REGION, LEN).unwrap();
            let unmap = timer.elapsed();
            // Nothing goes back at once; it does within
            // `GIVE_BACK_AGE` (here, with the program stopped, once the
            // event loop is idle).
            let (kept, back_after) = given_back(&mut p, t);
            let (_, after) = p.memory_kept();
            assert!(kept <= 512 << 10, "round {round}: {kept} kept");
            let freed = footprint();
            assert!(
                after.ram - before.ram >= LEN / 16384 - 64,
                "round {round}: trimmed {before:?} -> {after:?}"
            );
            p.map(t, REGION, LEN, Prot::RW, Sharing::Private).unwrap();
            let timer = Instant::now();
            p.resume(t, Resume::Continue).unwrap();
            assert_eq!(next(&mut p), 0, "round {round}: old bytes in new memory");
            let reread = timer.elapsed();
            p.unmap(t, REGION, LEN).unwrap();
            given_back(&mut p, t);
            eprintln!(
                "{vcpus} vCPUs, round {round}: footprint {} MiB at the start, {} before the \
                 touch, {} touched, {} freed (resident {}); unmap of 64 MiB {unmap:?}, back after {back_after:?} \
                 ({} host pages in {} calls, {} µs), \
                 64 MiB read again {reread:?}",
                start >> 20,
                untouched >> 20,
                touched >> 20,
                freed >> 20,
                resident_kib(),
                after.ram - before.ram,
                after.calls - before.calls,
                (after.nanos - before.nanos) / 1000
            );
        }
        for s in spinners {
            p.kill(s).unwrap();
        }
        p.kill(t).unwrap();
        // What the pools kept goes back once the loop is idle.
        for _ in 0..100 {
            if p.wait(Some(Duration::from_millis(100))).unwrap().is_none() {
                break;
            }
        }
        assert_eq!(p.memory_kept().0, 0);
        assert_eq!(p.memory_in_use().0, 0);
    }

    /// On the only vCPU a program spins without a system call, so the
    /// event loop is never idle: what was freed goes back once it has been
    /// free for `GIVE_BACK_AGE` (but the reserve), the run being ended for
    /// it.
    #[test]
    fn freed_memory_goes_back_while_a_program_spins() {
        let _guard = crate::tests::vm_tests::VM
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // spin: [x6] = x3++ for ever.
        let code: Vec<u8> = [0xf900_00c3u32, 0x9100_0463, 0x17ff_fffe]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        p.map(t, SPIN_DATA, PAGE, Prot::RW, Sharing::Private)
            .unwrap();
        p.map(t, REGION, LEN, Prot::RW, Sharing::Private).unwrap();
        for i in 0..LEN / PAGE {
            p.write(t, REGION + i * PAGE, &[1]).unwrap();
        }
        // From before the memory is freed: it cannot go back sooner than
        // `GIVE_BACK_AGE` after this.
        let timer = Instant::now();
        p.unmap(t, REGION, LEN).unwrap();
        assert!(p.memory_kept().0 >= LEN - (1 << 20));
        let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        ctx.pc = CODE;
        ctx.x[6] = SPIN_DATA;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        p.resume(t, Resume::Continue).unwrap();
        let mut kept = p.memory_kept().0;
        while kept > (testing::RAM_KEEP + testing::TABLES_KEEP) * 16384
            && timer.elapsed() < Duration::from_secs(2)
        {
            // The program never stops: each wait ends with its deadline.
            assert!(p.wait(Some(Duration::from_millis(20))).unwrap().is_none());
            kept = p.memory_kept().0;
        }
        let took = timer.elapsed();
        eprintln!("spinning: {kept} bytes kept after {took:?}");
        assert!(
            kept <= (testing::RAM_KEEP + testing::TABLES_KEEP) * 16384,
            "{kept} kept after {took:?}"
        );
        assert!(took >= testing::GIVE_BACK_AGE, "{took:?}");
        p.kill(t).unwrap();
    }

    #[test]
    fn freed_memory_goes_back_on_one_vcpu() {
        run(1);
    }

    #[test]
    fn freed_memory_goes_back_with_other_vcpus_running() {
        run(4);
    }
}

/// What needs the platform's insides: spaces beyond the ASIDs there are.
pub(crate) mod vm_tests {
    use super::*;

    /// One VM per process: the tests of this crate that make one take
    /// turns.
    pub(crate) static VM: Mutex<()> = Mutex::new(());

    const CODE: u64 = 0x10_000;

    fn word(trap: Trap) -> u64 {
        match trap {
            Trap::Syscall(SyscallTrap { args, .. }) => args[0],
            other => panic!("not a syscall: {other:?}"),
        }
    }

    /// The timer (or a waker) may stop the vCPU inside the page flush
    /// routine, while `x0` holds the routine's operand and the app's own
    /// `x0` waits in `TPIDR_EL1`: the app gets its own back, and the whole
    /// TLB is flushed instead.
    #[test]
    fn an_interrupted_page_flush_gives_the_app_its_x0_back() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
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
        p.resume(t, Resume::Continue).unwrap();
        assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x1111);
        // The vCPU as an exit inside the routine leaves it, at each of
        // its instructions: before and after `x0` is the app's again.
        for (at, x0) in [
            (0u64, 0xdead_0000_0000_0123u64),
            (12, 0xdead_0000_0000_0123),
            (16, 0x2222),
        ] {
            let v = &mut p.vcpu0().vcpu;
            v.set_sys_reg(sysreg::TPIDR_EL1, 0x2222).unwrap();
            v.set_reg(0, x0).unwrap();
            v.set_reg(HV_REG_PC, SHIM_VA + FLUSH_PAGE_OFFSET + at)
                .unwrap();
            v.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED).unwrap();
            // The platform then flushes the whole TLB instead.
            assert_eq!(p.vcpu0().interrupted_at().unwrap(), Stopped::Flushing);
            assert_eq!(p.vcpu0().vcpu.reg(0).unwrap(), 0x2222);
            // And the app runs on with it.
            p.resume(t, Resume::Continue).unwrap();
            assert_eq!(
                word(p.wait(None).unwrap().unwrap().trap),
                0x2222,
                "at +{at}"
            );
        }
    }

    fn make(config: HvfConfig) -> Option<HvfPlatform> {
        match HvfPlatform::new(config) {
            Ok(p) => Some(p),
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                None
            }
        }
    }

    #[test]
    fn registers_read_before_the_task_runs_again_have_the_result() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        testing::registers_read_before_the_task_runs_again_have_the_result(make);
    }

    #[test]
    fn spaces_beyond_the_asids_share_one_and_flush() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        testing::spaces_beyond_the_asids_share_one_and_flush(make);
    }

    #[test]
    fn a_slice_that_ends_in_a_vector_still_ends() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        testing::a_slice_that_ends_in_a_vector_still_ends(make);
    }
}
