//! Real programs on the HVF platform, through the kernel core: the C test
//! guests (`kernel/test-guest/c`), a busybox shell and CPython, from the
//! image `kernel/platform-hvf/build-guests.sh` assembles in the Linux dev
//! container. Its path is `HELLOVM_HVF_GUESTS`; without it (or without
//! the hypervisor) the tests print `SKIPPING` and pass, unless
//! `HELLOVM_REQUIRE_E2E=1`.
//!
//! Every test checks afterwards that every frame of app memory went back
//! to the pool and that only the shim's page tables are left.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm_core::{ExitStatus, Kernel};
use hellovm_host::{CaptureHost, ImageDir};
use hellovm_platform_hvf::{HvfConfig, HvfPlatform};

/// One VM per process: the tests take turns.
static VM: Mutex<()> = Mutex::new(());

/// Page tables of the shim (the `TTBR1_EL1` tree): what is left in use
/// when no app runs.
const SHIM_TABLES: u64 = 4 * 4096;

/// `HELLOVM_HVF_VCPUS`, if set, overrides the vCPU count of a config that
/// leaves it to the default, so that the whole suite runs with one vCPU
/// or with several.
fn with_test_vcpus(mut config: HvfConfig) -> HvfConfig {
    if config.vcpus == 0 {
        if let Some(n) = std::env::var("HELLOVM_HVF_VCPUS")
            .ok()
            .and_then(|n| n.parse().ok())
        {
            config.vcpus = n;
        }
    }
    config
}

fn require() -> bool {
    std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1")
}

/// The guest image, a platform with `config`, and the lock.
fn setup(config: HvfConfig) -> Option<(MutexGuard<'static, ()>, HvfPlatform, PathBuf)> {
    let guard = VM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = std::env::var_os("HELLOVM_HVF_GUESTS").map(PathBuf::from) else {
        if require() {
            panic!("HELLOVM_REQUIRE_E2E=1 but HELLOVM_HVF_GUESTS is not set");
        }
        eprintln!("SKIPPING: set HELLOVM_HVF_GUESTS (see platform-hvf/build-guests.sh)");
        return None;
    };
    assert!(
        root.join("guests/forks").is_file(),
        "{} is not an image made by build-guests.sh",
        root.display()
    );
    match HvfPlatform::new(with_test_vcpus(config)) {
        Ok(p) => Some((guard, p, root)),
        Err(err) if require() => {
            panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
        }
        Err(err) => {
            eprintln!("SKIPPING: the HVF platform is unavailable: {err}");
            None
        }
    }
}

struct Out {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status {:?}\n--- stdout\n{}--- stderr\n{}",
            self.status, self.stdout, self.stderr
        )
    }
}

fn run(p: &mut HvfPlatform, root: &PathBuf, argv: &[&str]) -> Out {
    let host = CaptureHost::new(Some(ImageDir::open(root).unwrap()));
    let mut kernel = Kernel::new(host);
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
    let env = [b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()];
    kernel.exec(p, &argv[0], &argv, &env).expect("exec");
    let status = kernel.run(p).expect("run");
    let host = kernel.into_host();
    let out = Out {
        status,
        stdout: String::from_utf8_lossy(&host.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&host.stderr).into_owned(),
    };
    assert_eq!(
        p.memory_in_use(),
        (0, SHIM_TABLES),
        "memory left in use after the run: {out:?}"
    );
    out
}

fn lines(out: &Out) -> Vec<&str> {
    out.stdout.lines().collect()
}

/// A static glibc program: arguments, a file, `malloc`, an 8 MiB `mmap`.
#[test]
fn c_program() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/smoke", "one", "two words"]);
    assert_eq!(out.status, ExitStatus::Exited(3), "{out:?}");
    assert_eq!(
        out.stdout,
        "argv[0]=/guests/smoke\nargv[1]=one\nargv[2]=two words\n\
         read 18 bytes: hello from a file\n\
         malloc ok, mmap ok: zz, pid 1\n",
        "{out:?}"
    );
}

/// Processes: see `kernel/test-guest/c/forks.c`. The same lines as on
/// the seccomp platform (`hellovm/tests/forks.rs`).
#[test]
fn fork_exec_vfork_and_copy_on_write() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/forks"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        lines(&out),
        [
            "fork: child exited 42",
            "cow: parent-saw=1ppp child-kept-its-own=yes",
            "shared: parent-sees=CD private-untouched=0",
            "shared: child-sees=P",
            "zero: child=ok parent=kept",
            "big shared: child 0, parent-sees=Sp",
            "exec: child forked",
            "fork+exec: status 7",
            "exec: child vforked",
            "vfork+exec: status 7",
            "vfork+_exit: status 5",
            "exec: child spawned",
            "posix_spawn: status 7",
            "fork of fork: 13, parent still 10",
            "big: 64 MiB child=ok parent=ok",
            "wait: 5 children, sum 15",
            "pipe: writer 0 reader 0",
            "busy child: parent ran, child ended by 9",
        ],
        "{out:?}"
    );
}

/// `kernel/test-guest/c/signals.c` passes completely: the same lines as
/// `hellovm/tests/signals.rs` expects on the seccomp platform.
#[test]
fn signals() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/signals"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        lines(&out),
        [
            "segv: caught at 0x10",
            "raise: 10",
            "blocked: pending=1 got=0",
            "unblocked: got=10",
            "alarm: 14",
            "sigsuspend: -1 Interrupted system call got=10 still-blocked=1",
            "altstack: 1",
            "ticks: ok fp: ok",
            "read restart: 1 data",
            "read eintr: -1 Interrupted system call",
            "child term: signaled=1 sig=15 core=0",
            "child segv: signaled=1 sig=11 core=1",
            "stopped: 1 sig=19",
            "continued and exited: 5 sigchld=1",
            "pipe write: 300000 reader=0",
            "sleep keeps its deadline: 1",
            "sleep eintr: -1 rem-ok=1",
            "vfork parent killed: 1 fast=1",
            "clone sharing refused: -1 1",
        ],
        "{out:?}"
    );
}

/// Threads share the address space and run on the default vCPUs (or
/// `HELLOVM_HVF_VCPUS`): the same lines as `hellovm/tests/threads.rs`
/// expects on the seccomp platform.
#[test]
fn threads() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/threads"]);
    assert_eq!(out.status, ExitStatus::Exited(7), "{out:?}");
    assert_eq!(
        lines(&out),
        [
            "join: counter=16000 tls-sum=288 distinct-tids=1",
            "broadcast: all woke",
            "timedwait: timed out",
            "pthread_kill: pending-while-blocked=1 handled-by-target=1",
            "robust: owner died",
            "fork: child-threads=1",
        ],
        "{out:?}"
    );
}

/// A platform with `vcpus` vCPUs, and the image.
fn setup_vcpus(vcpus: usize) -> Option<(MutexGuard<'static, ()>, HvfPlatform, PathBuf)> {
    let (guard, p, root) = setup(HvfConfig {
        vcpus,
        ..HvfConfig::default()
    })?;
    assert_eq!(p.vcpus(), vcpus);
    Some((guard, p, root))
}

/// Threads that run at the same time, on 1, 2 and 4 vCPUs: the checks of
/// `kernel/test-guest/c/smp.c` (fork, `mprotect` and `munmap` while other
/// threads write, copy-on-write with concurrent writers, futex ping-pong,
/// a signal to a thread that never makes a system call, system calls
/// next to 16 spinning threads, and `exit_group` from the main thread or
/// another one and `execve`, while threads spin), CPython's `threading`
/// and a busybox pipeline. The same lines as on the seccomp platform
/// (`hellovm/tests/smp.rs`); after each program every frame and table is
/// back in its pool.
#[test]
fn threads_in_parallel() {
    for vcpus in [1, 2, 4] {
        let Some((guard, mut p, root)) = setup_vcpus(vcpus) else {
            return;
        };
        let out = run(&mut p, &root, &["/guests/smp", "all"]);
        assert_eq!(out.status, ExitStatus::Exited(0), "{vcpus} vCPUs: {out:?}");
        assert_eq!(
            lines(&out),
            [
                "fork-while-writing: ok",
                "mprotect-while-writing: ok rounds=20",
                "munmap-while-writing: ok rounds=20",
                "cow-concurrent-writers: ok rounds=10",
                "futex-ping-pong: ok rounds=20000",
                "signal-to-running-thread: ok rounds=20",
                "syscalls-next-to-spinners: ok",
            ],
            "{vcpus} vCPUs: {out:?}"
        );
        eprintln!("{vcpus} vCPUs: {}", out.stderr.trim_end());
        for (check, status, line) in [
            ("exit-group", 7, "exit-group: exiting"),
            (
                "exit-group-from-thread",
                8,
                "exit-group-from-thread: exiting",
            ),
            ("exec", 0, "exec-while-spinning: ok"),
        ] {
            let out = run(&mut p, &root, &["/guests/smp", check]);
            assert_eq!(
                out.status,
                ExitStatus::Exited(status),
                "{vcpus} vCPUs: {out:?}"
            );
            assert_eq!(lines(&out), [line], "{vcpus} vCPUs: {out:?}");
        }
        let out = run(&mut p, &root, &["/usr/bin/python3", "-c", PY_THREADS]);
        assert_eq!(out.status, ExitStatus::Exited(0), "{vcpus} vCPUs: {out:?}");
        assert_eq!(out.stdout, "threads: 8 results 39999600000 ok\n", "{out:?}");
        let out = run(
            &mut p,
            &root,
            &[
                "/bin/sh",
                "-c",
                "seq 1 20000 | grep 7 | sort -rn | uniq | head -3",
            ],
        );
        assert_eq!(out.status, ExitStatus::Exited(0), "{vcpus} vCPUs: {out:?}");
        assert_eq!(out.stdout, "19997\n19987\n19979\n", "{out:?}");
        drop(p);
        drop(guard);
    }
}

/// CPython threads: a queue, a lock, eight workers.
const PY_THREADS: &str = r#"
import queue, threading
q = queue.Queue()
lock = threading.Lock()
total = []
def work(n):
    s = sum(range(n))
    with lock:
        total.append(s)
    q.put(n)
ts = [threading.Thread(target=work, args=(100000,)) for _ in range(8)]
for t in ts:
    t.start()
for t in ts:
    t.join()
assert sorted(q.get() for _ in range(8)) == [100000] * 8
print("threads: %d results %d ok" % (len(total), sum(total)))
"#;

/// What `smp scale` computes (`work` in `kernel/test-guest/c/smp.c`).
fn scale_sum(threads: u64, iters: u64) -> u64 {
    let mut sum = 0u64;
    for id in 0..threads {
        let mut x = id.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        let mut acc = 0u64;
        for _ in 0..iters {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            acc = acc.wrapping_add(x >> 3);
        }
        sum = sum.wrapping_add(acc);
    }
    sum
}

/// `smp scale THREADS ITERS`: checks its sum, returns its time in ms.
fn scale(p: &mut HvfPlatform, root: &PathBuf, threads: u64, iters: u64) -> u64 {
    let (t, i) = (threads.to_string(), iters.to_string());
    let out = run(p, root, &["/guests/smp", "scale", &t, &i]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    let line = out.stdout.trim_end();
    let want = format!(
        "scale: threads={threads} sum={:016x} ms=",
        scale_sum(threads, iters)
    );
    let ms = line
        .strip_prefix(&want)
        .unwrap_or_else(|| panic!("wrong result: {line} (want {want}...)"));
    ms.parse().unwrap()
}

/// Four threads of CPU work take clearly less time on four vCPUs than on
/// one, and compute the same.
#[test]
fn cpu_work_scales_with_vcpus() {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    if cpus < 4 {
        eprintln!("SKIPPING: {cpus} host CPUs");
        return;
    }
    let (threads, iters) = (4, 20_000_000);
    let mut best = Vec::new();
    for vcpus in [1, 4] {
        let Some((guard, mut p, root)) = setup_vcpus(vcpus) else {
            return;
        };
        let ms = (0..3)
            .map(|_| scale(&mut p, &root, threads, iters))
            .min()
            .unwrap();
        eprintln!("{threads} threads of CPU work, {vcpus} vCPUs: {ms} ms (best of 3)");
        best.push(ms);
        drop(p);
        drop(guard);
    }
    assert!(
        best[1] * 10 < best[0] * 6,
        "4 vCPUs took {} ms, 1 vCPU {} ms",
        best[1],
        best[0]
    );
}

/// A static-PIE program and a dynamically linked one (its interpreter
/// maps libc and libm with file-backed private mappings, relocates them
/// and protects their RELRO).
#[test]
fn pie_and_dynamic_linking() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/pie", "arg"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    for part in [
        "argc=2 argv1=arg tls=42 big=x small",
        "pagesz=4096",
        "random=yes",
    ] {
        assert!(out.stdout.contains(part), "{part}: {out:?}");
    }
    let out = run(&mut p, &root, &["/guests/dynamic", "hello"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        out.stdout,
        "dynamic: arg=hello sqrt2=1.4142 interp=yes exe=/guests/dynamic\n"
    );
}

/// A busybox shell runs pipelines of several processes, a loop, command
/// substitution and a background job.
#[test]
fn busybox_shell_pipeline() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let script = "seq 1 20000 | grep 7 | sort -rn | uniq | head -3; \
                  echo $(seq 1 100 | wc -l) lines; \
                  for i in 1 2 3; do echo $i; done | tr 123 abc | sed s/b/B/ | cat; \
                  sleep 0.05 & wait $! && echo background done; \
                  yes | head -1000 | wc -c";
    let out = run(&mut p, &root, &["/bin/sh", "-c", script]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        lines(&out),
        [
            "19997",
            "19987",
            "19979",
            "100 lines",
            "a",
            "B",
            "c",
            "background done",
            "2000"
        ],
        "{out:?}"
    );
}

/// CPython 3 (dynamically linked, with extension modules): standard
/// modules, arithmetic, file I/O and `subprocess` (fork and exec of a
/// shell and of Python itself).
#[test]
fn python_script() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let script = r#"
import os, sys, json, re, hashlib, collections, decimal, math, subprocess, tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "x.json")
with open(path, "w") as f:
    json.dump({"n": [i * i for i in range(10)]}, f)
with open(path) as f:
    print("json", sum(json.load(f)["n"]))
os.remove(path)
os.rmdir(d)
print("arith", 2 ** 100 % 97, decimal.Decimal(1) / decimal.Decimal(7), math.factorial(20))
print("re", re.findall(r"\d+", "a1b22c333"))
print("sha256", hashlib.sha256(b"hellovm").hexdigest()[:16])
print("counter", collections.Counter("mississippi").most_common(2))
out = subprocess.run(["/bin/sh", "-c", "echo $((6 * 7)) | cat"], capture_output=True, text=True)
print("subprocess", out.returncode, out.stdout.strip())
out = subprocess.run([sys.executable, "-c", "import os; print(os.getppid())"], capture_output=True, text=True)
print("python child of", out.stdout.strip())
"#;
    let out = run(&mut p, &root, &["/usr/bin/python3", "-c", script]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        lines(&out),
        [
            "json 285",
            "arith 16 0.1428571428571428571428571429 2432902008176640000",
            "re ['1', '22', '333']",
            "sha256 3e11897887607fd8",
            "counter [('i', 4), ('s', 4)]",
            "subprocess 0 42",
            "python child of 1",
        ],
        "{out:?}"
    );
}

/// A fork bomb in a sandbox with 2 MiB of page tables (512 tables) and
/// 128 MiB of memory: forks fail with `EAGAIN` once the pools (or the
/// core's limit on processes) are used up, every process ends, and all
/// memory and tables go back to the pools. The kernel process allocates
/// nothing more for it than its fixed pools and the core's per-process
/// state, which the core bounds.
#[test]
fn fork_bomb_is_bounded_by_the_pools() {
    let config = HvfConfig {
        memory: 128 << 20,
        table_memory: 2 << 20,
        ..HvfConfig::default()
    };
    let Some((_guard, mut p, root)) = setup(config) else {
        return;
    };
    // A last resort, so that a hang fails the test instead of blocking.
    let killer = p.killer();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let done = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(120) {
                if done.load(std::sync::atomic::Ordering::SeqCst) {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            killer.kill();
            true
        })
    };
    let start = Instant::now();
    let out = run(&mut p, &root, &["/guests/forks", "bomb", "60"]);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(!watchdog.join().unwrap(), "the bomb did not end: {out:?}");
    eprintln!("{} (in {:?})", out.stderr.trim(), start.elapsed());
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        out.stdout, "bomb: ended, forks failed: yes, other errors: 0\n",
        "{out:?}"
    );
}

/// A process that runs out of the sandbox's memory on a copy-on-write
/// fault is killed (`SIGKILL`, as by Linux's OOM killer); its parent and
/// the shell go on, and all memory goes back to the pool.
#[test]
fn out_of_memory_ends_only_the_process() {
    let config = HvfConfig {
        memory: 64 << 20,
        ..HvfConfig::default()
    };
    let Some((_guard, mut p, root)) = setup(config) else {
        return;
    };
    // 40 MiB touched, then a child that writes all of it: 80 MiB.
    let out = run(
        &mut p,
        &root,
        &["/bin/sh", "-c", "/guests/forks bench 1 40; echo status $?"],
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert!(out.stdout.starts_with("FAILED: child"), "{out:?}");
    assert!(out.stdout.ends_with("status 1\n"), "{out:?}");
}

/// Benchmarks for the README: `HELLOVM_HVF_GUESTS=... cargo test --release
/// -p hellovm-platform-hvf --test guests -- --ignored --nocapture`.
#[test]
#[ignore = "benchmark"]
fn benchmarks() {
    let Some((_guard, mut p, root)) = setup(HvfConfig::default()) else {
        return;
    };
    let out = run(&mut p, &root, &["/guests/forks", "bench", "1000", "256"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    eprint!("{}", out.stdout);
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        let out = run(&mut p, &root, &["/usr/bin/python3", "-c", "pass"]);
        best = best.min(start.elapsed());
        assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    }
    eprintln!("python3 -c pass: {best:?} (best of 5, in process)");
    let out = run(&mut p, &root, &["/usr/bin/python3", "-c", PY_BENCH]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    eprint!("{}", out.stdout);
}

/// A small CPython benchmark: function calls, a dictionary, sorting,
/// string formatting. Prints its own time (the interpreter's clock).
pub const PY_BENCH: &str = r#"
import time
def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)
best = None
for _ in range(3):
    t = time.perf_counter()
    fib(24)
    d = {str(i): i for i in range(200000)}
    s = sorted(d.values(), reverse=True)
    "".join("%d," % i for i in s[:50000])
    took = time.perf_counter() - t
    best = took if best is None else min(best, took)
print("python bench: %.1f ms (best of 3)" % (best * 1e3))
"#;
