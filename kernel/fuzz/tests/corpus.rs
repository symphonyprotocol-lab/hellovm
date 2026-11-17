//! Every fuzz target on the stable toolchain: each input of
//! `corpus/<target>/` (the seeds, everything libFuzzer kept, and the
//! minimized inputs of every crash found so far), then
//! `HELLOVM_FUZZ_ITERS` (default 2000) deterministic mutations of them.
//!
//! Per input: no panic, at most 2 s, and at most 256 MiB allocated at
//! once (a counting global allocator). A failing input is written to
//! `<target dir>/tmp/fuzz-failures/<target>/` for `cargo fuzz` and a regression
//! test.
//!
//! `cargo test --release` in `kernel/fuzz`; `HELLOVM_FUZZ_TARGET=name`
//! runs one target, `HELLOVM_FUZZ_SEED=n` picks another mutation stream.

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_LIVE: usize = 256 << 20;
const MAX_TIME: Duration = Duration::from_secs(2);

/// Counts live bytes and remembers the peak since the last reset.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: delegates to the system allocator and only adds counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Refuse instead of exhausting the machine: the test then fails
        // with an allocation error for that input.
        if layout.size() > MAX_LIVE * 4 {
            return std::ptr::null_mut();
        }
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: [u64; 12] = [
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x7fff,
    0xffff,
    0x7fff_ffff,
    0xffff_ffff,
    0x7fff_ffff_ffff_ffff,
    u64::MAX,
];

fn mutate(rng: &mut Rng, input: &mut Vec<u8>, corpus: &[Vec<u8>]) {
    for _ in 0..1 + rng.below(4) {
        let len = input.len();
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len);
                input[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                input[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(len + 1);
                let n = 1 + rng.below(16);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                input.splice(i..i, bytes);
            }
            3 if len > 0 => {
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(64));
                input.drain(i..i + n);
            }
            4 if len > 0 => {
                // An interesting integer, little- or big-endian.
                let v = INTERESTING[rng.below(INTERESTING.len())];
                let width = [1, 2, 4, 8][rng.below(4)];
                let i = rng.below(len);
                let bytes = if rng.below(2) == 0 {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                for (k, b) in bytes.iter().take(width).enumerate() {
                    if let Some(slot) = input.get_mut(i + k) {
                        *slot = *b;
                    }
                }
            }
            5 if !corpus.is_empty() => {
                // Splice in part of another input.
                let other = &corpus[rng.below(corpus.len())];
                if !other.is_empty() {
                    let a = rng.below(other.len());
                    let b = a + rng.below(other.len() - a + 1);
                    let i = rng.below(len + 1);
                    input.splice(i..i, other[a..b].iter().copied());
                }
            }
            6 if len > 1 => {
                // Duplicate a chunk.
                let a = rng.below(len);
                let b = a + rng.below((len - a).min(256) + 1);
                let chunk = input[a..b].to_vec();
                let i = rng.below(len + 1);
                input.splice(i..i, chunk);
            }
            _ => input.truncate(rng.below(len + 1)),
        }
    }
    input.truncate(1 << 16);
}

fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target)
}

fn load(target: &str) -> Vec<Vec<u8>> {
    let mut inputs: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(corpus_dir(target))
        .map(|dir| {
            dir.filter_map(|e| {
                let path = e.ok()?.path();
                Some((path.clone(), std::fs::read(path).ok()?))
            })
            .collect()
        })
        .unwrap_or_default();
    inputs.sort();
    inputs.into_iter().map(|(_, data)| data).collect()
}

/// Runs one input; returns what went wrong, if anything.
fn check(run: fn(&[u8]), input: &[u8]) -> Result<(), String> {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let start = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| run(input)));
    let took = start.elapsed();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    match result {
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            Err(format!("panicked: {msg}"))
        }
        Ok(()) if took > MAX_TIME => Err(format!("took {took:?}")),
        Ok(()) if peak > MAX_LIVE => Err(format!("allocated {} MiB at once", peak >> 20)),
        Ok(()) => Ok(()),
    }
}

fn save_failure(target: &str, input: &[u8]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("fuzz-failures")
        .join(target);
    std::fs::create_dir_all(&dir).unwrap();
    let hash = input
        .iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    let path = dir.join(format!("{hash:016x}"));
    std::fs::write(&path, input).unwrap();
    path
}

/// `HELLOVM_FUZZ_REPLAY=target:FILE` runs one input without catching its
/// panic, for a backtrace.
#[test]
fn replay() {
    let Ok(spec) = std::env::var("HELLOVM_FUZZ_REPLAY") else {
        return;
    };
    let (name, file) = spec.split_once(':').expect("target:FILE");
    let run = hellovm_fuzz::TARGETS
        .iter()
        .find(|t| t.0 == name)
        .expect("a target name")
        .1;
    run(&std::fs::read(file).unwrap());
}

#[test]
fn every_target_over_its_corpus_and_mutations() {
    // Panics are expected and caught; keep the output readable.
    std::panic::set_hook(Box::new(|_| {}));
    let iters: usize = std::env::var("HELLOVM_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let seed: u64 = std::env::var("HELLOVM_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let only = std::env::var("HELLOVM_FUZZ_TARGET").ok();
    let mut failures = Vec::new();
    for &(name, run) in hellovm_fuzz::TARGETS {
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        let corpus = load(name);
        assert!(!corpus.is_empty(), "{name}: no corpus in {}", corpus_dir(name).display());
        for input in &corpus {
            if let Err(what) = check(run, input) {
                failures.push(format!("{name}: corpus input {}: {what}", save_failure(name, input).display()));
            }
        }
        let mut rng = Rng(seed ^ name.len() as u64 ^ (name.as_bytes()[0] as u64) << 32);
        for _ in 0..iters {
            let mut input = corpus[rng.below(corpus.len())].clone();
            mutate(&mut rng, &mut input, &corpus);
            if let Err(what) = check(run, &input) {
                failures.push(format!("{name}: {}: {what}", save_failure(name, &input).display()));
                break;
            }
        }
    }
    let _ = std::panic::take_hook();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
