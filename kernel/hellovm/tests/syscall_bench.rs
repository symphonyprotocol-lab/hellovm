//! System-call timings on the seccomp platform (not a gate; ignored by
//! default). Prints, natively and under `hellovm`:
//!
//! * the round trip of single system calls (`test-guest/c/syscall_bench.c`):
//!   getppid, a 1-byte write to /dev/null, a 1-byte pipe write and read,
//!   clock_gettime;
//! * CPython from start to exit for `python3 -c pass` and for a program
//!   that imports a working set of the standard library.
//!
//! ```sh
//! cargo test --release -p hellovm --test syscall_bench -- --ignored --nocapture
//! ```
//!
//! `HELLOVM_BENCH_ITERS` sets the iterations per system-call case (default
//! 20000).

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::TempDir;
use hellovm_test_guest as guest;

const IMPORTS: &str = "import asyncio, json, decimal, hashlib, http.client, email.parser, \
                       xml.etree.ElementTree, urllib.request, argparse, dataclasses, pathlib";

/// Runs the command and returns its stdout; panics unless it succeeds.
fn output(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// `case ns` lines into pairs.
fn cases(out: &str) -> Vec<(String, f64)> {
    out.lines()
        .map(|line| {
            let (name, ns) = line.split_once(' ').unwrap();
            (name.to_string(), ns.parse().unwrap())
        })
        .collect()
}

fn median(cmd: &mut Command, runs: usize) -> Duration {
    let mut samples: Vec<Duration> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            output(cmd);
            start.elapsed()
        })
        .collect();
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
#[ignore]
fn syscall_timings() {
    if !common::require_guest(guest::SYSCALL_BENCH, "syscall_bench") {
        return;
    }
    let iters = std::env::var("HELLOVM_BENCH_ITERS").unwrap_or_else(|_| "20000".into());
    let hellovm = env!("CARGO_BIN_EXE_hellovm");
    let image = TempDir::new("syscall-bench");
    image.install(guest::SYSCALL_BENCH, "syscall_bench");
    image.mkdir("dev");

    let native = cases(&output(Command::new(guest::SYSCALL_BENCH).arg(&iters)));
    let root = image.path().to_str().unwrap();
    let sandboxed = cases(&output(Command::new(hellovm).args([
        "--root",
        root,
        "/syscall_bench",
        &iters,
    ])));

    println!();
    println!(
        "{:<20} {:>12} {:>12} {:>8}",
        "per call", "native", "hellovm", "ratio"
    );
    for ((name, n), (_, h)) in native.iter().zip(&sandboxed) {
        println!(
            "{name:<20} {n:>10.0}ns {h:>10.0}ns {:>7.0}x",
            h / n.max(1.0)
        );
    }

    if !std::path::Path::new("/usr/bin/python3").exists() {
        common::skip_or_fail("syscall bench: /usr/bin/python3 not found");
        return;
    }
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    for (name, program) in [("python3 -c pass", "pass"), ("python3 imports", IMPORTS)] {
        let native = median(Command::new("/usr/bin/python3").args(["-c", program]), 5);
        let sandboxed = median(
            Command::new(hellovm).args(["--root", "/", "/usr/bin/python3", "-c", program]),
            5,
        );
        println!(
            "{name:<20} {:>10.1}ms {:>10.1}ms {:>7.1}x",
            ms(native),
            ms(sandboxed),
            sandboxed.as_secs_f64() / native.as_secs_f64()
        );
    }
}
