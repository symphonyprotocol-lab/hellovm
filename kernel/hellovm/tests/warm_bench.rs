//! Warm-clone timings (not a gate; ignored by default). Prints, for the
//! same CPython program with a set of standard modules imported:
//!
//! * cold start under hellovm: from spawning `hellovm` to the program's
//!   first line of output, and the same natively;
//! * the template: from spawning it to being frozen;
//! * a clone: from sending the request to frame `S` (the clone's first
//!   guest instruction runs), to the program's first line, and to the
//!   clone's exit status.
//!
//! ```sh
//! cargo test --release -p hellovm --test warm_bench -- --ignored --nocapture
//! ```
//!
//! `HELLOVM_BENCH_CLONES` sets the number of clones (default 30).

#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::Template;

/// Imports a working set of the standard library, then waits at the clone
/// point (end of file at once when not a template) and prints a line.
const PROGRAM: &str = r#"
import asyncio, json, decimal, hashlib, http.client, email.parser, ssl
import xml.etree.ElementTree, urllib.request, argparse, dataclasses, pathlib, sqlite3
open("/dev/hellovm-clone", "rb").read()
print("hello", flush=True)
"#;

fn first_line(cmd: &mut Command) -> (Duration, Duration) {
    let start = Instant::now();
    let mut child = cmd.stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let first = start.elapsed();
    assert_eq!(line, "hello\n");
    assert!(child.wait().unwrap().success());
    (first, start.elapsed())
}

fn stats(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!(
        "{name:<44} min {:>8.2} ms  median {:>8.2} ms  max {:>8.2} ms  (n={})",
        ms(samples[0]),
        ms(samples[samples.len() / 2]),
        ms(samples[samples.len() - 1]),
        samples.len()
    );
}

#[test]
#[ignore]
fn warm_clone_timings() {
    if !std::path::Path::new("/usr/bin/python3").exists() {
        common::skip_or_fail("warm-clone bench: /usr/bin/python3 not found");
        return;
    }
    let n: usize = std::env::var("HELLOVM_BENCH_CLONES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let hellovm = env!("CARGO_BIN_EXE_hellovm");

    let mut native = Vec::new();
    let mut cold = Vec::new();
    for _ in 0..5 {
        // Natively there is no clone point.
        let native_program = PROGRAM.replace("open(\"/dev/hellovm-clone\", \"rb\").read()", "");
        native.push(first_line(Command::new("/usr/bin/python3").args(["-c", &native_program])).0);
        cold.push(
            first_line(Command::new(hellovm).args([
                "--root",
                "/",
                "/usr/bin/python3",
                "-c",
                PROGRAM,
            ]))
            .0,
        );
    }

    let start = Instant::now();
    let template = Template::start(&["/usr/bin/python3", "-c", PROGRAM], &[]);
    let (stored, areas) = template
        .ready()
        .unwrap_or_else(|err| panic!("{err}\n{}", template.output()));
    let frozen = start.elapsed();

    let mut to_start = Vec::new();
    let mut to_line = Vec::new();
    let mut to_exit = Vec::new();
    for _ in 0..n {
        let start = Instant::now();
        let mut clone = template.spawn(None, b"").unwrap();
        to_start.push(start.elapsed());
        assert_eq!(clone.line(), "hello\n");
        to_line.push(start.elapsed());
        let run = clone.finish();
        to_exit.push(start.elapsed());
        assert_eq!(run.status, hellovm::warm::Status::Exited(0));
    }

    println!();
    println!(
        "template: frozen {:.1} ms after start; snapshot {:.1} MiB stored in {areas} areas",
        frozen.as_secs_f64() * 1000.0,
        stored as f64 / (1 << 20) as f64
    );
    stats("native python3: start to first line", native);
    stats("cold hellovm: start to first line", cold);
    stats("clone: request to first instruction (S)", to_start);
    stats("clone: request to first line", to_line);
    stats("clone: request to exit status", to_exit);
}
