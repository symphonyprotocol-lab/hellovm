//! Node.js from the build host, with the host's root as the image
//! (`--root /`, read-only with an in-memory layer), through the command
//! line. Its event loop (libuv) is built on epoll; the checks are in
//! `tests/node/check.js`: timers, promises and the file system, a hash, a
//! child process run to completion and one fed through a pipe, a worker
//! thread, and an HTTP server answering three clients on loopback.
//!
//! Without `node` on `PATH` the test is skipped unless
//! `HELLOVM_REQUIRE_E2E=1`, which fails it.

#![cfg(target_os = "linux")]

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::TempDir;

const CHECK: &str = include_str!("node/check.js");

fn node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("node"))
        .find(|candidate| candidate.is_file())
        .and_then(|found| std::fs::canonicalize(found).ok())
}

#[test]
fn node_runs_its_event_loop() {
    let Some(node) = node() else {
        common::skip_or_fail("Node.js: no `node` on PATH");
        return;
    };
    let dir = TempDir::new("node");
    dir.write("check.js", CHECK.as_bytes());
    let script = dir.path().join("check.js");
    for sandbox in ["off", "require"] {
        let out = Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .args(["--sandbox", sandbox, "--root", "/"])
            .arg(&node)
            .arg(&script)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            lines,
            [
                "timers: ok",
                "fs: 100000",
                "sha256: 3e11897887607fd8",
                "execFileSync: 42",
                "spawn: piped",
                "worker: 499999500000",
                "http: hi /1,hi /2,hi /3",
            ],
            "--sandbox {sandbox}\nstderr:\n{stderr}"
        );
        assert_eq!(out.status.code(), Some(3), "--sandbox {sandbox}\n{stderr}");
    }
}
