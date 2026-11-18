//! The SDKs and the MCP server end to end: each test starts a whole plane
//! (the one `control_plane.rs` uses: an egress proxy, `hellovm-noded`
//! with a warm CPython template, `hellovm-api` with two tenants) and runs
//! one suite against it as a child process, which finds the plane in
//! `HELLOVM_TEST_URL`, `HELLOVM_TEST_TOKEN`, `HELLOVM_TEST_TEMPLATE`,
//! `HELLOVM_TEST_TOKEN_B` and `HELLOVM_TEST_TEMPLATE_B`.
//!
//! They are ignored by a plain `cargo test`, which must not need Node.js:
//! `kernel/dev/run-sdk-e2e.sh` builds the TypeScript packages and runs
//! them with `--ignored`. A missing Python 3.10+ or Node.js 20+, or an
//! unbuilt package, skips a test with a message, or fails it when
//! `HELLOVM_REQUIRE_E2E=1`.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{skip_or_fail, Plane, PlaneOptions, ACME, BETA};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The version `program --version`-like `args` print, as numbers.
fn version(program: &str, args: &[&str]) -> Option<Vec<u32>> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim().trim_start_matches('v');
    text.split('.').take(2).map(|p| p.parse().ok()).collect()
}

fn python() -> Option<&'static str> {
    match version("python3", &["-c", "import sys; print('%d.%d' % sys.version_info[:2])"]) {
        Some(v) if v >= vec![3, 10] => Some("python3"),
        _ => {
            skip_or_fail("SDK e2e: python3 3.10 or later not found (install python3)");
            None
        }
    }
}

fn node(built: &[&str]) -> bool {
    match version("node", &["--version"]) {
        Some(v) if v >= vec![20, 0] => {}
        _ => {
            skip_or_fail("SDK e2e: Node.js 20 or later not found (install nodejs)");
            return false;
        }
    }
    for path in built {
        if !repo().join(path).exists() {
            skip_or_fail(&format!(
                "SDK e2e: {path} is not built (run `npm ci && npm run build` in sdk/ts and sdk/mcp, \
                 or kernel/dev/run-sdk-e2e.sh)"
            ));
            return false;
        }
    }
    true
}

/// Runs `program args` in `dir` against a fresh plane; panics with its
/// output and the plane's logs if it fails.
fn run_suite(what: &str, dir: &str, program: &str, args: &[&str], env: &[(&str, String)]) {
    let Some(plane) = Plane::start(PlaneOptions {
        acme_max: 12,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let url = format!("http://{}", plane.api_addr());
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(repo().join(dir))
        .env("HELLOVM_TEST_URL", &url)
        .env("HELLOVM_TEST_TOKEN", ACME)
        .env("HELLOVM_TEST_TEMPLATE", plane.template(ACME))
        .env("HELLOVM_TEST_TOKEN_B", BETA)
        .env("HELLOVM_TEST_TEMPLATE_B", plane.template(BETA))
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{what}: cannot run {program}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        panic!(
            "{what} failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n{}",
            out.status,
            plane.logs()
        );
    }
    eprintln!("{what}:\n{stdout}{stderr}");
    for skipped in ["skipped=", "# skip "] {
        if common::e2e_required() {
            if let Some(line) = stdout
                .lines()
                .chain(stderr.lines())
                .find(|l| l.contains(skipped) && !l.contains(&format!("{skipped}0")))
            {
                panic!("{what}: a required test was skipped: {line}");
            }
        }
    }
}

#[test]
#[ignore = "needs Python and Node.js: run by kernel/dev/run-sdk-e2e.sh"]
fn python_sdk() {
    let Some(python) = python() else { return };
    run_suite(
        "the Python SDK's tests",
        "sdk/python",
        python,
        &["-m", "unittest", "discover", "-s", "tests", "-t", "tests", "-v"],
        &[("PYTHONPATH", repo().join("sdk/python/src").display().to_string())],
    );
}

#[test]
#[ignore = "needs Python and Node.js: run by kernel/dev/run-sdk-e2e.sh"]
fn typescript_sdk() {
    if !node(&["sdk/ts/dist/index.js", "sdk/ts/dist/test"]) {
        return;
    }
    run_suite(
        "the TypeScript SDK's tests",
        "sdk/ts",
        "node",
        &["--test", "--test-concurrency=1", "dist/test/"],
        &[],
    );
}

#[test]
#[ignore = "needs Python and Node.js: run by kernel/dev/run-sdk-e2e.sh"]
fn mcp_server() {
    if !node(&["sdk/ts/dist/index.js", "sdk/mcp/dist/server.js", "sdk/mcp/dist/test"]) {
        return;
    }
    run_suite(
        "the MCP server's tests",
        "sdk/mcp",
        "node",
        &["--test", "--test-concurrency=1", "dist/test/"],
        &[],
    );
}
