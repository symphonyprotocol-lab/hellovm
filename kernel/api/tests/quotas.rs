//! Quotas and metering (README, "Control plane", "Quotas and metering"):
//! period budgets refused at create and exec and given back at the period's
//! end, the memory quota exact under concurrent creates, the request rate
//! limited per tenant, the usage log's records of sandboxes that ran and
//! ended, the totals across an API restart and a log that could not be
//! written at first, a node that reports absurd or decreasing counters,
//! the delete of a sandbox on an unreachable node, and a node that starts
//! drained.

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{header, raw_call, Plane, PlaneOptions, ACME, ADMIN_TOKEN, BETA};
use serde_json::{json, Value};

fn id_of(sandbox: &Value) -> String {
    sandbox["id"].as_str().unwrap().to_string()
}

fn node_of(sandbox: &Value) -> String {
    sandbox["node"].as_str().unwrap().to_string()
}

fn eventually(limit: Duration, what: &str, mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < limit, "{what} after {limit:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn usage(plane: &Plane, token: &str) -> Value {
    let r = plane.call(token, "GET", "/v1/usage", b"");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

fn admin_state(plane: &Plane, name: &str) -> String {
    plane
        .admin_call(ADMIN_TOKEN, "GET", &format!("/admin/v1/nodes/{name}"))
        .json()["state"]
        .as_str()
        .unwrap()
        .to_string()
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Sleeps until a period of `period` seconds has just begun.
fn wait_for_period(period: f64) {
    let into = now_secs() % period;
    std::thread::sleep(Duration::from_secs_f64(period - into + 0.2));
}

/// Python that keeps a CPU busy for `seconds`.
fn burn(seconds: f64) -> Value {
    json!({
        "python": format!(
            "import time\nend = time.time() + {seconds}\nwhile time.time() < end:\n    sum(range(100000))\n"
        ),
        "timeout": 60,
    })
}

/// Python that fetches `http://web.test/` (through the egress proxy).
fn fetch() -> Value {
    json!({
        "python": "import urllib.request\nprint(urllib.request.urlopen('http://web.test/', timeout=10).read().decode())",
        "timeout": 30,
    })
}

#[test]
fn budgets_refuse_new_work_until_the_period_ends() {
    let period = 15.0;
    let Some(plane) = Plane::start(PlaneOptions {
        acme_max: 4,
        acme_extra: json!({"cpu_seconds_per_period": 0.5}),
        beta_extra: json!({"egress_bytes_per_period": 1}),
        api_extra: json!({"metering": {"period": 15}}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let before = usage(&plane, ACME);
    assert_eq!(before["quotas"]["cpu_seconds_per_period"], 0.5);
    assert_eq!(before["period"]["seconds"], 15);
    assert_eq!(before["exceeded"], json!([]));

    wait_for_period(period);
    let a = id_of(&plane.create(ACME, json!({})));
    let b = id_of(&plane.create(ACME, json!({})));
    // Started before the budget is used up: it runs to its end.
    let long = plane.start_exec(
        ACME,
        &a,
        json!({"command": "sleep 3; echo still", "timeout": 30}),
    );
    plane.exec(ACME, &b, burn(1.5));
    eventually(Duration::from_secs(8), "the CPU budget used up", || {
        usage(&plane, ACME)["exceeded"] == json!(["cpu"])
    });
    let used = usage(&plane, ACME);
    assert!(used["usage"]["cpu_ms"].as_u64().unwrap() >= 500, "{used}");

    // New work is refused, with when to try again.
    let r = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    assert_eq!((r.status, r.code().as_str()), (429, "budget_exceeded"));
    for what in ["exec", "execs"] {
        let r = plane.call_json(
            ACME,
            "POST",
            &format!("/v1/sandboxes/{a}/{what}"),
            json!({"command": "true"}),
        );
        assert_eq!(
            (r.status, r.code().as_str()),
            (429, "budget_exceeded"),
            "{what}"
        );
    }
    let (status, head) = raw_call(
        &plane.api_addr(),
        ACME,
        "POST",
        &format!("/v1/sandboxes/{a}/exec"),
    );
    assert_eq!(status, 429);
    let retry: u64 = header(&head, "retry-after").unwrap().parse().unwrap();
    assert!((1..=15).contains(&retry), "{head}");
    // Everything else works: reads, polls, cancels, files, deletes.
    assert_eq!(
        plane
            .call(ACME, "GET", &format!("/v1/sandboxes/{a}"), b"")
            .status,
        200
    );
    assert_eq!(plane.call(ACME, "GET", "/v1/sandboxes", b"").status, 200);
    let (_, result) = plane.follow(ACME, &a, &long);
    assert_eq!(
        plane
            .call(
                ACME,
                "GET",
                &format!("/v1/sandboxes/{a}/files?path=/etc/passwd"),
                b""
            )
            .status,
        200
    );
    assert_eq!(
        (result["exit_code"].as_i64(), result["stdout"].as_str()),
        (Some(0), Some("still\n"))
    );
    assert_eq!(plane.cancel(ACME, &a, &long).status, 200);
    assert_eq!(
        plane
            .call(
                ACME,
                "POST",
                &format!("/v1/sandboxes/{a}/python/reset"),
                b""
            )
            .status,
        200
    );
    assert_eq!(plane.delete(ACME, &b), 204);

    // Another tenant is not touched by acme's budget, and has its own.
    let y = id_of(&plane.create(BETA, json!({})));
    let fetched = plane.exec(BETA, &y, fetch());
    assert_eq!(
        fetched["stdout"],
        format!("{}\n", common::WEB_BODY),
        "{fetched}"
    );
    eventually(
        Duration::from_secs(8),
        "beta's egress budget used up",
        || usage(&plane, BETA)["exceeded"] == json!(["egress"]),
    );
    let beta = usage(&plane, BETA);
    assert!(
        beta["usage"]["egress_sent_bytes"].as_u64().unwrap() > 0,
        "{beta}"
    );
    assert!(
        beta["usage"]["egress_received_bytes"].as_u64().unwrap() > common::WEB_BODY.len() as u64
    );
    let r = plane.call_json(
        BETA,
        "POST",
        &format!("/v1/sandboxes/{y}/exec"),
        json!({"command": "true"}),
    );
    assert_eq!(r.code(), "budget_exceeded");
    let acme = usage(&plane, ACME);
    assert_eq!(acme["usage"]["egress_sent_bytes"], 0, "{acme}");
    assert_eq!(acme["exceeded"], json!(["cpu"]));

    // A new period: the budgets are back.
    let left = period - now_secs() % period;
    std::thread::sleep(Duration::from_secs_f64(left + 0.3));
    let fresh = usage(&plane, ACME);
    assert_eq!(fresh["exceeded"], json!([]), "{fresh}");
    assert!(fresh["period"]["start"].as_u64() > used["period"]["start"].as_u64());
    assert_eq!(plane.sh(ACME, &a, "echo again")["stdout"], "again\n");
    let c = plane.create(ACME, json!({}));
    assert_eq!(plane.delete(ACME, &id_of(&c)), 204);
    assert_eq!(plane.sh(BETA, &y, "echo beta")["stdout"], "beta\n");
}

#[test]
fn the_memory_quota_is_exact_under_concurrent_creates() {
    // Each sandbox may use 512 MiB (the template's limit): three fit.
    let Some(plane) = Plane::start(PlaneOptions {
        acme_max: 20,
        acme_extra: json!({"max_memory_mb": 3 * 512 + 100}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let addr = plane.api_addr();
    let body = json!({"template": plane.template(ACME)}).to_string();
    let answers: Vec<(u16, String)> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..12)
            .map(|_| {
                let (addr, body) = (&addr, &body);
                scope.spawn(move || {
                    let r = common::api_call(addr, ACME, "POST", "/v1/sandboxes", body.as_bytes())
                        .unwrap();
                    let code = if r.status == 201 {
                        String::new()
                    } else {
                        r.code()
                    };
                    (r.status, code)
                })
            })
            .collect();
        threads.into_iter().map(|t| t.join().unwrap()).collect()
    });
    let made = answers.iter().filter(|(s, _)| *s == 201).count();
    assert_eq!(made, 3, "{answers:?}\n{}", plane.logs());
    assert!(answers
        .iter()
        .all(|(s, c)| *s == 201 || (*s == 429 && c == "memory_limit")));
    let u = usage(&plane, ACME);
    assert_eq!(u["sandboxes"], 3);
    assert_eq!(u["memory_limit_bytes"], 3 * (512u64 << 20));
    assert_eq!(u["quotas"]["max_memory_bytes"], (3 * 512 + 100u64) << 20);
    // One goes: one more fits.
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    let first = id_of(&list["sandboxes"][0]);
    assert_eq!(plane.delete(ACME, &first), 204);
    plane.create(ACME, json!({}));
    let r = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    assert_eq!((r.status, r.code().as_str()), (429, "memory_limit"));
}

#[test]
fn the_request_rate_is_limited_per_tenant() {
    let Some(plane) = Plane::start(PlaneOptions {
        acme_extra: json!({"requests_per_second": 2, "request_burst": 4}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let addr = plane.api_addr();
    let get = |token: &str| common::api_call(&addr, token, "GET", "/v1/templates", b"").unwrap();
    // Spend acme's burst.
    let mut refused = 0;
    for _ in 0..8 {
        if get(ACME).status == 429 {
            refused += 1;
        }
    }
    assert!(refused >= 3, "{refused} of 8 refused");
    let (status, head) = raw_call(&addr, ACME, "GET", "/v1/templates");
    assert_eq!(status, 429, "{head}");
    assert_eq!(header(&head, "retry-after").as_deref(), Some("1"));
    // beta is not slowed: every request answered, at once.
    for _ in 0..50 {
        let start = Instant::now();
        assert_eq!(get(BETA).status, 200);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    // Requests without a valid token take nothing from acme's bucket.
    std::thread::sleep(Duration::from_millis(2100));
    for token in ["", "nope", "acme-token-0123456789abcdef012345678X"] {
        for _ in 0..30 {
            assert_eq!(get(token).status, 401);
        }
    }
    for i in 0..4 {
        assert_eq!(get(ACME).status, 200, "request {i} after the refill");
    }
    assert_eq!(get(ACME).status, 429);
    let u = usage(&plane, BETA);
    assert_eq!(u["quotas"]["requests_per_second"], Value::Null);
}

/// The records of the usage log at `prefix`, of every file.
fn log_records(dir: &std::path::Path) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    files.sort();
    for file in files {
        for line in std::fs::read_to_string(&file).unwrap().lines() {
            out.push(serde_json::from_str(line).unwrap_or_else(|_| panic!("{file:?}: {line}")));
        }
    }
    out
}

#[test]
fn the_usage_log_records_what_ran_and_survives_a_restart() {
    let Some(mut plane) = Plane::start(PlaneOptions {
        acme_max: 4,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    // The log's directory does not exist yet: the API serves anyway.
    let dir = plane.dir.join("usage");
    plane.options.api_extra = json!({"metering": {"log": dir.join("usage"), "interval": 1}});
    plane.restart_api();
    let x = id_of(&plane.create(ACME, json!({})));
    let y = id_of(&plane.create(BETA, json!({})));
    plane.exec(ACME, &x, burn(0.5));
    let fetched = plane.exec(ACME, &x, fetch());
    assert_eq!(fetched["exit_code"], 0, "{fetched}");
    eventually(Duration::from_secs(10), "an error about the log", || {
        plane
            .api
            .as_ref()
            .unwrap()
            .log()
            .contains("usage log: cannot write")
    });
    let admin = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage")
        .json();
    assert_eq!(admin["log"]["healthy"], false, "{admin}");
    assert!(admin["log"]["backlog"].as_u64().unwrap() > 0);
    std::fs::create_dir_all(&dir).unwrap();
    eventually(Duration::from_secs(10), "the log written", || {
        plane
            .api
            .as_ref()
            .unwrap()
            .log()
            .contains("usage log: writing again")
    });
    assert_eq!(plane.delete(ACME, &x), 204);
    // A sandbox removed between two of its node's measurements (they are
    // a second apart) pays for what it used all the same: it is measured
    // once more as it is removed.
    let z = id_of(&plane.create(ACME, json!({})));
    plane.exec(ACME, &z, burn(0.6));
    assert_eq!(plane.delete(ACME, &z), 204);
    let finals = |records: &[Value], id: &str| {
        records
            .iter()
            .filter(|r| r["sandbox"] == id && r["kind"] == "final")
            .count()
    };
    eventually(Duration::from_secs(15), "x's final record", || {
        finals(&log_records(&dir), &x) == 1
    });
    eventually(Duration::from_secs(15), "z's final record", || {
        finals(&log_records(&dir), &z) == 1
    });
    let of_z = log_records(&dir)
        .into_iter()
        .rfind(|r| r["sandbox"] == z && r["kind"] == "final")
        .unwrap();
    assert!(of_z["total"]["cpu_ms"].as_u64().unwrap() >= 400, "{of_z}");
    // Let a record of y come too.
    std::thread::sleep(Duration::from_millis(1500));
    let records = log_records(&dir);
    let of_x: Vec<&Value> = records.iter().filter(|r| r["sandbox"] == x).collect();
    assert!(of_x
        .iter()
        .all(|r| r["tenant"] == "acme" && r["node"] == "node-1" && r["v"] == 1));
    let last = of_x.last().unwrap();
    assert_eq!(
        (last["kind"].as_str(), last["end"].as_str()),
        (Some("final"), Some("ended"))
    );
    // The deltas add up to the final counters (it was counted from zero).
    for counter in [
        "cpu_ms",
        "egress_sent_bytes",
        "egress_received_bytes",
        "memory_byte_seconds",
    ] {
        let sum: u64 = of_x
            .iter()
            .map(|r| r["delta"][counter].as_u64().unwrap())
            .sum();
        assert_eq!(
            sum,
            last["total"][counter].as_u64().unwrap(),
            "{counter}: {of_x:?}"
        );
    }
    let total = &last["total"];
    assert!(total["cpu_ms"].as_u64().unwrap() >= 300, "{total}");
    assert!(total["egress_sent_bytes"].as_u64().unwrap() > 0, "{total}");
    assert!(total["egress_received_bytes"].as_u64().unwrap() > common::WEB_BODY.len() as u64);
    assert!(
        total["memory_byte_seconds"].as_u64().unwrap() > 0,
        "{total}"
    );
    assert!(total["run_ms"].as_u64().unwrap() > 0);
    assert!(records
        .iter()
        .filter(|r| r["sandbox"] == y)
        .all(|r| r["tenant"] == "beta"));
    assert!(records
        .iter()
        .any(|r| r["sandbox"] == y && r["kind"] == "usage"));

    // The API restarts mid-period: the totals are what the log says, and
    // what ran before is not counted again.
    let acme_before = usage(&plane, ACME)["usage"].clone();
    let beta_before = usage(&plane, BETA)["usage"].clone();
    assert_eq!(
        acme_before["cpu_ms"].as_u64().unwrap(),
        total["cpu_ms"].as_u64().unwrap() + of_z["total"]["cpu_ms"].as_u64().unwrap(),
        "acme's sandboxes were x and z"
    );
    plane.restart_api();
    std::thread::sleep(Duration::from_millis(1500));
    let acme_after = usage(&plane, ACME)["usage"].clone();
    let beta_after = usage(&plane, BETA)["usage"].clone();
    for counter in [
        "cpu_ms",
        "egress_sent_bytes",
        "egress_received_bytes",
        "run_ms",
    ] {
        assert_eq!(acme_after[counter], acme_before[counter], "{counter}");
    }
    let (b0, b1) = (
        beta_before["cpu_ms"].as_u64().unwrap(),
        beta_after["cpu_ms"].as_u64().unwrap(),
    );
    assert!(b1 >= b0 && b1 <= b0 + 2000, "beta's cpu {b0} -> {b1}");
    let (r0, r1) = (
        beta_before["run_ms"].as_u64().unwrap(),
        beta_after["run_ms"].as_u64().unwrap(),
    );
    assert!(r1 > r0 && r1 < r0 + 30_000, "beta's run time {r0} -> {r1}");
    assert_eq!(finals(&log_records(&dir), &x), 1, "x ended once");
    let admin = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage")
        .json();
    assert_eq!(admin["tenants"].as_array().unwrap().len(), 2);
    assert_eq!(admin["log"]["healthy"], true);
    let one = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage/beta")
        .json();
    assert_eq!(one["tenant"], "beta");
    assert_eq!(
        plane
            .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage/nobody")
            .status,
        404
    );
    // A tenant cannot reach the admin view.
    assert_eq!(plane.call(ACME, "GET", "/admin/v1/usage", b"").status, 404);
}

/// A fake node whose list reports nonsense usage: its answers change with
/// every list asked (`step`).
fn nonsense_node(name: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let step = Arc::new(AtomicU64::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let step = Arc::clone(&step);
            std::thread::spawn(move || nonsense_answer(&mut stream, name, &step));
        }
    });
    addr
}

const S: &str = "sb-11111111111111111111111111111111";
const T: &str = "sb-22222222222222222222222222222222";
const U: &str = "sb-33333333333333333333333333333333";

fn nonsense_answer(stream: &mut TcpStream, name: &str, step: &AtomicU64) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let target = head.split(' ').nth(1).unwrap_or("").to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let body = if target == "/v1/node" {
        json!({
            "node": name,
            "templates": [{"name": "python", "ready": true, "starts": 1, "tenant": null, "pid": 1}],
            "sandboxes": 2, "creating": 0, "max_sandboxes": 8,
            "memory_bytes": 0, "memory_limit_bytes": 1u64 << 30,
            // Draining: it gets no sandbox of the test's.
            "draining": true, "cpus": 1,
        })
    } else if target.starts_with("/v1/sandboxes?ended_after=") {
        let n = step.fetch_add(1, Ordering::SeqCst);
        // S: sense, then absurd, then backwards, then on from the absurd.
        let cpu = match n {
            0 => 1000,
            1 => 1u64 << 52,
            2 => 5,
            _ => (1u64 << 52) + 1000,
        };
        let sent = if n == 1 { u64::MAX } else { 10 };
        let sandbox = |id: &str, tenant: &str, cpu: u64, sent: u64| {
            json!({
                "id": id, "tenant": tenant, "template": "python", "node": name,
                "egress_id": "1111111111111111", "created_at": now, "last_used_at": now,
                "expires_at": now + 3_600_000, "idle_timeout": 600.0, "memory_bytes": 1,
                "memory_limit_bytes": 1, "ready_ms": 1.0,
                "usage": {"run_ms": 1000, "cpu_ms": cpu, "memory_byte_seconds": 1,
                          "egress_sent_bytes": sent, "egress_received_bytes": 0},
            })
        };
        // T is beta's, then claimed for acme.
        let t = if n == 0 {
            sandbox(T, "beta", 7, 0)
        } else {
            sandbox(T, "acme", 99_999, 0)
        };
        json!({
            "sandboxes": [sandbox(S, "acme", cpu, sent), t],
            // U ended: listed every time with the same seq, counted once.
            "ended": [{"id": U, "tenant": "beta", "template": "python", "seq": 1,
                       "created_at": now, "ended_at": now,
                       "memory_limit_bytes": 1,
                       "usage": {"run_ms": 500, "cpu_ms": 3, "memory_byte_seconds": 0,
                                 "egress_sent_bytes": 0, "egress_received_bytes": 0}}],
            "boot": 42,
        })
    } else if target.starts_with("/v1/sandboxes") {
        json!({"sandboxes": []})
    } else {
        json!({"error": {"code": "nope", "message": "nope"}})
    };
    let body = body.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// A fake node that "restarts" after its second list: its `boot` changes
/// and its numbering of ended sandboxes starts again at 1. Before, one
/// sandbox of beta ended as seq 5 (2 ms of CPU); after, another as seq 1
/// (3 ms), listed only to `ended_after=0`.
fn restarting_node(name: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let lists = Arc::new(AtomicU64::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let lists = Arc::clone(&lists);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let target = head.split(' ').nth(1).unwrap_or("").to_string();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let ended = |id: &str, seq: u64, cpu: u64| {
                    json!({"id": id, "tenant": "beta", "template": "python", "seq": seq,
                           "created_at": now, "ended_at": now, "memory_limit_bytes": 1,
                           "usage": {"run_ms": 1, "cpu_ms": cpu, "memory_byte_seconds": 0,
                                     "egress_sent_bytes": 0, "egress_received_bytes": 0}})
                };
                let body = if target == "/v1/node" {
                    json!({
                        "node": name, "templates": [], "sandboxes": 0, "creating": 0,
                        "max_sandboxes": 8, "memory_bytes": 0, "memory_limit_bytes": 1u64 << 30,
                        "draining": true, "cpus": 1,
                    })
                } else if let Some(after) = target.strip_prefix("/v1/sandboxes?ended_after=") {
                    if lists.fetch_add(1, Ordering::SeqCst) < 2 {
                        json!({"sandboxes": [], "ended": [ended(U, 5, 2)], "boot": 1})
                    } else if after == "0" {
                        json!({"sandboxes": [], "ended": [ended(T, 1, 3)], "boot": 2})
                    } else {
                        json!({"sandboxes": [], "ended": [], "boot": 2})
                    }
                } else {
                    json!({"sandboxes": []})
                };
                let body = body.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    addr
}

#[test]
fn a_node_that_restarts_is_asked_from_its_first_ended_sandbox() {
    let Some(plane) = Plane::start(PlaneOptions {
        extra_nodes: vec![("fake-restart".into(), restarting_node("fake-restart"))],
        ..PlaneOptions::default()
    }) else {
        return;
    };
    eventually(
        Duration::from_secs(10),
        "both ended sandboxes counted",
        || usage(&plane, BETA)["usage"]["cpu_ms"] == 5,
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(usage(&plane, BETA)["usage"]["cpu_ms"], 5, "each once");
}

#[test]
fn absurd_and_decreasing_counters_are_bounded() {
    let Some(plane) = Plane::start(PlaneOptions {
        extra_nodes: vec![("fake-usage".into(), nonsense_node("fake-usage"))],
        ..PlaneOptions::default()
    }) else {
        return;
    };
    assert_eq!(admin_state(&plane, "fake-usage"), "draining");
    // Many probes: every step of the fake, and more.
    std::thread::sleep(Duration::from_secs(4));
    let acme = usage(&plane, ACME)["usage"].clone();
    let beta = usage(&plane, BETA)["usage"].clone();
    // S: 1 s, then at most what one CPU can do in a probe's time plus the
    // slack (30 s), then nothing for going back, then 1 s more.
    let cpu = acme["cpu_ms"].as_u64().unwrap();
    assert!((2000..=40_000).contains(&cpu), "{acme}");
    // Egress past a JSON number's exact range, bounded by 100 Gbit/s.
    let sent = acme["egress_sent_bytes"].as_u64().unwrap();
    assert!((10..1 << 40).contains(&sent), "{acme}");
    // beta: T's first report and U once; T claimed for acme counts nowhere.
    assert_eq!(beta["cpu_ms"], 10, "{beta}");
    let admin = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage")
        .json();
    assert!(admin["odd_reports"].as_u64().unwrap() >= 3, "{admin}");
    assert_eq!(
        admin_state(&plane, "fake-usage"),
        "draining",
        "a node is not dropped for it"
    );
    // The API is fine.
    let s = plane.create(ACME, json!({}));
    assert_eq!(node_of(&s), "node-1");
}

#[test]
fn a_delete_on_an_unreachable_node_is_done_when_it_is_back() {
    let Some(mut plane) = Plane::start(PlaneOptions {
        nodes: 2,
        acme_max: 2,
        // Everything goes to node-2 until node-1 is undrained.
        node_extra: vec![json!({"start_drained": true})],
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let dir = plane.dir.join("usage");
    std::fs::create_dir_all(&dir).unwrap();
    plane.options.api_extra = json!({"metering": {"log": dir.join("usage"), "interval": 1}});
    plane.restart_api();
    let s1 = plane.create(ACME, json!({}));
    let s2 = plane.create(ACME, json!({}));
    assert_eq!(
        (node_of(&s1), node_of(&s2)),
        ("node-2".into(), "node-2".into())
    );
    let (s1, s2) = (id_of(&s1), id_of(&s2));
    // s1 keeps a CPU busy from now on, also after its delete.
    let r = plane.sh(
        ACME,
        &s1,
        "nohup python3 -c 'while True: pass' >/dev/null 2>&1 &",
    );
    assert_eq!(r["exit_code"], 0, "{r}");
    std::thread::sleep(Duration::from_secs(2));

    plane.stop_node(1);
    eventually(Duration::from_secs(20), "node-2 unreachable", || {
        admin_state(&plane, "node-2") == "unreachable"
    });
    // Accepted: gone for the tenant at once, and its slot free.
    assert_eq!(plane.delete(ACME, &s1), 202);
    let cpu_at_delete = usage(&plane, ACME)["usage"]["cpu_ms"].as_u64().unwrap();
    assert!(cpu_at_delete > 0);
    // What it burns while its node does not answer is not charged.
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(
        plane
            .call(ACME, "GET", &format!("/v1/sandboxes/{s1}"), b"")
            .status,
        404
    );
    assert_eq!(plane.delete(ACME, &s1), 404);
    assert_eq!(usage(&plane, ACME)["sandboxes"], 1);
    let r = plane.call(ACME, "POST", "/admin/v1/nodes/node-1/undrain", b"");
    assert_eq!(r.status, 404, "not on the tenants' listener");
    assert_eq!(
        plane
            .admin_call(ADMIN_TOKEN, "POST", "/admin/v1/nodes/node-1/undrain")
            .status,
        200
    );
    let s3 = plane.create(ACME, json!({}));
    assert_eq!(node_of(&s3), "node-1");
    let s3 = id_of(&s3);
    let r = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    assert_eq!(r.code(), "tenant_limit", "s2 still counts");
    // Another tenant cannot delete it, nor learn of it.
    assert_eq!(plane.delete(BETA, &s2), 404);

    // The API restarts while node-2 is still stopped: the delete to do is
    // read back from the usage log.
    plane.restart_api();
    let admin = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage")
        .json();
    assert_eq!(admin["deletes_waiting"], 1, "{admin}");

    plane.cont_node(1);
    eventually(Duration::from_secs(20), "node-2 back", || {
        admin_state(&plane, "node-2") == "healthy"
    });
    eventually(Duration::from_secs(10), "s1 deleted on node-2", || {
        let list = plane.node_call_at(1, "GET", "/v1/sandboxes").json();
        let ids: Vec<String> = list["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(id_of)
            .collect();
        !ids.contains(&s1) && ids.contains(&s2)
    });
    // It never comes back, nor counts again.
    for _ in 0..10 {
        let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
        let mut ids: Vec<String> = list["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(id_of)
            .collect();
        ids.sort();
        let mut want = vec![s2.clone(), s3.clone()];
        want.sort();
        assert_eq!(ids, want);
        assert_eq!(usage(&plane, ACME)["sandboxes"], 2);
        std::thread::sleep(Duration::from_millis(200));
    }
    let admin = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/usage")
        .json();
    assert_eq!(admin["deletes_waiting"], 0, "{admin}");
    // Its final record is in, and none of what it burned after its delete
    // (seconds of CPU) was charged: s2 and s3 were idle, a fraction of a
    // second at most.
    eventually(Duration::from_secs(15), "s1's final record", || {
        log_records(&dir)
            .iter()
            .any(|r| r["sandbox"] == s1 && r["kind"] == "final")
    });
    let cpu = usage(&plane, ACME)["usage"]["cpu_ms"].as_u64().unwrap();
    assert!(
        cpu < cpu_at_delete + 1500,
        "charged {} ms of CPU after the delete",
        cpu - cpu_at_delete
    );
    let after: u64 = log_records(&dir)
        .iter()
        .filter(|r| r["sandbox"] == s1 && r["ts"].as_u64() > Some(0))
        .skip_while(|r| r["kind"] != "delete_pending")
        .map(|r| r["delta"]["cpu_ms"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(after, 0, "records of s1 after its delete charge CPU");
    assert!(plane
        .api
        .as_ref()
        .unwrap()
        .log()
        .contains("the delete that waited for node node-2 is done"));
    let records = log_records(&dir);
    for kind in ["delete_pending", "delete_done"] {
        assert!(
            records
                .iter()
                .any(|r| r["sandbox"] == s1 && r["kind"] == kind),
            "{kind}"
        );
    }
    assert_eq!(plane.sh(ACME, &s2, "echo ok")["stdout"], "ok\n");
}

#[test]
fn a_node_configured_to_start_drained_stays_drained_across_restarts() {
    let Some(mut plane) = Plane::start(PlaneOptions {
        nodes: 2,
        node_extra: vec![json!({}), json!({"start_drained": true})],
        ..PlaneOptions::default()
    }) else {
        return;
    };
    assert_eq!(admin_state(&plane, "node-2"), "draining");
    assert_eq!(
        plane.node_call_at(1, "GET", "/v1/node").json()["draining"],
        true
    );
    for _ in 0..3 {
        let s = plane.create(ACME, json!({}));
        assert_eq!(node_of(&s), "node-1");
        assert_eq!(plane.delete(ACME, &id_of(&s)), 204);
    }
    assert_eq!(
        plane
            .admin_call(ADMIN_TOKEN, "POST", "/admin/v1/nodes/node-2/undrain")
            .status,
        200
    );
    assert_eq!(admin_state(&plane, "node-2"), "healthy");
    // Restarted, it is drained again.
    plane.kill_node(1);
    plane.start_node(1);
    plane.wait_templates_at(1, 1);
    eventually(Duration::from_secs(20), "node-2 drained again", || {
        admin_state(&plane, "node-2") == "draining"
    });
    assert!(plane.nodes[1]
        .service
        .as_ref()
        .unwrap()
        .log()
        .contains("draining=true (start_drained)"));
}

/// `metering.period: "month"`: UTC calendar months, for the usage
/// answers, `Retry-After`, the log's file names, and the totals read back
/// after a restart.
#[test]
fn calendar_month_periods() {
    let Some(mut plane) = Plane::start(PlaneOptions {
        beta_extra: json!({"cpu_seconds_per_period": 0}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let dir = plane.dir.join("usage");
    std::fs::create_dir_all(&dir).unwrap();
    plane.options.api_extra =
        json!({"metering": {"period": "month", "log": dir.join("usage"), "interval": 1}});
    plane.restart_api();
    let u = usage(&plane, ACME);
    let (start, end) = (
        u["period"]["start"].as_u64().unwrap() / 1000,
        u["period"]["end"].as_u64().unwrap() / 1000,
    );
    let now = now_secs() as u64;
    assert!(start <= now && now < end, "{u}");
    let (y, m, d) = civil(start);
    assert_eq!((d, start % 86400), (1, 0), "{u}");
    let (y2, m2, d2) = civil(end);
    assert_eq!((d2, end % 86400), (1, 0));
    assert_eq!((y2, m2), if m == 12 { (y + 1, 1) } else { (y, m + 1) });
    assert_eq!(u["period"]["seconds"].as_u64().unwrap(), end - start);
    // A budget of the month: Retry-After is the month's end.
    let body = json!({"template": plane.template(BETA)}).to_string();
    let mut conn = TcpStream::connect(plane.api_addr()).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        conn,
        "POST /v1/sandboxes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {BETA}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut answer = String::new();
    let _ = conn.read_to_string(&mut answer);
    assert!(answer.contains("budget_exceeded"), "{answer}");
    let wait: u64 = header(&answer, "retry-after").unwrap().parse().unwrap();
    let left = end - now_secs() as u64;
    assert!(
        wait.abs_diff(left) <= 5,
        "Retry-After {wait}, {left} s left"
    );
    // Usage goes to the month's file and is read back after a restart.
    let s = id_of(&plane.create(ACME, json!({})));
    plane.exec(ACME, &s, burn(0.5));
    let file = dir.join(format!("usage.{y:04}{m:02}01T000000Z.jsonl"));
    eventually(Duration::from_secs(15), "the month's log file", || {
        std::fs::read_to_string(&file).is_ok_and(|t| t.contains("cpu_ms"))
    });
    std::thread::sleep(Duration::from_secs(2));
    let before = usage(&plane, ACME)["usage"]["cpu_ms"].as_u64().unwrap();
    assert!(before > 0);
    plane.restart_api();
    let after = usage(&plane, ACME)["usage"]["cpu_ms"].as_u64().unwrap();
    assert!(
        after >= before && after < before + 1000,
        "{before} then {after}"
    );
}

/// (year, month, day) of a Unix time (UTC).
fn civil(unix_secs: u64) -> (i64, i64, i64) {
    let z = (unix_secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}
