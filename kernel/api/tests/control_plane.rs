//! The control plane end to end (README, "Control plane"): a client of
//! `hellovm-api` creates sandboxes cloned from the warm CPython template
//! `hellovm-noded` keeps, runs commands and Python in them, reads, writes
//! and edits files, and cannot reach another tenant's sandboxes; idle
//! timeouts, lifetimes, memory and tenant limits, egress through the proxy,
//! and restarts of the template, of noded and of the API.

#![cfg(target_os = "linux")]

mod common;

use std::time::{Duration, Instant};

use common::{ms, stats, Plane, PlaneOptions, ACME, BETA, WEB_BODY};
use serde_json::{json, Value};

fn id_of(sandbox: &Value) -> String {
    sandbox["id"].as_str().unwrap().to_string()
}

/// Waits until `check` holds, or fails after `limit` with `what`.
fn eventually(limit: Duration, what: &str, mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < limit, "{what} after {limit:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn sandboxes_through_the_api() {
    let Some(plane) = Plane::start(PlaneOptions::default()) else {
        return;
    };

    // Authentication.
    assert_eq!(plane.call("", "GET", "/v1/sandboxes", b"").status, 401);
    assert_eq!(
        plane
            .call(
                "acme-token-wrong-0123456789abcdef",
                "GET",
                "/v1/sandboxes",
                b""
            )
            .status,
        401
    );
    let templates = plane.call(ACME, "GET", "/v1/templates", b"").json();
    assert!(
        templates["templates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "python" && t["ready"] == json!(true)),
        "{templates}"
    );
    // Nothing of the node's insides (process ids, restarts).
    assert!(
        templates["templates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t.as_object().unwrap().len() == 2),
        "{templates}"
    );

    // Create: request to ready (the agent in the clone answered).
    let started = Instant::now();
    let sandbox = plane.create(ACME, json!({}));
    let create_ms = ms(started);
    let id = id_of(&sandbox);
    assert!(id.starts_with("sb-") && id.len() == 35, "{id}");
    assert_eq!(sandbox["tenant"], "acme");
    assert_eq!(sandbox["egress_id"].as_str().unwrap(), &id[3..19]);
    eprintln!(
        "MEASURE create (debug build): {create_ms:.1} ms through the API, {:.1} ms on the node",
        sandbox["ready_ms"].as_f64().unwrap()
    );

    // exec: stdout, stderr and the exit code.
    let started = Instant::now();
    let r = plane.sh(ACME, &id, "echo hello; echo oops >&2; exit 3");
    eprintln!("MEASURE first exec (debug build): {:.1} ms", ms(started));
    assert_eq!(r["exit_code"], 3, "{r}");
    assert_eq!(r["stdout"], "hello\n");
    assert_eq!(r["stderr"], "oops\n");
    assert_eq!(r["timed_out"], false);
    assert_eq!(r["signal"], Value::Null);

    // State between execs: files and background processes stay; the
    // shell's own state (cwd, variables) does not.
    plane.sh(
        ACME,
        &id,
        "echo kept > state.txt; cd /tmp; X=1; (sleep 1000 >/dev/null 2>&1 &)",
    );
    let r = plane.sh(ACME, &id, "cat state.txt; pwd; echo \"x=$X\"");
    assert_eq!(r["stdout"], "kept\n/home/sandbox\nx=\n", "{r}");
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import os\nprint(sum(open(f'/proc/{p}/comm').read() == 'sleep\\n' for p in os.listdir('/proc') if p.isdigit()))"}),
    );
    assert_eq!(r["stdout"], "1\n", "the background sleep still runs: {r}");

    // Python in the warm interpreter: the template's modules are loaded.
    let started = Instant::now();
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import sys\nprint('sqlite3' in sys.modules, 6 * 7)"}),
    );
    eprintln!("MEASURE python exec (debug build): {:.1} ms", ms(started));
    assert_eq!(r["stdout"], "True 42\n", "{r}");
    let r = plane.exec(ACME, &id, json!({"python": "raise SystemExit(5)"}));
    assert_eq!(r["exit_code"], 5);
    let r = plane.exec(ACME, &id, json!({"python": "1/0"}));
    assert_eq!(r["exit_code"], 1);
    assert!(
        r["stderr"].as_str().unwrap().contains("ZeroDivisionError"),
        "{r}"
    );

    // stdin, cwd and env.
    let r = plane.exec(
        ACME,
        &id,
        json!({"command": "cat; pwd; echo $GREETING", "stdin": "in\n", "cwd": "/tmp",
               "env": {"GREETING": "hi"}}),
    );
    assert_eq!(r["stdout"], "in\n/tmp\nhi\n", "{r}");

    // A timeout kills the command (and what it started) and says so.
    let started = Instant::now();
    let r = plane.exec(
        ACME,
        &id,
        json!({"command": "sleep 60 & sleep 60", "timeout": 0.5}),
    );
    assert_eq!(r["timed_out"], true, "{r}");
    assert_eq!(r["signal"], 9);
    assert!(started.elapsed() < Duration::from_secs(15));

    // Long output keeps its start and end, with a marker in between.
    let r = plane.exec(
        ACME,
        &id,
        json!({"command": "seq 1 200000", "max_output": 1000}),
    );
    let out = r["stdout"].as_str().unwrap();
    assert_eq!(r["stdout_truncated"], true);
    assert_eq!(r["stdout_bytes"], 1288895);
    assert!(out.starts_with("1\n2\n3\n"), "{out}");
    assert!(out.ends_with("199999\n200000\n"), "{out}");
    assert!(out.contains("bytes omitted ...]"), "{out}");
    assert!(out.len() < 1100);

    // Files: write, read, edit.
    let path = "/v1/sandboxes/ID/files?path=notes/a.txt".replace("ID", &id);
    let w = plane.call(ACME, "PUT", &path, b"hello world\nbye world\n");
    assert_eq!(w.status, 200, "{}", String::from_utf8_lossy(&w.body));
    assert_eq!(w.json()["bytes"], 22);
    let r = plane.call(ACME, "GET", &path, b"");
    assert_eq!(r.body, b"hello world\nbye world\n");
    let edit = |old: &str, new: &str, all: bool| {
        plane.call_json(
            ACME,
            "POST",
            &format!("/v1/sandboxes/{id}/files/edit"),
            json!({"path": "/home/sandbox/notes/a.txt", "old": old, "new": new, "replace_all": all}),
        )
    };
    let ambiguous = edit("world", "there", false);
    assert_eq!(
        (ambiguous.status, ambiguous.code().as_str()),
        (422, "ambiguous")
    );
    assert_eq!(
        edit("hello world", "hello there", false).json()["replacements"],
        1
    );
    assert_eq!(edit("world", "moon", true).json()["replacements"], 1);
    let missing_text = edit("absent", "x", false);
    assert_eq!(
        (missing_text.status, missing_text.code().as_str()),
        (422, "no_match")
    );
    let r = plane.sh(ACME, &id, "cat notes/a.txt");
    assert_eq!(r["stdout"], "hello there\nbye moon\n");
    let missing = plane.call(ACME, "GET", &path.replace("a.txt", "nope"), b"");
    assert_eq!(
        (missing.status, missing.code().as_str()),
        (404, "not_found")
    );
    let dir = plane.call(ACME, "GET", &path.replace("notes/a.txt", "notes"), b"");
    assert_eq!((dir.status, dir.code().as_str()), (400, "is_directory"));
    // Binary data, 1 MiB each way.
    let blob: Vec<u8> = (0..1u32 << 20)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let started = Instant::now();
    let w = plane.call(ACME, "PUT", &path.replace("a.txt", "blob"), &blob);
    assert_eq!(w.status, 200);
    let r = plane.call(ACME, "GET", &path.replace("a.txt", "blob"), b"");
    eprintln!(
        "MEASURE 1 MiB write + read (debug build): {:.1} ms",
        ms(started)
    );
    assert!(r.body == blob, "the blob came back different");
    // The writable layer's limit (256 MiB here) holds.
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import errno\ntry:\n    with open('/tmp/huge', 'wb') as f:\n        for _ in range(300):\n            f.write(b'x' * (1 << 20))\nexcept OSError as e:\n    print(errno.errorcode[e.errno])", "timeout": 60}),
    );
    assert_eq!(r["stdout"], "ENOSPC\n", "{r}");
    // With the layer full, a write or an edit that does not fit fails and
    // leaves the file it was to replace as it was (and no temporary file).
    let keep = format!("/v1/sandboxes/{id}/files?path=/tmp/keep/k.txt");
    plane.sh(ACME, &id, "rm -f /tmp/huge; mkdir /tmp/keep");
    assert_eq!(plane.call(ACME, "PUT", &keep, b"precious").status, 200);
    plane.exec(
        ACME,
        &id,
        json!({"python": "try:\n    with open('/tmp/huge', 'wb') as f:\n        for _ in range(300):\n            f.write(b'x' * (1 << 20))\nexcept OSError:\n    pass", "timeout": 60}),
    );
    let big = vec![b'y'; 4 << 20];
    let r = plane.call(ACME, "PUT", &keep, &big);
    assert_eq!((r.status, r.code().as_str()), (507, "no_space"));
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/files/edit"),
        json!({"path": "/tmp/keep/k.txt", "old": "precious", "new": "z".repeat(3 << 20)}),
    );
    assert_eq!((r.status, r.code().as_str()), (507, "no_space"));
    assert_eq!(plane.call(ACME, "GET", &keep, b"").body, b"precious");
    assert_eq!(plane.sh(ACME, &id, "ls -A /tmp/keep")["stdout"], "k.txt\n");
    plane.sh(ACME, &id, "rm -f /tmp/huge");
    // An edit keeps the file's mode and goes through a symbolic link.
    plane.sh(
        ACME,
        &id,
        "chmod 750 /tmp/keep/k.txt; ln -s k.txt /tmp/keep/link",
    );
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/files/edit"),
        json!({"path": "/tmp/keep/link", "old": "precious", "new": "edited"}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = plane.sh(
        ACME,
        &id,
        "cd /tmp/keep; cat k.txt; stat -c ' %a' k.txt; test -L link && echo link",
    );
    assert_eq!(r["stdout"], "edited 750\nlink\n", "{r}");
    // A Python run with a timeout too short for it to start is killed
    // like any other, and the sandbox goes on.
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import time\ntime.sleep(30)", "timeout": 0.0005}),
    );
    assert_eq!(r["timed_out"], json!(true), "{r}");
    assert_eq!(
        plane.sh(ACME, &id, "echo still here")["stdout"],
        "still here\n"
    );

    // Egress: through the proxy, named by the sandbox's egress id.
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import urllib.request\nprint(urllib.request.urlopen('http://web.test/', timeout=20).read().decode())", "timeout": 30}),
    );
    assert_eq!(r["stdout"], format!("{WEB_BODY}\n"), "{r}");
    let egress_id = sandbox["egress_id"].as_str().unwrap();
    eventually(Duration::from_secs(10), "no audit line", || {
        plane.audit.lines().iter().any(|l| {
            l.contains(&format!("sandbox={egress_id}"))
                && l.contains("host=web.test")
                && l.contains("verdict=allow")
        })
    });
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "import urllib.request\ntry:\n    urllib.request.urlopen('http://example.com/', timeout=20)\nexcept Exception as e:\n    print('refused')", "timeout": 30}),
    );
    assert_eq!(r["stdout"], "refused\n", "{r}");

    // One request at a time per sandbox.
    let slow = {
        let (addr, target) = (plane.api_addr(), format!("/v1/sandboxes/{id}/exec"));
        std::thread::spawn(move || {
            common::api_call(&addr, ACME, "POST", &target, br#"{"command": "sleep 2"}"#).unwrap()
        })
    };
    let busy = {
        std::thread::sleep(Duration::from_millis(700));
        let second = plane.call_json(
            ACME,
            "POST",
            &format!("/v1/sandboxes/{id}/exec"),
            json!({"command": "true"}),
        );
        assert_eq!(slow.join().unwrap().status, 200);
        second
    };
    assert_eq!((busy.status, busy.code().as_str()), (409, "busy"));

    // Tenants: beta sees none of acme's sandboxes and cannot touch them.
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    assert_eq!(list["sandboxes"].as_array().unwrap().len(), 1);
    assert_eq!(list["sandboxes"][0]["id"], id.as_str());
    let list = plane.call(BETA, "GET", "/v1/sandboxes", b"").json();
    assert_eq!(list["sandboxes"].as_array().unwrap().len(), 0);
    for (method, target, body) in [
        ("GET", format!("/v1/sandboxes/{id}"), json!(null)),
        (
            "POST",
            format!("/v1/sandboxes/{id}/exec"),
            json!({"command": "true"}),
        ),
        (
            "GET",
            format!("/v1/sandboxes/{id}/files?path=state.txt"),
            json!(null),
        ),
        (
            "PUT",
            format!("/v1/sandboxes/{id}/files?path=x"),
            json!(null),
        ),
        (
            "POST",
            format!("/v1/sandboxes/{id}/files/edit"),
            json!({"path": "state.txt", "old": "k", "new": "j"}),
        ),
        ("DELETE", format!("/v1/sandboxes/{id}"), json!(null)),
    ] {
        let r = plane.call_json(BETA, method, &target, body);
        assert_eq!(
            (r.status, r.code().as_str()),
            (404, "sandbox_not_found"),
            "{method} {target}"
        );
    }
    // A made-up id is just as missing.
    let last = if id.ends_with('0') { '1' } else { '0' };
    let guess = format!("{}{last}", &id[..34]);
    assert_eq!(
        plane
            .call(ACME, "GET", &format!("/v1/sandboxes/{guess}"), b"")
            .status,
        404
    );
    assert_eq!(plane.sh(ACME, &id, "cat state.txt")["stdout"], "kept\n");
    let other = plane.create(BETA, json!({}));
    assert_ne!(id_of(&other), id);
    assert_eq!(
        plane.sh(
            BETA,
            &id_of(&other),
            "cat /home/sandbox/state.txt 2>&1; echo $?"
        )["stdout"],
        "cat: /home/sandbox/state.txt: No such file or directory\n1\n"
    );

    // The tenant limit (acme: 3 at once).
    let two = plane.create(ACME, json!({}));
    let three = plane.create(ACME, json!({}));
    let four = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    assert_eq!((four.status, four.code().as_str()), (429, "tenant_limit"));
    assert_eq!(plane.delete(ACME, &id_of(&three)), 204);
    let three = plane.create(ACME, json!({}));

    // Delete.
    assert_eq!(plane.delete(ACME, &id_of(&two)), 204);
    let gone = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{}/exec", id_of(&two)),
        json!({"command": "true"}),
    );
    assert_eq!(gone.status, 404);
    assert_eq!(plane.delete(ACME, &id_of(&two)), 404);

    // Unknown templates and malformed requests.
    let r = plane.call_json(ACME, "POST", "/v1/sandboxes", json!({"template": "nope"}));
    assert_eq!(r.status, 404);
    let r = plane.call(ACME, "POST", "/v1/sandboxes", b"{not json");
    assert_eq!(r.status, 400);
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/exec"),
        json!({"command": "x", "timeout": -1}),
    );
    assert_eq!(r.status, 400);
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/exec"),
        json!({"command": "x", "python": "y"}),
    );
    assert_eq!(r.status, 400);

    // Each sandbox's memory is measured.
    let info = plane
        .call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"")
        .json();
    let memory = info["memory_bytes"].as_u64().unwrap();
    eprintln!("MEASURE memory of a used sandbox: {} MiB", memory >> 20);
    assert!(memory > 0 && memory < 512 << 20, "{info}");

    for sandbox in [&id, &id_of(&three), &id_of(&other)] {
        let token = if *sandbox == id_of(&other) {
            BETA
        } else {
            ACME
        };
        assert_eq!(plane.delete(token, sandbox), 204);
    }
    assert_eq!(plane.node_call("GET", "/v1/node").json()["sandboxes"], 0);
}

#[test]
fn idle_lifetime_and_memory_limits_remove_sandboxes() {
    let Some(plane) = Plane::start(PlaneOptions {
        memory_limit_mb: 300,
        max_processes: 40,
        acme_max: 8,
    }) else {
        return;
    };
    let gone = |id: &str| {
        let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"");
        matches!(r.status, 404 | 410)
    };

    // Idle: no request for a second.
    let idle = id_of(&plane.create(ACME, json!({"idle_timeout": 1.0})));
    // Kept alive by requests, but only for its lifetime.
    let old = id_of(&plane.create(ACME, json!({"lifetime": 3.0})));
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        plane.sh(ACME, &old, "true");
        std::thread::sleep(Duration::from_millis(200));
    }
    eventually(
        Duration::from_secs(10),
        "the idle sandbox is still there",
        || gone(&idle),
    );
    assert!(!gone(&old));
    eventually(
        Duration::from_secs(10),
        "the old sandbox is still there",
        || gone(&old),
    );

    // An exec that runs longer than the idle timeout is not idle.
    let busy = id_of(&plane.create(ACME, json!({"idle_timeout": 1.0})));
    let r = plane.sh(ACME, &busy, "sleep 2.5; echo done");
    assert_eq!(r["stdout"], "done\n");

    // Memory: past the limit (300 MiB here) the sandbox is removed.
    let hog = id_of(&plane.create(ACME, json!({})));
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{hog}/exec"),
        json!({"python": "import time\nx = b'x' * (400 << 20)\ntime.sleep(30)", "timeout": 60}),
    );
    assert!(
        matches!(r.status, 410 | 502),
        "{} {}",
        r.status,
        String::from_utf8_lossy(&r.body)
    );
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert!(text.contains("memory"), "{text}");
    assert!(gone(&hog));
    // Others are untouched.
    assert_eq!(plane.sh(ACME, &busy, "echo ok")["stdout"], "ok\n");
    // The reason is still told after the API has reconciled with the node
    // (every two seconds) and dropped the sandbox from what runs.
    std::thread::sleep(Duration::from_secs(5));
    let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{hog}"), b"");
    assert_eq!((r.status, r.code().as_str()), (410, "sandbox_ended"));
    assert!(String::from_utf8_lossy(&r.body).contains("memory"));
    // Another tenant learns nothing of it.
    let r = plane.call(BETA, "GET", &format!("/v1/sandboxes/{hog}"), b"");
    assert_eq!(r.status, 404);

    // Processes: more than the limit (40 here) and the sandbox is removed.
    let forker = id_of(&plane.create(ACME, json!({})));
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{forker}/exec"),
        json!({"command": "for i in $(seq 60); do sleep 60 & done; sleep 30", "timeout": 60}),
    );
    assert!(
        matches!(r.status, 410 | 502),
        "{} {}",
        r.status,
        String::from_utf8_lossy(&r.body)
    );
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert!(text.contains("processes"), "{text}");
    assert!(gone(&forker));
}

#[test]
fn restarts_of_the_template_noded_and_api() {
    let Some(mut plane) = Plane::start(PlaneOptions::default()) else {
        return;
    };
    let sockets = plane.dir.join("state/templates");

    // The API restarts: sandboxes keep running and are found again.
    let first = id_of(&plane.create(ACME, json!({})));
    plane.sh(ACME, &first, "echo before > /home/sandbox/mark");
    plane.restart_api();
    assert_eq!(
        plane.sh(ACME, &first, "cat /home/sandbox/mark")["stdout"],
        "before\n"
    );
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    assert_eq!(list["sandboxes"].as_array().unwrap().len(), 1);
    // ... and still count against the tenant's limit.
    plane.create(ACME, json!({}));
    plane.create(ACME, json!({}));
    let r = plane.call_json(ACME, "POST", "/v1/sandboxes", json!({"template": "python"}));
    assert_eq!(r.status, 429);

    // The template dies: noded starts it again; its clones are gone.
    let status = plane.node_call("GET", "/v1/node").json();
    let template = status["templates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "python")
        .unwrap()
        .clone();
    let pid = template["pid"].as_u64().unwrap() as i32;
    // SAFETY: plain kill of a process of this test's user.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    eventually(
        Duration::from_secs(10),
        "the dead template's sandboxes remain",
        || {
            let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{first}"), b"");
            matches!(r.status, 404 | 410)
        },
    );
    let status = plane.wait_templates(2);
    let restarted = status["templates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "python")
        .unwrap();
    assert_ne!(restarted["pid"].as_u64().unwrap() as i32, pid);
    eventually(
        Duration::from_secs(10),
        "the API still counts the dead sandboxes",
        || {
            plane.call(ACME, "GET", "/v1/sandboxes", b"").json()["sandboxes"]
                .as_array()
                .unwrap()
                .is_empty()
        },
    );
    let second = id_of(&plane.create(ACME, json!({})));
    assert_eq!(plane.sh(ACME, &second, "echo after")["stdout"], "after\n");

    // noded dies hard: its templates die with it and leave their sockets.
    plane.noded().kill();
    eventually(
        Duration::from_secs(10),
        "the template outlived noded",
        || std::fs::read_to_string(format!("/proc/{}/stat", restarted["pid"])).is_err(),
    );
    let left: Vec<_> = std::fs::read_dir(&sockets).unwrap().flatten().collect();
    assert!(!left.is_empty(), "the dead templates' sockets");
    // Plus a stale socket of some earlier template.
    drop(std::os::unix::net::UnixListener::bind(sockets.join("old.sock")).unwrap());
    // Sandboxes on the dead node cannot be reached.
    let r = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{second}/exec"),
        json!({"command": "true"}),
    );
    assert_eq!(r.status, 502, "{}", String::from_utf8_lossy(&r.body));

    // A new noded removes the stale sockets and starts fresh templates;
    // the API (not restarted) forgets the sandboxes that died.
    plane.start_noded();
    assert!(
        !sockets.join("old.sock").exists(),
        "the stale socket was not removed"
    );
    plane.wait_templates(1);
    eventually(
        Duration::from_secs(10),
        "the API still lists the lost sandbox",
        || {
            plane
                .call(ACME, "GET", &format!("/v1/sandboxes/{second}"), b"")
                .status
                == 404
        },
    );
    let third = id_of(&plane.create(ACME, json!({})));
    assert_eq!(plane.sh(ACME, &third, "echo fresh")["stdout"], "fresh\n");

    // A clean shutdown removes every sandbox, template and socket.
    let status = plane.noded().terminate();
    assert!(status.success(), "{status}");
    let left: Vec<_> = std::fs::read_dir(&sockets)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sock"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// Request-to-ready numbers for the README (`cargo test --release -p
/// hellovm-api --test control_plane -- --ignored --nocapture`).
#[test]
#[ignore]
fn bench_create_and_exec() {
    let Some(plane) = Plane::start(PlaneOptions {
        memory_limit_mb: 1024,
        acme_max: 64,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let rounds = 30;
    let (mut create, mut node, mut echo, mut python, mut first) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut write, mut read, mut delete) = (Vec::new(), Vec::new(), Vec::new());
    let (mut first_output, mut py_first, mut py_call) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..rounds {
        let started = Instant::now();
        let sandbox = plane.create(ACME, json!({}));
        create.push(ms(started));
        node.push(sandbox["ready_ms"].as_f64().unwrap());
        let id = id_of(&sandbox);
        let started = Instant::now();
        assert_eq!(plane.sh(ACME, &id, "echo hi")["stdout"], "hi\n");
        echo.push(ms(started));
        first.push(create.last().unwrap() + echo.last().unwrap());
        let started = Instant::now();
        let r = plane.exec(
            ACME,
            &id,
            json!({"python": "import json; print(json.dumps([1]))"}),
        );
        assert_eq!(r["stdout"], "[1]\n");
        python.push(ms(started));
        // A streamed exec: from the request to its first output.
        let started = Instant::now();
        let exec = plane.start_exec(ACME, &id, json!({"command": "echo hi; sleep 0.2"}));
        let (events, _) = plane.follow_until(ACME, &id, &exec, |e| !e.is_empty());
        first_output.push(ms(started));
        assert_eq!(common::stream_text(&events, "stdout"), "hi\n");
        plane.follow(ACME, &id, &exec);
        // The stateful interpreter: the first call starts it.
        let started = Instant::now();
        assert_eq!(plane.py(ACME, &id, "x = 1\nx")["value"], "1");
        py_first.push(ms(started));
        let started = Instant::now();
        assert_eq!(plane.py(ACME, &id, "x += 1\nx")["value"], "2");
        py_call.push(ms(started));
        let started = Instant::now();
        let path = format!("/v1/sandboxes/{id}/files?path=f.txt");
        assert_eq!(plane.call(ACME, "PUT", &path, b"hello").status, 200);
        write.push(ms(started));
        let started = Instant::now();
        assert_eq!(plane.call(ACME, "GET", &path, b"").body, b"hello");
        read.push(ms(started));
        let started = Instant::now();
        assert_eq!(plane.delete(ACME, &id), 204);
        delete.push(ms(started));
    }
    // For comparison: a cold python3 in hellovm, start to first line.
    let mut cold = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        let out = std::process::Command::new(&plane.hellovm)
            .args([
                "--root",
                "/",
                "/usr/bin/python3",
                "-c",
                "import json; print(json.dumps([1]))",
            ])
            .output()
            .unwrap();
        assert_eq!(out.stdout, b"[1]\n");
        cold.push(ms(started));
    }
    for (what, samples) in [
        ("create, request to ready (API)", &mut create),
        ("create, on the node", &mut node),
        ("exec `echo hi`", &mut echo),
        ("create + first exec", &mut first),
        ("exec python (warm fork)", &mut python),
        ("streamed exec, request to first output", &mut first_output),
        (
            "stateful python, first call (starts the interpreter)",
            &mut py_first,
        ),
        ("stateful python, a call", &mut py_call),
        ("write_file 5 bytes", &mut write),
        ("read_file 5 bytes", &mut read),
        ("delete", &mut delete),
        ("cold hellovm python3 (for comparison)", &mut cold),
    ] {
        let (median, min, max) = stats(samples);
        eprintln!(
            "BENCH {what}: median {median:.1} ms ({min:.1}-{max:.1}), n={}",
            samples.len()
        );
    }
}

/// Polls `GET .../execs` until the sandbox's latest exec is in `state`;
/// its status.
fn wait_exec_state(plane: &Plane, token: &str, id: &str, state: &str) -> Value {
    let start = Instant::now();
    loop {
        let list = plane
            .call(token, "GET", &format!("/v1/sandboxes/{id}/execs"), b"")
            .json();
        if let Some(exec) = list["execs"].as_array().and_then(|e| e.first()) {
            if exec["state"] == state {
                return exec.clone();
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no exec {state}: {list}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn streamed_execs_and_cancel() {
    let Some(plane) = Plane::start(PlaneOptions::default()) else {
        return;
    };
    let id = id_of(&plane.create(ACME, json!({})));

    // The request/response exec says which exec it was and that it was
    // not cancelled; otherwise as before.
    let r = plane.sh(ACME, &id, "echo old");
    assert_eq!(r["stdout"], "old\n");
    assert_eq!(r["cancelled"], false);
    assert!(r["exec_id"].as_str().unwrap().starts_with("ex-"), "{r}");
    assert!(r.get("state_lost").is_none(), "{r}");

    // Output arrives while the command runs; a second connection cancels
    // it while a poll waits on a third; its background child dies with it.
    let started = Instant::now();
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"command": "sleep 1000 & echo $! > /tmp/bg; echo first; sleep 60; echo never",
               "timeout": 120}),
    );
    let (events, poll) = plane.follow_until(ACME, &id, &exec, |events| {
        common::stream_text(events, "stdout").contains("first")
    });
    eprintln!(
        "MEASURE first output of a streamed exec (debug build): {:.1} ms",
        ms(started)
    );
    assert_eq!(common::stream_text(&events, "stdout"), "first\n");
    assert_eq!(poll["state"], "running", "{poll}");
    assert_eq!(poll["eof"], false);
    // While it runs: one request at a time, but reading, listing and
    // cancelling are not requests that take the sandbox.
    let busy = plane.call_json(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/exec"),
        json!({"command": "true"}),
    );
    assert_eq!((busy.status, busy.code().as_str()), (409, "busy"));
    let busy = plane.call(
        ACME,
        "GET",
        &format!("/v1/sandboxes/{id}/files?path=x"),
        b"",
    );
    assert_eq!(busy.status, 409);
    let listed = wait_exec_state(&plane, ACME, &id, "running");
    assert_eq!(listed["exec_id"], exec);
    assert_eq!(listed["kind"], "command");
    let cursor = poll["next_cursor"].as_u64().unwrap();
    let waiter = {
        let addr = plane.api_addr();
        let target = format!("/v1/sandboxes/{id}/execs/{exec}?cursor={cursor}&wait=25");
        std::thread::spawn(move || {
            let started = Instant::now();
            let r = common::api_call(&addr, ACME, "GET", &target, b"").unwrap();
            (r, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    let cancelled_at = Instant::now();
    let r = plane.cancel(ACME, &id, &exec);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let status = r.json();
    eprintln!(
        "MEASURE cancel to end (debug build): {:.1} ms",
        ms(cancelled_at)
    );
    assert_eq!(status["state"], "done", "{status}");
    let result = &status["result"];
    assert_eq!(result["cancelled"], true, "{status}");
    assert_eq!(result["timed_out"], false);
    assert_eq!(result["signal"], 9);
    assert_eq!(result["stdout"], "first\n");
    assert!(cancelled_at.elapsed() < Duration::from_secs(5));
    let (r, waited) = waiter.join().unwrap();
    let poll = r.json();
    assert_eq!(poll["eof"], true, "{poll}");
    assert_eq!(poll["result"]["cancelled"], true);
    assert!(
        waited < Duration::from_secs(20),
        "the waiting poll was not woken"
    );
    assert!(started.elapsed() < Duration::from_secs(60));
    // Cancelling again changes nothing.
    assert_eq!(plane.cancel(ACME, &id, &exec).json()["result"], *result);
    // The sandbox is usable, and the background child is gone.
    eventually(Duration::from_secs(10), "the background child died", || {
        plane.sh(
            ACME,
            &id,
            "kill -0 $(cat /tmp/bg) 2>/dev/null && echo alive || echo dead",
        )["stdout"]
            == "dead\n"
    });

    // stdout and stderr apart, in order.
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"command": "echo a; sleep 0.5; echo b >&2; sleep 0.5; echo c; sleep 0.5; echo d >&2; exit 4"}),
    );
    let (events, result) = plane.follow(ACME, &id, &exec);
    let pairs = common::merged(&events);
    let expect: Vec<(String, String)> = [
        ("stdout", "a\n"),
        ("stderr", "b\n"),
        ("stdout", "c\n"),
        ("stderr", "d\n"),
    ]
    .iter()
    .map(|(k, t)| (k.to_string(), t.to_string()))
    .collect();
    assert_eq!(pairs, expect);
    assert_eq!(result["exit_code"], 4);
    assert_eq!(result["stdout"], "a\nc\n");
    assert_eq!(result["stderr"], "b\nd\n");

    // A client that goes away mid-poll: the command goes on, and its
    // output is there for the next reader, from any connection.
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"command": "echo early; sleep 1; echo late"}),
    );
    {
        use std::io::Write;
        let mut gone = std::net::TcpStream::connect(plane.api_addr()).unwrap();
        write!(
            gone,
            "GET /v1/sandboxes/{id}/execs/{exec}?cursor=0&wait=20 HTTP/1.1\r\nAuthorization: Bearer {ACME}\r\n\r\n"
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    let (events, result) = plane.follow(ACME, &id, &exec);
    assert_eq!(common::stream_text(&events, "stdout"), "early\nlate\n");
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["cancelled"], false);

    // A reader that comes late to much more output than is held: the
    // first and the last part, and how much was dropped between them.
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"command": "seq 1 300000", "max_output": 1000}),
    );
    wait_exec_state(&plane, ACME, &id, "done");
    let total: usize = (1..=300000).map(|n: u32| n.to_string().len() + 1).sum();
    let (events, result) = plane.follow(ACME, &id, &exec);
    let pairs = common::merged(&events);
    assert_eq!(pairs.len(), 3, "{pairs:?}");
    assert!(pairs[0].1.starts_with("1\n2\n3\n") && pairs[0].1.len() == 1000);
    assert_eq!(
        pairs[1],
        ("omitted".to_string(), (total - 2000).to_string())
    );
    assert!(pairs[2].1.ends_with("299999\n300000\n") && pairs[2].1.len() == 1000);
    assert_eq!(result["stdout_bytes"], total);
    assert_eq!(result["stdout_truncated"], true);
    assert!(result["stdout"].as_str().unwrap().len() < 1100);

    // A timeout while streaming.
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"command": "echo x; sleep 60", "timeout": 1}),
    );
    let (events, result) = plane.follow(ACME, &id, &exec);
    assert_eq!(common::stream_text(&events, "stdout"), "x\n");
    assert_eq!(result["timed_out"], true, "{result}");
    assert_eq!(result["cancelled"], false);
    assert_eq!(result["signal"], 9);

    // A request/response exec is cancelled from another connection.
    let one_shot = {
        let addr = plane.api_addr();
        let target = format!("/v1/sandboxes/{id}/exec");
        std::thread::spawn(move || {
            common::api_call(&addr, ACME, "POST", &target, br#"{"command": "sleep 60"}"#).unwrap()
        })
    };
    let running = wait_exec_state(&plane, ACME, &id, "running");
    let exec = running["exec_id"].as_str().unwrap().to_string();
    assert_eq!(plane.cancel(ACME, &id, &exec).status, 200);
    let r = one_shot.join().unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["cancelled"], true);

    // Bad polls, unknown execs; only the latest exec is kept.
    let bad = plane.call(
        ACME,
        "GET",
        &format!("/v1/sandboxes/{id}/execs/{exec}?wait=31"),
        b"",
    );
    assert_eq!(bad.status, 400);
    let bad = plane.call(
        ACME,
        "GET",
        &format!("/v1/sandboxes/{id}/execs/{exec}?max_bytes=1"),
        b"",
    );
    assert_eq!(bad.status, 400);
    for unknown in ["ex-999999", "nope", "ex-1"] {
        let r = plane.call(
            ACME,
            "GET",
            &format!("/v1/sandboxes/{id}/execs/{unknown}"),
            b"",
        );
        assert_eq!(
            (r.status, r.code().as_str()),
            (404, "exec_not_found"),
            "{unknown}"
        );
        assert_eq!(plane.cancel(ACME, &id, unknown).status, 404);
    }

    // Another tenant cannot see, read or cancel any of it.
    let other = id_of(&plane.create(BETA, json!({})));
    let exec = plane.start_exec(ACME, &id, json!({"command": "sleep 60"}));
    for (method, target) in [
        ("GET", format!("/v1/sandboxes/{id}/execs")),
        ("GET", format!("/v1/sandboxes/{id}/execs/{exec}")),
        ("POST", format!("/v1/sandboxes/{id}/execs/{exec}/cancel")),
        ("POST", format!("/v1/sandboxes/{id}/python/reset")),
        ("POST", format!("/v1/sandboxes/{id}/execs")),
    ] {
        let r = plane.call(BETA, method, &target, b"{\"command\": \"true\"}");
        assert_eq!(
            (r.status, r.code().as_str()),
            (404, "sandbox_not_found"),
            "{method} {target}"
        );
    }
    // Nor through its own sandbox's id.
    let r = plane.call(
        BETA,
        "GET",
        &format!("/v1/sandboxes/{other}/execs/{exec}"),
        b"",
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        plane.cancel(ACME, &id, &exec).json()["result"]["cancelled"],
        true
    );

    // Deleting a sandbox with an exec running ends the exec's readers.
    let exec = plane.start_exec(ACME, &id, json!({"command": "sleep 60"}));
    assert_eq!(plane.delete(ACME, &id), 204);
    let r = plane.poll(ACME, &id, &exec, 0, 1.0);
    assert!(matches!(r.status, 404 | 410), "{}", r.status);
    assert_eq!(plane.delete(BETA, &other), 204);
}

#[test]
fn stateful_python() {
    let Some(plane) = Plane::start(PlaneOptions::default()) else {
        return;
    };
    let id = id_of(&plane.create(ACME, json!({})));

    // Variables and imports persist; the last expression is the value.
    let started = Instant::now();
    let r = plane.py(ACME, &id, "import json\nx = 41\nprint('set')");
    eprintln!(
        "MEASURE first stateful call (debug build, starts the interpreter): {:.1} ms",
        ms(started)
    );
    assert_eq!(r["stdout"], "set\n", "{r}");
    assert_eq!(r["state_lost"], false);
    assert!(r.get("value").is_none(), "{r}");
    let started = Instant::now();
    let r = plane.py(ACME, &id, "x += 1\nx");
    eprintln!(
        "MEASURE stateful call round trip (debug build): {:.1} ms",
        ms(started)
    );
    assert_eq!(r["value"], "42", "{r}");
    assert_eq!(r["exit_code"], 0);
    let r = plane.py(ACME, &id, "json.dumps({'x': x})");
    assert_eq!(r["value"], "'{\"x\": 42}'");
    // The template's modules are there, as in a fresh fork.
    assert_eq!(
        plane.py(ACME, &id, "import sys\n'sqlite3' in sys.modules")["value"],
        "True"
    );
    // stdin is the call's.
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "input()", "stateful": true, "stdin": "hi\n"}),
    );
    assert_eq!(r["value"], "'hi'");
    // A long value keeps its start and end.
    let r = plane.py(ACME, &id, "'a' * 100000 + 'z'");
    let value = r["value"].as_str().unwrap();
    assert!(
        value.len() < 17_000 && value.starts_with("'aaa") && value.ends_with("az'"),
        "{}",
        value.len()
    );
    assert!(value.contains("characters omitted"));

    // An exception: its type and traceback; the state survives it.
    let r = plane.py(ACME, &id, "def f():\n    return 1/0\nf()");
    assert_eq!(r["exit_code"], 1);
    assert_eq!(r["error"]["type"], "ZeroDivisionError", "{r}");
    let trace = r["error"]["traceback"].as_str().unwrap();
    assert!(
        trace.contains("return 1/0") && trace.contains("ZeroDivisionError"),
        "{trace}"
    );
    let r = plane.py(ACME, &id, "syntax error here");
    assert_eq!(r["error"]["type"], "SyntaxError");
    assert_eq!(plane.py(ACME, &id, "x")["value"], "42");

    // Streamed and cancelled: interrupted, the state kept.
    let exec = plane.start_exec(
        ACME,
        &id,
        json!({"python": "import time\nprint('tick')\ntime.sleep(60)", "stateful": true}),
    );
    let (_, poll) = plane.follow_until(ACME, &id, &exec, |events| {
        common::stream_text(events, "stdout") == "tick\n"
    });
    assert_eq!(poll["state"], "running");
    let r = plane.cancel(ACME, &id, &exec).json();
    let result = &r["result"];
    assert_eq!(result["cancelled"], true, "{r}");
    assert_eq!(result["error"]["type"], "KeyboardInterrupt");
    assert_eq!(result["state_lost"], false);
    assert_eq!(plane.py(ACME, &id, "x")["value"], "42");

    // Interrupted at its timeout: the state kept.
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "y = 1\nimport time\ntime.sleep(60)", "stateful": true, "timeout": 1}),
    );
    assert_eq!(r["timed_out"], true, "{r}");
    assert_eq!(r["error"]["type"], "KeyboardInterrupt");
    assert_eq!(r["state_lost"], false);
    assert_eq!(plane.py(ACME, &id, "x + y")["value"], "43");

    // Code that cannot be interrupted: killed, restarted, state lost.
    plane.py(
        ACME,
        &id,
        "import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)",
    );
    let started = Instant::now();
    let r = plane.exec(
        ACME,
        &id,
        json!({"python": "while True: pass", "stateful": true, "timeout": 1}),
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(r["timed_out"], true, "{r}");
    assert_eq!(r["error"]["type"], "InterpreterKilled");
    assert_eq!(r["state_lost"], true);
    let r = plane.py(ACME, &id, "x");
    assert_eq!(r["error"]["type"], "NameError", "{r}");
    assert_eq!(r["state_lost"], false);
    // An interpreter that ends by itself.
    let r = plane.py(ACME, &id, "import os\nos._exit(7)");
    assert_eq!(r["error"]["type"], "InterpreterExited", "{r}");
    assert_eq!(r["exit_code"], 7);
    assert_eq!(r["state_lost"], true);

    // Reset.
    plane.py(ACME, &id, "z = 3");
    let reset = plane.call(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/python/reset"),
        b"",
    );
    assert_eq!(reset.status, 200);
    assert_eq!(reset.json()["had_state"], true);
    assert_eq!(plane.py(ACME, &id, "'z' in dir()")["value"], "False");
    let reset = plane.call(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/python/reset"),
        b"",
    );
    assert_eq!(reset.json()["had_state"], true);
    let reset = plane.call(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{id}/python/reset"),
        b"",
    );
    assert_eq!(reset.json()["had_state"], false);

    // Separate per sandbox and per tenant; the fresh-fork mode is apart.
    plane.py(ACME, &id, "secret = 'acme'");
    let second = id_of(&plane.create(ACME, json!({})));
    assert_eq!(
        plane.py(ACME, &second, "'secret' in dir()")["value"],
        "False"
    );
    let other = id_of(&plane.create(BETA, json!({})));
    assert_eq!(
        plane.py(BETA, &other, "'secret' in dir()")["value"],
        "False"
    );
    let r = plane.exec(ACME, &id, json!({"python": "print('secret' in dir())"}));
    assert_eq!(r["stdout"], "False\n");
    assert_eq!(plane.py(ACME, &id, "secret")["value"], "'acme'");
    let r = plane.call_json(
        BETA,
        "POST",
        &format!("/v1/sandboxes/{id}/exec"),
        json!({"python": "secret", "stateful": true}),
    );
    assert_eq!(r.status, 404);

    // Malformed stateful requests.
    for bad in [
        json!({"python": "1", "stateful": true, "cwd": "/tmp"}),
        json!({"python": "1", "stateful": true, "env": {"A": "b"}}),
        json!({"command": "true", "stateful": true}),
    ] {
        let r = plane.call_json(ACME, "POST", &format!("/v1/sandboxes/{id}/exec"), bad);
        assert_eq!(r.status, 400);
    }

    // Its memory counts in the sandbox's limit (512 MiB here).
    let r = plane.py(ACME, &id, "blob = bytearray(64 << 20)\nlen(blob)");
    assert_eq!(r["value"], "67108864");
    eventually(
        Duration::from_secs(10),
        "the interpreter's memory counted",
        || {
            let info = plane
                .call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"")
                .json();
            info["memory_bytes"].as_u64().unwrap() > 64 << 20
        },
    );

    for (token, sandbox) in [(ACME, &id), (ACME, &second), (BETA, &other)] {
        assert_eq!(plane.delete(token, sandbox), 204);
    }
}
