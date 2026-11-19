//! Scheduling across nodes (README, "Control plane", "Scheduling"): a
//! plane with three `noded` on this host. Creates spread by load, a full
//! node is skipped, a draining node gets nothing new while its sandboxes
//! work and can be deleted, a killed node is unreachable (its sandboxes
//! answer `502 node_unreachable`, creates go elsewhere) and converges when
//! it is back, the tenant limit is exact under concurrent creates, the API
//! rebuilds placement from the nodes when it restarts, the admin API
//! refuses every token but its own, and nodes that answer nonsense or
//! oversized bodies neither crash nor bloat the API.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use common::{Plane, PlaneOptions, ACME, ADMIN_TOKEN, BETA, NODE_TOKEN};
use serde_json::{json, Value};

fn id_of(sandbox: &Value) -> String {
    sandbox["id"].as_str().unwrap().to_string()
}

fn node_of(sandbox: &Value) -> String {
    sandbox["node"].as_str().unwrap().to_string()
}

/// Waits until `check` holds, or fails after `limit` with `what`.
fn eventually(limit: Duration, what: &str, mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < limit, "{what} after {limit:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The admin API's view of node `name`.
fn admin_node(plane: &Plane, name: &str) -> Value {
    let r = plane.admin_call(ADMIN_TOKEN, "GET", &format!("/admin/v1/nodes/{name}"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

fn wait_state(plane: &Plane, name: &str, state: &str) {
    eventually(
        Duration::from_secs(20),
        &format!(
            "{name} is not {state}: {}\n{}",
            admin_node(plane, name),
            plane.logs()
        ),
        || admin_node(plane, name)["state"] == state,
    );
}

/// How many of `sandboxes` run on each node.
fn per_node(sandboxes: &[Value]) -> HashMap<String, usize> {
    let mut count = HashMap::new();
    for s in sandboxes {
        *count.entry(node_of(s)).or_default() += 1;
    }
    count
}

fn templates(plane: &Plane, token: &str) -> Vec<(String, bool)> {
    let r = plane.call(token, "GET", "/v1/templates", b"").json();
    r["templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            assert_eq!(t.as_object().unwrap().len(), 2, "{t}");
            (
                t["name"].as_str().unwrap().to_string(),
                t["ready"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[test]
fn placement_draining_and_the_admin_api() {
    let Some(plane) = Plane::start(PlaneOptions {
        nodes: 3,
        // node-3 takes one sandbox.
        node_max_sandboxes: vec![32, 32, 1],
        // node-2 also has acme's own template `extra`.
        extra_template_on: Some(1),
        acme_max: 12,
        ..PlaneOptions::default()
    }) else {
        return;
    };

    // The admin API takes its own token only, and only on its listener.
    let wrong = "admin-token-wrong-0123456789abcdef";
    for token in ["", ACME, BETA, NODE_TOKEN, wrong] {
        let r = plane.admin_call(token, "GET", "/admin/v1/nodes");
        assert_eq!(r.status, 401, "{token}");
        let r = plane.admin_call(token, "POST", "/admin/v1/nodes/node-1/drain");
        assert_eq!(r.status, 401, "{token}");
    }
    let r = plane.call(ACME, "GET", "/admin/v1/nodes", b"");
    assert_eq!((r.status, r.code().as_str()), (404, "no_route"));
    let r = plane.call(ADMIN_TOKEN, "GET", "/admin/v1/nodes", b"");
    assert_eq!(r.status, 401, "the admin token is no tenant's");
    let r = plane.admin_call(ADMIN_TOKEN, "GET", "/admin/v1/nodes");
    assert_eq!(r.status, 200);
    let nodes = r.json();
    let nodes = nodes["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3, "{nodes:?}");
    assert!(nodes.iter().all(|n| n["state"] == "healthy"), "{nodes:?}");
    let r = plane.admin_call(ADMIN_TOKEN, "GET", "/admin/v1/nodes/node-9");
    assert_eq!(r.status, 404);
    let r = plane.admin_call(ADMIN_TOKEN, "POST", "/admin/v1/nodes/node-1/bogus");
    assert_eq!(r.status, 404);

    // Templates answer the same whichever node has them: `extra` is on
    // node-2 only, and acme's.
    let python = plane.template(ACME).to_string();
    assert_eq!(
        templates(&plane, ACME),
        vec![("extra".to_string(), true), (python.clone(), true)]
    );
    assert!(templates(&plane, BETA).iter().all(|(n, _)| n != "extra"));

    // Creates spread by load; node-3 is full after one.
    let mut sandboxes: Vec<Value> = (0..7).map(|_| plane.create(ACME, json!({}))).collect();
    let count = per_node(&sandboxes);
    assert_eq!(count.get("node-3"), Some(&1), "{count:?}");
    for node in ["node-1", "node-2"] {
        let n = count.get(node).copied().unwrap_or(0);
        assert!((2..=4).contains(&n), "{count:?}");
    }
    let extra = plane.create(ACME, json!({"template": "extra"}));
    assert_eq!(node_of(&extra), "node-2");
    sandboxes.push(extra);
    eventually(Duration::from_secs(10), "node-3's report", || {
        admin_node(&plane, "node-3")["report"]["sandboxes"] == 1
    });

    // node-1 drains: nothing new goes there, its sandboxes work on and
    // can be deleted.
    let r = plane.admin_call(ADMIN_TOKEN, "POST", "/admin/v1/nodes/node-1/drain");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "draining");
    assert_eq!(
        plane.node_call_at(0, "GET", "/v1/node").json()["draining"],
        true
    );
    assert!(plane
        .api
        .as_ref()
        .unwrap()
        .log()
        .contains("node state change: node=node-1 from=healthy to=draining"));
    for _ in 0..2 {
        let s = plane.create(ACME, json!({}));
        assert_eq!(node_of(&s), "node-2", "{s}");
        sandboxes.push(s);
    }
    let on_one: Vec<String> = sandboxes
        .iter()
        .filter(|s| node_of(s) == "node-1")
        .map(id_of)
        .collect();
    assert!(!on_one.is_empty());
    assert_eq!(
        plane.sh(ACME, &on_one[0], "echo still")["stdout"],
        "still\n"
    );
    assert_eq!(plane.delete(ACME, &on_one[0]), 204);
    sandboxes.retain(|s| id_of(s) != on_one[0]);
    assert_eq!(templates(&plane, ACME)[1], (python.clone(), true));

    // node-2 drains too: node-3 is full, so nothing can take a sandbox,
    // and `extra` is on no node that takes sandboxes.
    let r = plane.admin_call(ADMIN_TOKEN, "POST", "/admin/v1/nodes/node-2/drain");
    assert_eq!(r.status, 200);
    let r = plane.call_json(ACME, "POST", "/v1/sandboxes", json!({"template": python}));
    assert_eq!((r.status, r.code().as_str()), (503, "node_full"));
    assert_eq!(
        templates(&plane, ACME),
        vec![("extra".to_string(), false), (python.clone(), true)],
        "python is ready on node-3, which has no room: listed as ready"
    );
    let r = plane.call_json(ACME, "POST", "/v1/sandboxes", json!({"template": "extra"}));
    assert_eq!((r.status, r.code().as_str()), (503, "template_not_ready"));
    let r = plane.call_json(ACME, "POST", "/v1/sandboxes", json!({"template": "nope"}));
    assert_eq!((r.status, r.code().as_str()), (404, "template_not_found"));

    // Undrained, they take sandboxes again.
    for node in ["node-1", "node-2"] {
        let r = plane.admin_call(
            ADMIN_TOKEN,
            "POST",
            &format!("/admin/v1/nodes/{node}/undrain"),
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["state"], "healthy");
    }
    let s = plane.create(ACME, json!({}));
    assert_eq!(node_of(&s), "node-1", "the least loaded: {s}");
    sandboxes.push(s);

    // The tenant limit is exact under concurrent creates across nodes.
    for s in &sandboxes {
        assert_eq!(plane.delete(ACME, &id_of(s)), 204);
    }
    // (With the reports up to date: placement then starts from equal
    // loads, which the spread below relies on.)
    eventually(Duration::from_secs(10), "the nodes' reports", || {
        ["node-1", "node-2", "node-3"]
            .iter()
            .all(|n| admin_node(&plane, n)["report"]["sandboxes"] == 0)
    });
    let addr = plane.api_addr();
    let template = python.clone();
    let answers: Vec<(u16, Value)> = std::thread::scope(|scope| {
        let creates: Vec<_> = (0..20)
            .map(|_| {
                let (addr, template) = (&addr, &template);
                scope.spawn(move || {
                    let body = json!({ "template": template }).to_string();
                    let r = common::api_call(addr, ACME, "POST", "/v1/sandboxes", body.as_bytes())
                        .unwrap();
                    let value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                    (r.status, value)
                })
            })
            .collect();
        creates.into_iter().map(|c| c.join().unwrap()).collect()
    });
    let made: Vec<Value> = answers
        .iter()
        .filter(|(status, _)| *status == 201)
        .map(|(_, v)| v.clone())
        .collect();
    assert_eq!(made.len(), 12, "{answers:?}\n{}", plane.logs());
    assert!(answers
        .iter()
        .all(|(status, v)| *status == 201
            || (*status == 429 && v["error"]["code"] == "tenant_limit")));
    let count = per_node(&made);
    assert!(count.get("node-3").copied().unwrap_or(0) <= 1, "{count:?}");
    for node in ["node-1", "node-2"] {
        assert!(
            count.get(node).copied().unwrap_or(0) >= 4,
            "spread: {count:?}"
        );
    }
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    assert_eq!(list["sandboxes"].as_array().unwrap().len(), 12);
    eventually(Duration::from_secs(10), "the nodes' reports", || {
        ["node-1", "node-2", "node-3"]
            .iter()
            .map(|n| {
                admin_node(&plane, n)["report"]["sandboxes"]
                    .as_u64()
                    .unwrap()
            })
            .sum::<u64>()
            == 12
    });
}

#[test]
fn a_node_fails_and_comes_back_and_the_api_restarts() {
    let Some(mut plane) = Plane::start(PlaneOptions {
        nodes: 3,
        acme_max: 8,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let sandboxes: Vec<Value> = (0..6).map(|_| plane.create(ACME, json!({}))).collect();
    let count = per_node(&sandboxes);
    assert_eq!(count.len(), 3, "{count:?}");
    for s in &sandboxes {
        let id = id_of(s);
        plane.sh(ACME, &id, &format!("echo {id} > /home/sandbox/mark"));
    }
    let placement: HashMap<String, String> =
        sandboxes.iter().map(|s| (id_of(s), node_of(s))).collect();

    // The API restarts: placement is rebuilt from the nodes.
    plane.restart_api();
    for (id, node) in &placement {
        let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"");
        assert_eq!(r.status, 200);
        assert_eq!(node_of(&r.json()), *node);
        assert_eq!(
            plane.sh(ACME, id, "cat /home/sandbox/mark")["stdout"],
            format!("{id}\n")
        );
    }
    let r = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    let extra = r.json();
    assert_eq!(r.status, 201);
    assert_eq!(plane.delete(ACME, &id_of(&extra)), 204);

    // node-2 dies: it is marked unreachable; its sandboxes answer a
    // stable error that names nothing of the node.
    let lost: Vec<String> = sandboxes
        .iter()
        .filter(|s| node_of(s) == "node-2")
        .map(id_of)
        .collect();
    plane.kill_node(1);
    wait_state(&plane, "node-2", "unreachable");
    let log = plane.api.as_ref().unwrap().log();
    assert!(
        log.contains("node state change: node=node-2 from=healthy to=unreachable"),
        "{log}"
    );
    let node_addr = format!("127.0.0.1:{}", plane.nodes[1].port);
    // (Deleting one is accepted and done later: see quotas.rs.)
    for id in &lost {
        for r in [
            plane.call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b""),
            plane.call_json(
                ACME,
                "POST",
                &format!("/v1/sandboxes/{id}/exec"),
                json!({"command": "true"}),
            ),
        ] {
            assert_eq!((r.status, r.code().as_str()), (502, "node_unreachable"));
            let body = String::from_utf8_lossy(&r.body);
            assert!(
                !body.contains("node-2") && !body.contains(&node_addr),
                "{body}"
            );
        }
        // Another tenant learns nothing: the same answer as for none.
        let r = plane.call(BETA, "GET", &format!("/v1/sandboxes/{id}"), b"");
        assert_eq!((r.status, r.code().as_str()), (404, "sandbox_not_found"));
    }
    // Creates go elsewhere; the lost sandboxes still count, so the limit
    // stays exact.
    let mut more = Vec::new();
    for _ in 0..(8 - sandboxes.len()) {
        let s = plane.create(ACME, json!({}));
        assert_ne!(node_of(&s), "node-2");
        more.push(id_of(&s));
    }
    let r = plane.call_json(
        ACME,
        "POST",
        "/v1/sandboxes",
        json!({"template": plane.template(ACME)}),
    );
    assert_eq!((r.status, r.code().as_str()), (429, "tenant_limit"));
    for id in &more {
        assert_eq!(plane.delete(ACME, id), 204);
    }
    assert!(templates(&plane, ACME).contains(&(plane.template(ACME).to_string(), true)));

    // The API restarts while node-2 is down: what the others run is found.
    plane.restart_api();
    assert_eq!(admin_node(&plane, "node-2")["state"], "unreachable");
    for (id, node) in placement.iter().filter(|(_, n)| *n != "node-2") {
        let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"");
        assert_eq!(r.status, 200);
        assert_eq!(node_of(&r.json()), *node);
    }

    // node-2 comes back (empty: its sandboxes died with it); the state
    // converges.
    plane.start_node(1);
    plane.wait_templates_at(1, 1);
    wait_state(&plane, "node-2", "healthy");
    eventually(Duration::from_secs(10), "node-2's templates", || {
        admin_node(&plane, "node-2")["report"]["templates"]
            .as_array()
            .is_some_and(|t| t.iter().all(|t| t["ready"] == true))
    });
    for id in &lost {
        eventually(
            Duration::from_secs(10),
            "a lost sandbox is still there",
            || {
                plane
                    .call(ACME, "GET", &format!("/v1/sandboxes/{id}"), b"")
                    .status
                    == 404
            },
        );
    }
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    assert_eq!(
        list["sandboxes"].as_array().unwrap().len(),
        sandboxes.len() - lost.len()
    );
    // It is the least loaded now.
    let back = plane.create(ACME, json!({}));
    assert_eq!(node_of(&back), "node-2", "{back}");
    assert_eq!(
        plane.sh(ACME, &id_of(&back), "echo back")["stdout"],
        "back\n"
    );
}

/// What a fake node does with every request.
#[derive(Clone, Copy)]
enum Fake {
    /// `200` with a body that is not JSON.
    Garbage,
    /// A `Content-Length` of a terabyte, and then some of it.
    Huge,
    /// No `Content-Length`: bytes until the API stops reading.
    Endless,
    /// A valid status, of another node, inviting sandboxes.
    Impostor,
    /// A status of absurd numbers.
    Absurd,
    /// Accepts and never answers.
    Silent,
    /// A good status and list, inviting sandboxes, and a nonsense refusal
    /// of every create.
    Trap(&'static str),
    /// A good status (draining, so it gets no sandbox) and a list with one
    /// sandbox of `beta`; every request about that sandbox is read and the
    /// connection closed without an answer.
    Hangup(&'static str),
}

/// The sandbox the [`Fake::Hangup`] node lists.
const HUNG: &str = "sb-abababababababababababababababab";

fn fake_status(name: &str, max: u64) -> String {
    json!({
        "node": name,
        "templates": [{"name": "python", "ready": true, "starts": 1, "tenant": null, "pid": 1}],
        "sandboxes": 0, "creating": 0, "max_sandboxes": max,
        "memory_bytes": 0, "memory_limit_bytes": 1u64 << 40, "draining": false,
    })
    .to_string()
}

fn fake_answer(stream: &mut TcpStream, fake: Fake) {
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
    let length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length.min(1 << 20)];
    let _ = stream.read_exact(&mut body);
    let target = head.split(' ').nth(1).unwrap_or("").to_string();
    // The path: the API asks for the list with `?ended_after=`.
    let target = target.split('?').next().unwrap_or("").to_string();
    let reply = |stream: &mut TcpStream, status: &str, body: &str| {
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    };
    let zeros = vec![b'0'; 64 << 10];
    match fake {
        Fake::Garbage => reply(stream, "200 OK", "{not json at all"),
        Fake::Huge => {
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\nConnection: close\r\n\r\n"
            );
            for _ in 0..64 {
                if stream.write_all(&zeros).is_err() {
                    return;
                }
            }
        }
        Fake::Endless => {
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n[");
            // Up to 256 MiB, until the API hangs up.
            for _ in 0..4096 {
                if stream.write_all(&zeros).is_err() {
                    return;
                }
            }
        }
        Fake::Impostor => reply(stream, "200 OK", &fake_status("node-1", 4096)),
        Fake::Absurd => reply(stream, "200 OK", &fake_status("fake-absurd", u64::MAX)),
        Fake::Silent => std::thread::sleep(Duration::from_secs(60)),
        Fake::Trap(name) => match target.as_str() {
            "/v1/node" => reply(stream, "200 OK", &fake_status(name, 4096)),
            "/v1/sandboxes" => reply(stream, "200 OK", r#"{"sandboxes": []}"#),
            _ => reply(stream, "503 Service Unavailable", "\u{0}\u{1}nonsense"),
        },
        Fake::Hangup(name) => match target.as_str() {
            "/v1/node" => {
                let mut status: Value = serde_json::from_str(&fake_status(name, 4096)).unwrap();
                status["draining"] = json!(true);
                status["sandboxes"] = json!(1);
                reply(stream, "200 OK", &status.to_string());
            }
            "/v1/sandboxes" => {
                let list = json!({"sandboxes": [{
                    "id": HUNG, "tenant": "beta", "template": "python", "node": name,
                    "egress_id": "abababababababab", "created_at": 1, "last_used_at": 1,
                    "expires_at": u64::MAX, "idle_timeout": 600.0, "memory_bytes": 0,
                    "memory_limit_bytes": 1, "ready_ms": 1.0,
                }]});
                reply(stream, "200 OK", &list.to_string());
            }
            // Read, and not answered.
            _ => {}
        },
    }
}

/// A fake node on loopback: its address.
fn fake_node(fake: Fake) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || fake_answer(&mut stream, fake));
        }
    });
    addr
}

/// The resident memory of process `pid`, in bytes.
fn rss(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap();
    kib * 1024
}

#[test]
fn nodes_that_answer_nonsense_cannot_hurt_the_api() {
    let fakes = [
        ("fake-garbage", Fake::Garbage),
        ("fake-huge", Fake::Huge),
        ("fake-endless", Fake::Endless),
        ("fake-impostor", Fake::Impostor),
        ("fake-absurd", Fake::Absurd),
        ("fake-silent", Fake::Silent),
        ("fake-trap", Fake::Trap("fake-trap")),
        ("fake-hangup", Fake::Hangup("fake-hangup")),
    ];
    let extra_nodes = fakes
        .iter()
        .map(|(name, fake)| (name.to_string(), fake_node(*fake)))
        .collect();
    let Some(mut plane) = Plane::start(PlaneOptions {
        extra_nodes,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let pid = plane.api.as_ref().unwrap().child.id();
    assert_eq!(admin_node(&plane, "node-1")["state"], "healthy");
    for (name, _) in &fakes[..6] {
        assert_eq!(admin_node(&plane, name)["state"], "unreachable", "{name}");
    }
    assert_eq!(admin_node(&plane, "fake-trap")["state"], "healthy");
    assert_eq!(admin_node(&plane, "fake-hangup")["state"], "draining");

    // Requests about a sandbox that get no answer are that sandbox's
    // trouble, however many: the node answers its probes and stays up, so
    // one tenant cannot make a node unreachable for the others.
    let hung = format!("/v1/sandboxes/{HUNG}");
    for _ in 0..8 {
        let answer = plane.call(BETA, "GET", &hung, b"");
        assert_eq!(answer.status, 502, "{}", answer.json());
        assert_eq!(answer.code(), "node_unreachable");
        let reset = plane.call(BETA, "POST", &format!("{hung}/python/reset"), b"");
        assert_eq!(reset.status, 502);
    }
    assert_eq!(admin_node(&plane, "fake-hangup")["state"], "draining");
    assert_eq!(plane.call(ACME, "GET", &hung, b"").status, 404);

    // Every create goes to node-1: the trap is asked first (it reports no
    // load), refuses with nonsense, and the next node is asked.
    let start = Instant::now();
    let mut made = Vec::new();
    while start.elapsed() < Duration::from_secs(5) || made.len() < 3 {
        let s = plane.create(ACME, json!({}));
        assert_eq!(node_of(&s), "node-1");
        assert_eq!(plane.delete(ACME, &id_of(&s)), 204);
        made.push(s);
        assert_eq!(
            templates(&plane, ACME),
            vec![(plane.template(ACME).to_string(), true)]
        );
    }
    // Ten rounds of probes later the API runs, and holds little memory.
    assert!(plane
        .api
        .as_mut()
        .unwrap()
        .child
        .try_wait()
        .unwrap()
        .is_none());
    let memory = rss(pid);
    assert!(memory < 64 << 20, "the API holds {} MiB", memory >> 20);
    for (name, _) in &fakes[..6] {
        assert_eq!(admin_node(&plane, name)["state"], "unreachable", "{name}");
        assert!(admin_node(&plane, name)["report"].is_null(), "{name}");
    }
    let view = admin_node(&plane, "fake-impostor");
    assert_eq!(
        view["last_error"], "the node reports another name",
        "{view}"
    );
}
