//! The public API: tenants authenticate with a bearer token and manage
//! their own sandboxes. Another tenant's sandbox is reported as missing,
//! exactly like one that does not exist.
//!
//! | Method and path | Body | Answer |
//! |---|---|---|
//! | `GET /v1/templates` | | `{"templates": [{"name": ..., "ready": ...}]}` |
//! | `POST /v1/sandboxes` | `CreateSandbox` | `201` `SandboxInfo` |
//! | `GET /v1/sandboxes` | | `SandboxList` |
//! | `GET /v1/sandboxes/{id}` | | `SandboxInfo` |
//! | `DELETE /v1/sandboxes/{id}` | | `204` |
//! | `POST /v1/sandboxes/{id}/exec` | `ExecRequest` | `ExecResult` (runs it to its end) |
//! | `POST /v1/sandboxes/{id}/execs` | `ExecRequest` | `201` `ExecStatus` (once started) |
//! | `GET /v1/sandboxes/{id}/execs` | | `ExecList` (the latest exec) |
//! | `GET /v1/sandboxes/{id}/execs/{exec}?cursor=&wait=&max_bytes=` | | `ExecPoll` |
//! | `POST /v1/sandboxes/{id}/execs/{exec}/cancel` | | `ExecStatus` |
//! | `POST /v1/sandboxes/{id}/python/reset` | | `ResetResult` |
//! | `GET /v1/sandboxes/{id}/files?path=P` | | the bytes |
//! | `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `WriteResult` |
//! | `POST /v1/sandboxes/{id}/files/edit` | `EditRequest` | `EditResult` |

use std::sync::Arc;
use std::time::{Duration, Instant};

use hellovm_control::http::{self, percent_encode, ClientResponse, Handler, Request, Response};
use hellovm_control::ids::{token_eq, SandboxId};
use hellovm_control::types::{
    self, CreateSandbox, DrainRequest, ExecRequest, NodeCreate, NodeStatus, PollQuery, SandboxInfo,
    SandboxList,
};

use crate::config::{valid_name, Config, Node, Tenant};
use crate::nodes::{check_status, NoPlace, Nodes};
use crate::store::{Record, Store};

/// The header naming the tenant to the node.
const TENANT_HEADER: &str = "X-Hellovm-Tenant";
/// Largest node answer read for a request about a sandbox (a file of
/// 16 MiB is the largest).
const MAX_NODE_ANSWER: usize = 24 << 20;
/// Largest node status read: 256 templates of a few hundred bytes.
const MAX_STATUS: usize = 1 << 20;
/// Largest sandbox list read: 4096 sandboxes of under 1 KiB.
const MAX_LIST: usize = 8 << 20;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const FILE_TIMEOUT: Duration = Duration::from_secs(90);

pub struct Api {
    pub config: Config,
    pub tenants: Vec<Tenant>,
    pub nodes: Nodes,
    pub store: Arc<dyn Store>,
}

fn error(status: u16, code: &str, message: &str) -> Response {
    Response::error(status, code, message)
}

fn not_found() -> Response {
    error(404, "sandbox_not_found", "no such sandbox")
}

impl Api {
    /// The tenant whose token this is. Every token is compared, so the
    /// time taken does not tell which one matched.
    fn tenant(&self, request: &Request) -> Option<&Tenant> {
        let presented = request.bearer()?;
        let mut found = None;
        for tenant in &self.tenants {
            if token_eq(presented, &tenant.token) && found.is_none() {
                found = Some(tenant);
            }
        }
        found
    }

    fn call(
        &self,
        node: &Node,
        method: &str,
        target: &str,
        tenant: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> std::io::Result<ClientResponse> {
        self.call_max(node, method, target, tenant, body, timeout, MAX_NODE_ANSWER)
    }

    #[allow(clippy::too_many_arguments)]
    fn call_max(
        &self,
        node: &Node,
        method: &str,
        target: &str,
        tenant: Option<&str>,
        body: &[u8],
        timeout: Duration,
        max_answer: usize,
    ) -> std::io::Result<ClientResponse> {
        let auth = format!("Bearer {}", node.token);
        let mut headers = vec![("Authorization", auth.as_str())];
        if let Some(tenant) = tenant {
            headers.push((TENANT_HEADER, tenant));
        }
        http::call(
            &node.addr, method, target, &headers, body, timeout, max_answer,
        )
    }

    /// What a tenant is told about a sandbox whose node does not answer:
    /// nothing about the node.
    fn unreachable() -> Response {
        error(
            502,
            "node_unreachable",
            "the sandbox's node does not answer; try again later",
        )
    }

    /// A request to node `i` failed: logged, and counted against it.
    fn node_failed(&self, i: usize, err: &std::io::Error) {
        let name = &self.nodes.configs()[i].name;
        log::warn!("node {name}: {err}");
        self.nodes.failed(i, &err.to_string());
    }

    /// Asks node `i` for its status and sandboxes, updates what is known
    /// of it, and makes the store agree. A node that does not answer, or
    /// answers nonsense, keeps its records and counts a failure.
    pub fn probe(&self, i: usize) {
        let node = &self.nodes.configs()[i];
        let timeout = Duration::from_secs_f64(self.config.node_timeout);
        let asked = Instant::now();
        let status = self
            .call_max(node, "GET", "/v1/node", None, b"", timeout, MAX_STATUS)
            .map_err(|e| e.to_string())
            .and_then(|r| match r.status {
                200 => serde_json::from_slice::<NodeStatus>(&r.body)
                    .map_err(|_| "a malformed status".to_string()),
                status => Err(format!("status {status} for its status")),
            })
            .and_then(|status| check_status(status, &node.name));
        let load = match status {
            Ok(load) => load,
            Err(why) => {
                log::debug!("node {}: probe: {why}", node.name);
                self.nodes.failed(i, &why);
                return;
            }
        };
        let list = self
            .call_max(
                node,
                "GET",
                "/v1/sandboxes",
                None,
                b"",
                NODE_TIMEOUT,
                MAX_LIST,
            )
            .map_err(|e| e.to_string())
            .and_then(|r| match r.status {
                200 => serde_json::from_slice::<SandboxList>(&r.body)
                    .map_err(|_| "a malformed sandbox list".to_string()),
                status => Err(format!("status {status} for its sandboxes")),
            });
        let list = match list {
            Ok(list) => list,
            Err(why) => {
                log::warn!("node {}: listing sandboxes: {why}", node.name);
                self.nodes.failed(i, &why);
                return;
            }
        };
        let records = list
            .sandboxes
            .into_iter()
            .filter_map(|s| {
                if !valid_name(&s.tenant) || !valid_name(&s.template) {
                    return None;
                }
                Some(Record {
                    id: SandboxId::parse(&s.id)?,
                    tenant: s.tenant,
                    node: node.name.clone(),
                    template: s.template,
                })
            })
            .collect();
        self.nodes.reported(i, asked, load);
        self.store.replace_node(&node.name, asked, records);
    }

    /// Probes every node at once; returns when all answered or failed.
    pub fn reconcile(&self) {
        std::thread::scope(|scope| {
            for i in 0..self.nodes.configs().len() {
                scope.spawn(move || self.probe(i));
            }
        });
    }

    fn templates(&self, tenant: &Tenant) -> Response {
        // What a tenant may know of a template: its name and whether a
        // sandbox can be made of it now. Not the nodes it is on.
        #[derive(serde::Serialize)]
        struct PublicTemplate {
            name: String,
            ready: bool,
        }
        let templates: Vec<PublicTemplate> = self
            .nodes
            .templates(&tenant.name)
            .into_iter()
            .map(|(name, ready)| PublicTemplate { name, ready })
            .collect();
        Response::json(200, &serde_json::json!({ "templates": templates }))
    }

    fn create(&self, tenant: &Tenant, request: &Request) -> Response {
        let body: CreateSandbox = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(e) => return error(400, "bad_request", &format!("malformed JSON body: {e}")),
        };
        let pick = |given: Option<f64>, default: f64, max: f64, what: &str| match given {
            None => Ok(default),
            Some(v) if v.is_finite() && v > 0.0 && v <= max => Ok(v),
            Some(_) => Err(error(
                400,
                "bad_request",
                &format!("{what} must be more than 0 and at most {max} seconds"),
            )),
        };
        let idle_timeout = match pick(
            body.idle_timeout,
            self.config.default_idle_timeout,
            self.config.max_idle_timeout,
            "idle_timeout",
        ) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let lifetime = match pick(
            body.lifetime,
            self.config.default_lifetime,
            self.config.max_lifetime,
            "lifetime",
        ) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if body.template.is_empty() || body.template.len() > 64 {
            return error(400, "bad_request", "malformed template name");
        }
        let Some(_slot) = self.store.reserve(&tenant.name, tenant.max_sandboxes) else {
            return error(
                429,
                "tenant_limit",
                &format!("at most {} sandboxes at once", tenant.max_sandboxes),
            );
        };
        let id = match SandboxId::random() {
            Ok(id) => id,
            Err(e) => return error(500, "internal", &format!("a sandbox id: {e}")),
        };
        let create = NodeCreate {
            id: id.to_string(),
            tenant: tenant.name.clone(),
            template: body.template.clone(),
            idle_timeout,
            lifetime,
        };
        let create = match serde_json::to_vec(&create) {
            Ok(bytes) => bytes,
            Err(e) => return error(500, "internal", &e.to_string()),
        };
        // Placement (see `nodes`): the least loaded node that should take
        // it, then the next, until one makes it. A node that answers did
        // not make it unless it said `201`, so the next may be asked.
        let mut tried: Vec<usize> = Vec::new();
        let mut answers: Vec<String> = Vec::new();
        loop {
            let i = match self.nodes.place(&body.template, &tenant.name, &tried) {
                Ok(i) => i,
                Err(why) => return Self::no_place(why, &answers),
            };
            tried.push(i);
            let node = &self.nodes.configs()[i];
            match self.call(node, "POST", "/v1/sandboxes", None, &create, NODE_TIMEOUT) {
                Ok(answer) if answer.status == 201 => {
                    self.nodes.answered(i);
                    let info = serde_json::from_slice::<SandboxInfo>(&answer.body)
                        .ok()
                        .filter(|info| info.id == id.to_string());
                    let Some(info) = info else {
                        log::warn!("node {}: a malformed create answer", node.name);
                        self.nodes.done(i, false);
                        self.nodes.failed(i, "a malformed create answer");
                        self.made_maybe(i, tenant, id, &body.template);
                        return error(502, "node_failed", "the sandbox could not be made");
                    };
                    self.nodes.done(i, true);
                    self.store.insert(Record {
                        id,
                        tenant: tenant.name.clone(),
                        node: node.name.clone(),
                        template: body.template.clone(),
                    });
                    return Response::json(201, &info);
                }
                Ok(answer) => {
                    self.nodes.answered(i);
                    self.nodes.done(i, false);
                    let code = answer.error_code().unwrap_or_default();
                    log::debug!(
                        "node {}: create refused: {} {code}",
                        node.name,
                        answer.status
                    );
                    answers.push(code);
                }
                // Nothing was sent: the next node may be asked.
                Err(err) if http::not_sent(&err) => {
                    self.nodes.done(i, false);
                    self.node_failed(i, &err);
                }
                Err(err) => {
                    // The node may have made the sandbox without its
                    // answer arriving. Offering the same id to another
                    // node could make it twice, so placement stops here.
                    self.nodes.done(i, false);
                    self.node_failed(i, &err);
                    self.made_maybe(i, tenant, id, &body.template);
                    return Self::unreachable();
                }
            }
        }
    }

    /// Node `i` may have made sandbox `id` (its answer to the create was
    /// lost or broken): it is removed if the node says so, and otherwise
    /// kept in the store, where it counts against the tenant's limit until
    /// the node's next list shows whether it exists (and the tenant sees it
    /// then if it does).
    fn made_maybe(&self, i: usize, tenant: &Tenant, id: SandboxId, template: &str) {
        let node = &self.nodes.configs()[i];
        let target = format!("/v1/sandboxes/{id}");
        let deleted = self
            .call(
                node,
                "DELETE",
                &target,
                Some(&tenant.name),
                b"",
                NODE_TIMEOUT,
            )
            .is_ok_and(|a| a.status == 204);
        if !deleted {
            self.store.insert(Record {
                id,
                tenant: tenant.name.clone(),
                node: node.name.clone(),
                template: template.to_string(),
            });
        }
    }

    /// The answer when no node made the sandbox. `answers` are the error
    /// codes of the nodes that refused it.
    fn no_place(why: NoPlace, answers: &[String]) -> Response {
        let not_found = || error(404, "template_not_found", "no such template");
        let not_ready = || {
            error(
                503,
                "template_not_ready",
                "the template is starting; try again shortly",
            )
        };
        let full = || {
            error(
                503,
                "node_full",
                "no node can take a sandbox now; try again shortly",
            )
        };
        if answers.is_empty() {
            return match why {
                NoPlace::UnknownTemplate => not_found(),
                NoPlace::NotReady => not_ready(),
                NoPlace::Full => full(),
            };
        }
        if answers.iter().all(|c| c == "template_not_found") {
            not_found()
        } else if answers.iter().any(|c| c == "template_not_ready") {
            not_ready()
        } else {
            full()
        }
    }

    fn list(&self, tenant: &Tenant) -> Response {
        let target = format!("/v1/sandboxes?tenant={}", percent_encode(&tenant.name));
        // Every node that answers, at once; an unreachable one is not asked
        // (its sandboxes are not listed while it is).
        let lists: Vec<Option<SandboxList>> = std::thread::scope(|scope| {
            let asks: Vec<_> = (0..self.nodes.configs().len())
                .map(|i| {
                    let target = &target;
                    scope.spawn(move || {
                        if !self.nodes.reachable(i) {
                            return None;
                        }
                        let node = &self.nodes.configs()[i];
                        match self.call_max(node, "GET", target, None, b"", NODE_TIMEOUT, MAX_LIST)
                        {
                            Ok(a) if a.status == 200 => {
                                self.nodes.answered(i);
                                serde_json::from_slice::<SandboxList>(&a.body).ok()
                            }
                            Ok(_) => None,
                            Err(err) => {
                                self.node_failed(i, &err);
                                None
                            }
                        }
                    })
                })
                .collect();
            asks.into_iter().map(|a| a.join().ok().flatten()).collect()
        });
        let mut sandboxes = Vec::new();
        for (i, list) in lists.into_iter().enumerate() {
            let node = &self.nodes.configs()[i].name;
            match list {
                // Only what this node runs for this tenant.
                Some(list) => sandboxes.extend(
                    list.sandboxes
                        .into_iter()
                        .filter(|s| s.tenant == tenant.name && s.node == *node),
                ),
                None => log::debug!("node {node}: no sandbox list"),
            }
        }
        sandboxes.sort_by_key(|s| (s.created_at, s.id.clone()));
        Response::json(200, &SandboxList { sandboxes })
    }

    /// Passes a request about one sandbox to its node.
    fn forward(&self, tenant: &Tenant, id: &str, request: &Request, rest: &[&str]) -> Response {
        let Some(sandbox) = SandboxId::parse(id) else {
            return not_found();
        };
        // A sandbox that ended is still asked about at its node, which
        // remembers why it ended (`410`).
        let Some(record) = self
            .store
            .get(&sandbox)
            .or_else(|| self.store.ended(&sandbox))
            .filter(|r| r.tenant == tenant.name)
        else {
            return not_found();
        };
        let Some(i) = self.nodes.index(&record.node) else {
            return not_found();
        };
        if !self.nodes.reachable(i) {
            return Self::unreachable();
        }
        let node = &self.nodes.configs()[i];
        let method = request.method.as_str();
        let (target, timeout) = match (method, rest) {
            ("GET" | "DELETE", []) => (format!("/v1/sandboxes/{sandbox}"), NODE_TIMEOUT),
            ("POST", [what @ ("exec" | "execs")]) => {
                let exec: ExecRequest = match serde_json::from_slice(&request.body) {
                    Ok(exec) => exec,
                    Err(e) => {
                        return error(400, "bad_request", &format!("malformed JSON body: {e}"))
                    }
                };
                let timeout = match exec.validate() {
                    Ok((timeout, _)) => timeout,
                    Err(m) => return error(400, "bad_request", &m),
                };
                // `exec` answers when it ended, `execs` when it started.
                let timeout = if *what == "exec" {
                    Duration::from_secs_f64(timeout) + NODE_TIMEOUT
                } else {
                    NODE_TIMEOUT
                };
                (format!("/v1/sandboxes/{sandbox}/{what}"), timeout)
            }
            ("GET", ["execs"]) => (format!("/v1/sandboxes/{sandbox}/execs"), NODE_TIMEOUT),
            ("GET", ["execs", exec]) => {
                if types::check_exec_id(exec).is_none() {
                    return error(404, "exec_not_found", "no such exec");
                }
                let query = match PollQuery::parse(
                    request.query("cursor"),
                    request.query("wait"),
                    request.query("max_bytes"),
                ) {
                    Ok(query) => query,
                    Err(m) => return error(400, "bad_request", &m),
                };
                (
                    format!("/v1/sandboxes/{sandbox}/execs/{exec}?{}", query.to_query()),
                    Duration::from_secs_f64(query.wait) + NODE_TIMEOUT,
                )
            }
            ("POST", ["execs", exec, "cancel"]) => {
                if types::check_exec_id(exec).is_none() {
                    return error(404, "exec_not_found", "no such exec");
                }
                (
                    format!("/v1/sandboxes/{sandbox}/execs/{exec}/cancel"),
                    NODE_TIMEOUT,
                )
            }
            ("POST", ["python", "reset"]) => (
                format!("/v1/sandboxes/{sandbox}/python/reset"),
                NODE_TIMEOUT,
            ),
            ("GET" | "PUT", ["files"]) => {
                let Some(path) = request.query("path") else {
                    return error(400, "bad_request", "no ?path=");
                };
                if let Err(m) = types::check_path(path) {
                    return error(400, "bad_request", &m);
                }
                (
                    format!(
                        "/v1/sandboxes/{sandbox}/files?path={}",
                        percent_encode(path)
                    ),
                    FILE_TIMEOUT,
                )
            }
            ("POST", ["files", "edit"]) => {
                (format!("/v1/sandboxes/{sandbox}/files/edit"), FILE_TIMEOUT)
            }
            _ => return error(404, "no_route", "no such endpoint"),
        };
        let answer = match self.call(
            node,
            method,
            &target,
            Some(&tenant.name),
            &request.body,
            timeout,
        ) {
            Ok(answer) => {
                self.nodes.answered(i);
                answer
            }
            Err(err) => {
                self.node_failed(i, &err);
                return Self::unreachable();
            }
        };
        // Gone on the node (ended, failed, removed): forget it here.
        let gone = matches!(
            answer.error_code().as_deref(),
            Some("sandbox_not_found" | "sandbox_ended" | "sandbox_failed")
        );
        if method == "DELETE" && answer.status == 204 {
            self.store.forget(&sandbox);
        } else if gone {
            self.store.remove(&sandbox);
        }
        answer.into_response()
    }
}

impl Handler for Api {
    fn body_limit(&self, method: &str, path: &str) -> usize {
        if method == "PUT" && path.ends_with("/files") {
            types::MAX_FILE
        } else {
            types::MAX_JSON
        }
    }

    fn handle(&self, request: Request) -> Response {
        let Some(tenant) = self.tenant(&request) else {
            return error(401, "unauthorized", "a valid bearer token is required")
                .with_header("WWW-Authenticate", "Bearer".into());
        };
        let segments = request.segments();
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["v1", "templates"]) => self.templates(tenant),
            ("POST", ["v1", "sandboxes"]) => self.create(tenant, &request),
            ("GET", ["v1", "sandboxes"]) => self.list(tenant),
            (_, ["v1", "sandboxes", id, rest @ ..]) => self.forward(tenant, id, &request, rest),
            _ => error(404, "no_route", "no such endpoint"),
        }
    }
}

/// The operators' API, served on a listener of its own (`admin.listen`)
/// with a token of its own; the tenants' listener does not route to it.
///
/// | Method and path | Answer |
/// |---|---|
/// | `GET /admin/v1/nodes` | `{"nodes": [NodeView]}` |
/// | `GET /admin/v1/nodes/{name}` | `NodeView` |
/// | `POST /admin/v1/nodes/{name}/drain` | `NodeView`, once the node drains |
/// | `POST /admin/v1/nodes/{name}/undrain` | `NodeView`, once it takes sandboxes again |
pub struct Admin {
    pub api: Arc<Api>,
    pub token: String,
}

impl Admin {
    fn set_draining(&self, i: usize, draining: bool) -> Response {
        let api = &self.api;
        let node = &api.nodes.configs()[i];
        let body = match serde_json::to_vec(&DrainRequest { draining }) {
            Ok(body) => body,
            Err(e) => return error(500, "internal", &e.to_string()),
        };
        let timeout = Duration::from_secs_f64(api.config.node_timeout);
        let asked = Instant::now();
        let answer = api.call_max(
            node,
            "POST",
            "/v1/node/drain",
            None,
            &body,
            timeout,
            MAX_STATUS,
        );
        let status = match answer {
            Ok(a) if a.status == 200 => serde_json::from_slice::<NodeStatus>(&a.body)
                .map_err(|_| "a malformed status".to_string())
                .and_then(|s| check_status(s, &node.name)),
            Ok(a) => Err(format!(
                "the node answered {}: {}",
                a.status,
                a.error_message()
            )),
            Err(err) => {
                api.node_failed(i, &err);
                Err(err.to_string())
            }
        };
        match status {
            Ok(load) if load.draining == draining => {
                log::info!(
                    "admin: node={} draining={draining} (asked by an operator)",
                    node.name
                );
                api.nodes.reported(i, asked, load);
                Response::json(200, &api.nodes.view(i))
            }
            Ok(_) => error(502, "node_failed", "the node did not change"),
            Err(why) => error(
                502,
                "node_unreachable",
                &format!("node {}: {why}", node.name),
            ),
        }
    }
}

impl Handler for Admin {
    fn body_limit(&self, _method: &str, _path: &str) -> usize {
        4096
    }

    fn handle(&self, request: Request) -> Response {
        if !request.bearer().is_some_and(|t| token_eq(t, &self.token)) {
            return error(401, "unauthorized", "a valid admin token is required")
                .with_header("WWW-Authenticate", "Bearer".into());
        }
        let nodes = &self.api.nodes;
        let segments = request.segments();
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["admin", "v1", "nodes"]) => {
                let views: Vec<_> = (0..nodes.configs().len()).map(|i| nodes.view(i)).collect();
                Response::json(200, &serde_json::json!({ "nodes": views }))
            }
            (method, ["admin", "v1", "nodes", name, rest @ ..]) => {
                let Some(i) = nodes.index(name) else {
                    return error(404, "node_not_found", "no such node");
                };
                match (method, rest) {
                    ("GET", []) => Response::json(200, &nodes.view(i)),
                    ("POST", ["drain"]) => self.set_draining(i, true),
                    ("POST", ["undrain"]) => self.set_draining(i, false),
                    _ => error(404, "no_route", "no such endpoint"),
                }
            }
            _ => error(404, "no_route", "no such endpoint"),
        }
    }
}
