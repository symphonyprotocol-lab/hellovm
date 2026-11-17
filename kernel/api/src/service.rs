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
//! | `POST /v1/sandboxes/{id}/exec` | `ExecRequest` | `ExecResult` |
//! | `GET /v1/sandboxes/{id}/files?path=P` | | the bytes |
//! | `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `WriteResult` |
//! | `POST /v1/sandboxes/{id}/files/edit` | `EditRequest` | `EditResult` |

use std::sync::Arc;
use std::time::{Duration, Instant};

use hellovm_control::http::{self, percent_encode, ClientResponse, Handler, Request, Response};
use hellovm_control::ids::{token_eq, SandboxId};
use hellovm_control::types::{
    self, CreateSandbox, ExecRequest, NodeCreate, NodeStatus, SandboxInfo, SandboxList,
    TemplateStatus,
};

use crate::config::{Config, Node, Tenant};
use crate::store::{Record, Store};

/// The header naming the tenant to the node.
const TENANT_HEADER: &str = "X-Hellovm-Tenant";
/// Largest node answer read.
const MAX_NODE_ANSWER: usize = 24 << 20;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const FILE_TIMEOUT: Duration = Duration::from_secs(90);

pub struct Api {
    pub config: Config,
    pub tenants: Vec<Tenant>,
    pub nodes: Vec<Node>,
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

    fn node(&self, name: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.name == name)
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
        let auth = format!("Bearer {}", node.token);
        let mut headers = vec![("Authorization", auth.as_str())];
        if let Some(tenant) = tenant {
            headers.push((TENANT_HEADER, tenant));
        }
        http::call(
            &node.addr,
            method,
            target,
            &headers,
            body,
            timeout,
            MAX_NODE_ANSWER,
        )
    }

    fn unreachable(node: &Node, err: &std::io::Error) -> Response {
        log::warn!("node {}: {err}", node.name);
        error(
            502,
            "node_unreachable",
            &format!("node {} did not answer", node.name),
        )
    }

    /// Asks every node for its sandboxes and makes the store agree. A node
    /// that does not answer keeps its records.
    pub fn reconcile(&self) {
        for node in &self.nodes {
            let asked = Instant::now();
            let answer = self.call(node, "GET", "/v1/sandboxes", None, b"", NODE_TIMEOUT);
            let list = match answer {
                Ok(r) if r.status == 200 => serde_json::from_slice::<SandboxList>(&r.body),
                Ok(r) => {
                    log::warn!(
                        "node {}: listing sandboxes: {}",
                        node.name,
                        r.error_message()
                    );
                    continue;
                }
                Err(err) => {
                    log::debug!("node {}: {err}", node.name);
                    continue;
                }
            };
            let Ok(list) = list else {
                log::warn!("node {}: a malformed sandbox list", node.name);
                continue;
            };
            let records = list
                .sandboxes
                .into_iter()
                .filter_map(|s| {
                    Some(Record {
                        id: SandboxId::parse(&s.id)?,
                        tenant: s.tenant,
                        node: node.name.clone(),
                        template: s.template,
                    })
                })
                .collect();
            self.store.replace_node(&node.name, asked, records);
        }
    }

    fn templates(&self, tenant: &Tenant) -> Response {
        // What a tenant may know of a template: not the node's process ids
        // or how often it restarted.
        #[derive(serde::Serialize)]
        struct PublicTemplate {
            name: String,
            ready: bool,
        }
        let mut templates: Vec<TemplateStatus> = Vec::new();
        for node in &self.nodes {
            let Ok(answer) = self.call(node, "GET", "/v1/node", None, b"", NODE_TIMEOUT) else {
                continue;
            };
            let Ok(status) = serde_json::from_slice::<NodeStatus>(&answer.body) else {
                continue;
            };
            for t in status.templates {
                let visible = t.tenant.as_ref().is_none_or(|only| *only == tenant.name);
                if visible && !templates.iter().any(|o| o.name == t.name && o.ready) {
                    templates.retain(|o| o.name != t.name);
                    templates.push(t);
                }
            }
        }
        templates.sort_by(|a, b| a.name.cmp(&b.name));
        let templates: Vec<PublicTemplate> = templates
            .into_iter()
            .map(|t| PublicTemplate {
                name: t.name,
                ready: t.ready,
            })
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
        // Placement: the first node that takes it. A node that is full,
        // starting its template or does not have it says so, and the next
        // one is asked.
        let mut last = error(404, "template_not_found", "no node has this template");
        for node in &self.nodes {
            match self.call(node, "POST", "/v1/sandboxes", None, &create, NODE_TIMEOUT) {
                Ok(answer) if answer.status == 201 => {
                    let Ok(info) = serde_json::from_slice::<SandboxInfo>(&answer.body) else {
                        log::warn!("node {}: a malformed create answer", node.name);
                        let target = format!("/v1/sandboxes/{id}");
                        let _ = self.call(
                            node,
                            "DELETE",
                            &target,
                            Some(&tenant.name),
                            b"",
                            NODE_TIMEOUT,
                        );
                        return error(502, "node_failed", "the node answered nonsense");
                    };
                    self.store.insert(Record {
                        id,
                        tenant: tenant.name.clone(),
                        node: node.name.clone(),
                        template: body.template.clone(),
                    });
                    return Response::json(201, &info);
                }
                Ok(answer) if matches!(answer.status, 503 | 404) => {
                    last = answer.into_response();
                }
                Ok(answer) => return answer.into_response(),
                // Nothing listens there: the node did not get the request.
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    last = Self::unreachable(node, &err);
                }
                Err(err) => {
                    // The node may have made the sandbox without its
                    // answer arriving. Offering the same id to another
                    // node could make it twice, so placement stops here;
                    // the sandbox is removed if the node can be told, and
                    // otherwise the next reconciliation finds it (the
                    // tenant sees it in its list and it counts).
                    let target = format!("/v1/sandboxes/{id}");
                    let _ = self.call(
                        node,
                        "DELETE",
                        &target,
                        Some(&tenant.name),
                        b"",
                        NODE_TIMEOUT,
                    );
                    return Self::unreachable(node, &err);
                }
            }
        }
        last
    }

    fn list(&self, tenant: &Tenant) -> Response {
        let mut sandboxes = Vec::new();
        let target = format!("/v1/sandboxes?tenant={}", percent_encode(&tenant.name));
        for node in &self.nodes {
            let answer = self
                .call(node, "GET", &target, None, b"", NODE_TIMEOUT)
                .ok()
                .filter(|a| a.status == 200)
                .and_then(|a| serde_json::from_slice::<SandboxList>(&a.body).ok());
            match answer {
                Some(list) => sandboxes.extend(
                    list.sandboxes
                        .into_iter()
                        .filter(|s| s.tenant == tenant.name),
                ),
                None => log::warn!("node {}: no sandbox list", node.name),
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
        let Some(node) = self.node(&record.node) else {
            return not_found();
        };
        let method = request.method.as_str();
        let (target, timeout) = match (method, rest) {
            ("GET" | "DELETE", []) => (format!("/v1/sandboxes/{sandbox}"), NODE_TIMEOUT),
            ("POST", ["exec"]) => {
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
                (
                    format!("/v1/sandboxes/{sandbox}/exec"),
                    Duration::from_secs_f64(timeout) + NODE_TIMEOUT,
                )
            }
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
            Ok(answer) => answer,
            Err(err) => return Self::unreachable(node, &err),
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
