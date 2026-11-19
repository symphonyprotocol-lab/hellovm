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
//! | `GET /v1/sandboxes/{id}/ingress` | | `IngressInfo` (token, exposed ports and their URLs) |
//! | `PUT /v1/sandboxes/{id}/ingress/ports/{port}` | `ExposeRequest` | `IngressInfo` |
//! | `DELETE /v1/sandboxes/{id}/ingress/ports/{port}` | | `IngressInfo` |
//! | `POST /v1/sandboxes/{id}/ingress/token` | | `IngressInfo` (a new token) |
//! | `GET /v1/usage` | | `TenantUsage` |

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm_control::http::{self, percent_encode, ClientResponse, Handler, Request, Response};
use hellovm_control::ids::{token_eq, SandboxId};
use hellovm_control::types::{
    self, check_port, CreateSandbox, DrainRequest, ExecRequest, IngressInfo, NodeCreate,
    NodeIngress, NodeStatus, PollQuery, PortInfo, SandboxInfo, SandboxList, TenantUsage,
    TouchRequest,
};
use hellovm_control::unix_ms;

use crate::config::{valid_name, Config, Node, Tenant};
use crate::meter::{period_start, Meter, Observed};
use crate::meterlog::{LogStatus, LogWriter};
use crate::nodes::{check_status, NoPlace, Nodes, MAX_SANDBOX_MEMORY};
use crate::quota::RateLimiter;
use crate::store::{Record, Refused, Store};

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
/// For requests the node itself waits up to 60 s on a sandbox's agent
/// for (file operations, resetting the interpreter).
const FILE_TIMEOUT: Duration = Duration::from_secs(90);
/// Most nodes that may refuse one creation before it is given up: the
/// reports are at most a probe old, so the first few choices are the ones
/// with room if any has.
const MAX_REFUSALS: usize = 3;

pub struct Api {
    pub config: Config,
    pub tenants: Vec<Tenant>,
    pub nodes: Nodes,
    pub store: Arc<dyn Store>,
    pub meter: Mutex<Meter>,
    /// The usage log's writer, when there is a log.
    pub log: Option<Arc<LogWriter>>,
    pub limiter: RateLimiter,
    /// HTTP ingress, when configured.
    pub ingress: Option<crate::ingress::IngressState>,
}

fn error(status: u16, code: &str, message: &str) -> Response {
    Response::error(status, code, message)
}

fn not_found() -> Response {
    error(404, "sandbox_not_found", "no such sandbox")
}

impl Api {
    /// The API, with what the usage log says (the period's totals, the
    /// last counters of every sandbox, the deletes still to do) read back.
    pub fn new(config: Config, tenants: Vec<Tenant>, nodes: Nodes, store: Arc<dyn Store>) -> Api {
        let now_ms = unix_ms();
        let m = config.metering.clone();
        let names: Vec<String> = tenants.iter().map(|t| t.name.clone()).collect();
        let known = |t: &str| names.iter().any(|n| n == t);
        let rebuilt = match &m.log {
            Some(prefix) => {
                let start = period_start(now_ms / 1000, m.period);
                let r = crate::meterlog::read(prefix, start, m.period, m.max_read_mb << 20, &known);
                log::info!(
                    "usage log: read {} records ({} not records) of the period from {}: {} tenants, \
                     {} sandboxes running, {} deletes to do",
                    r.records,
                    r.bad,
                    crate::meter::utc_stamp(start),
                    r.totals.len(),
                    r.baselines.len(),
                    r.deletes.len()
                );
                if r.truncated {
                    log::error!(
                        "usage log: more than max_read_mb ({}); the period's totals are short",
                        m.max_read_mb
                    );
                }
                r
            }
            None => Default::default(),
        };
        for (id, (tenant, node)) in &rebuilt.deletes {
            if nodes.index(node).is_some() {
                store.add_delete(Record {
                    id: *id,
                    tenant: tenant.clone(),
                    node: node.clone(),
                    template: String::new(),
                    memory_limit: 0,
                });
            }
        }
        let meter = Meter::new(
            m.period,
            now_ms,
            Instant::now(),
            m.log.is_some(),
            (config.max_lifetime * 1000.0) as u64,
            names.clone(),
            &rebuilt,
        );
        Api {
            log: m
                .log
                .map(|prefix| Arc::new(LogWriter::new(prefix, m.max_file_mb))),
            meter: Mutex::new(meter),
            limiter: RateLimiter::default(),
            ingress: None,
            config,
            tenants,
            nodes,
            store,
        }
    }

    fn meter(&self) -> MutexGuard<'_, Meter> {
        self.meter.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Once a second: starts a new period when one began, records what
    /// running sandboxes used when `flush`, and hands the records to the
    /// log.
    pub fn tick(&self, flush: bool) {
        let deletes: Vec<(SandboxId, String, String)> = self
            .store
            .deletes()
            .into_iter()
            .map(|r| (r.id, r.tenant, r.node))
            .collect();
        let counts = self
            .ingress
            .as_ref()
            .map(|i| {
                i.retain(|id| self.store.get(id).is_some());
                i.take_counts()
            })
            .unwrap_or_default();
        let lines = {
            let mut meter = self.meter();
            let now_ms = unix_ms();
            for c in counts {
                meter.ingress(
                    now_ms,
                    &c.sandbox,
                    &c.tenant,
                    &c.node,
                    &c.template,
                    c.received,
                    c.sent,
                );
            }
            meter.tick(now_ms, flush, &deletes);
            meter.take_lines()
        };
        if let Some(log) = &self.log {
            log.push(lines);
        }
    }

    /// A tenant's usage this period and its quotas.
    fn usage_of(&self, tenant: &Tenant) -> TenantUsage {
        let now_ms = unix_ms();
        let (usage, period) = {
            let meter = self.meter();
            let period = crate::meter::period_view(
                period_start(now_ms / 1000, self.config.metering.period),
                self.config.metering.period,
            );
            (meter.totals(&tenant.name, now_ms), period)
        };
        let (sandboxes, memory_limit_bytes) = self.store.held(&tenant.name);
        TenantUsage {
            tenant: tenant.name.clone(),
            period,
            usage,
            sandboxes,
            memory_limit_bytes,
            quotas: tenant.quotas(),
            exceeded: Self::exceeded(tenant, &usage),
        }
    }

    /// The budgets `tenant` used up, by `usage`.
    fn exceeded(tenant: &Tenant, usage: &types::UsageTotals) -> Vec<String> {
        let mut out = Vec::new();
        if tenant.cpu_ms_per_period.is_some_and(|b| usage.cpu_ms >= b) {
            out.push("cpu".to_string());
        }
        let egress = usage
            .egress_sent_bytes
            .saturating_add(usage.egress_received_bytes);
        if tenant.egress_bytes_per_period.is_some_and(|b| egress >= b) {
            out.push("egress".to_string());
        }
        out
    }

    /// `429 budget_exceeded` when `tenant` used up a budget of the
    /// period: no new sandbox, no new exec, until the period ends.
    fn over_budget(&self, tenant: &Tenant) -> Option<Response> {
        if tenant.cpu_ms_per_period.is_none() && tenant.egress_bytes_per_period.is_none() {
            return None;
        }
        let now_ms = unix_ms();
        let (usage, left) = {
            let meter = self.meter();
            (
                meter.totals(&tenant.name, now_ms),
                meter.seconds_left(now_ms),
            )
        };
        let exceeded = Self::exceeded(tenant, &usage);
        if exceeded.is_empty() {
            return None;
        }
        Some(
            error(
                429,
                "budget_exceeded",
                &format!(
                    "the {} budget of this period is used up: no new sandbox or exec until it \
                     ends, in {left} s",
                    exceeded.join(" and ")
                ),
            )
            .with_header("Retry-After", left.to_string()),
        )
    }

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

    /// A request to node `i` failed: logged, and counted against the node
    /// if no connection could be made. A request that was sent and not
    /// answered in time is not counted: how long it takes is partly up to
    /// the sandbox, and one tenant must not make a node unreachable for
    /// the others. The probes find a node that stopped answering.
    fn node_failed(&self, i: usize, err: &std::io::Error) {
        let name = &self.nodes.configs()[i].name;
        log::warn!("node {name}: {err}");
        if http::not_sent(err) {
            self.nodes.connect_failed(i, &err.to_string());
        }
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
        let ask = |cursor: u64| {
            let target = format!("/v1/sandboxes?ended_after={cursor}");
            self.call_max(node, "GET", &target, None, b"", NODE_TIMEOUT, MAX_LIST)
                .map_err(|e| e.to_string())
                .and_then(|r| match r.status {
                    200 => serde_json::from_slice::<SandboxList>(&r.body)
                        .map_err(|_| "a malformed sandbox list".to_string()),
                    status => Err(format!("status {status} for its sandboxes")),
                })
        };
        let (known_boot, mut cursor) = {
            let meter = self.meter();
            (meter.boot(&node.name), meter.cursor(&node.name))
        };
        let mut list = ask(cursor);
        // A node that restarted numbers its ended sandboxes from 1 again:
        // ask from the start.
        if let Ok(l) = &list {
            if cursor > 0 && known_boot.is_some() && l.boot != known_boot {
                cursor = 0;
                list = ask(0);
            }
        }
        let list = match list {
            Ok(list) => list,
            Err(why) => {
                log::warn!("node {}: listing sandboxes: {why}", node.name);
                self.nodes.failed(i, &why);
                return;
            }
        };
        let observed = |s: &SandboxInfo| -> Option<Observed> {
            if !valid_name(&s.tenant) || !valid_name(&s.template) {
                return None;
            }
            Some(Observed {
                id: SandboxId::parse(&s.id)?,
                tenant: s.tenant.clone(),
                template: s.template.clone(),
                usage: s.usage,
                memory_bytes: s.memory_bytes,
                memory_limit: s.memory_limit_bytes.min(MAX_SANDBOX_MEMORY),
                created_at: s.created_at,
            })
        };
        let live: Vec<Observed> = list.sandboxes.iter().filter_map(observed).collect();
        let records: Vec<Record> = live
            .iter()
            .map(|o| Record {
                id: o.id,
                tenant: o.tenant.clone(),
                node: node.name.clone(),
                template: o.template.clone(),
                memory_limit: o.memory_limit,
            })
            .collect();
        // What ended: only `seq`s past the cursor, in order, each once.
        let ended_list = list.ended.unwrap_or_default();
        let mut last_seq = cursor;
        let mut ended = Vec::new();
        for e in &ended_list {
            if e.seq <= last_seq || !valid_name(&e.tenant) || !valid_name(&e.template) {
                continue;
            }
            last_seq = e.seq;
            if let Some(id) = SandboxId::parse(&e.id) {
                ended.push(Observed {
                    id,
                    tenant: e.tenant.clone(),
                    template: e.template.clone(),
                    usage: e.usage,
                    memory_bytes: 0,
                    memory_limit: e.memory_limit_bytes.min(MAX_SANDBOX_MEMORY),
                    created_at: e.created_at,
                });
            }
        }
        let reported: std::collections::HashSet<SandboxId> = live.iter().map(|o| o.id).collect();
        // Usage is counted for the tenant this API made the sandbox for,
        // where it knows: a node that names another tenant for it is not
        // believed (its usage is not counted until it says the right one).
        let mut foreign = 0usize;
        let mut owned = |o: &Observed| {
            let ours = self
                .store
                .get(&o.id)
                .or_else(|| self.store.ended(&o.id))
                .is_none_or(|r| r.tenant == o.tenant);
            if !ours {
                foreign += 1;
            }
            ours
        };
        let live: Vec<Observed> = live.into_iter().filter(&mut owned).collect();
        let ended: Vec<Observed> = ended.into_iter().filter(&mut owned).collect();
        if foreign > 0 {
            log::warn!(
                "node {}: {foreign} sandboxes reported with another tenant than they were made                  for; their usage is not counted",
                node.name
            );
        }
        self.nodes.reported(i, asked, load, true);
        let bounds = self.nodes.bounds(i);
        self.store.replace_node(&node.name, asked, records);
        // A node that does not say when it started (an older one) has its
        // ended sandboxes go unread: they are counted as lost.
        let boot = list.boot.unwrap_or(0);
        self.meter().observe(
            &node.name,
            unix_ms(),
            Instant::now(),
            &bounds,
            live,
            ended,
            boot,
            last_seq,
            !list.ended_more,
        );
        self.finish_deletes(i, &reported);
        self.touch(i, timeout);
    }

    /// Tells node `i` which of its sandboxes were used through ingress
    /// since the last probe (their idle timeouts start again). Whether it
    /// answers does not count for its health.
    fn touch(&self, i: usize, timeout: Duration) {
        let Some(ingress) = &self.ingress else {
            return;
        };
        let node = &self.nodes.configs()[i];
        let ids = ingress.take_touched(&node.name);
        for chunk in ids.chunks(types::MAX_TOUCH) {
            let body = TouchRequest {
                sandboxes: chunk.iter().map(|id| id.to_string()).collect(),
            };
            let Ok(body) = serde_json::to_vec(&body) else {
                return;
            };
            if let Err(err) = self.call_max(
                node,
                "POST",
                "/v1/node/touch",
                None,
                &body,
                timeout,
                MAX_STATUS,
            ) {
                log::debug!("node {}: touching sandboxes: {err}", node.name);
                return;
            }
        }
    }

    /// The ingress counters the API keeps, in a node's answer about a
    /// sandbox (the node reports none).
    fn with_ingress_usage(&self, info: &mut SandboxInfo) {
        if let Some(id) = SandboxId::parse(&info.id) {
            let (received, sent) = self.meter().ingress_of(&id);
            info.usage.ingress_received_bytes = received;
            info.usage.ingress_sent_bytes = sent;
        }
    }

    /// A node's answer about a sandbox's ingress as its tenant sees it:
    /// with the ports' URLs. Remembered for the ingress listener.
    fn ingress_answer(&self, sandbox: SandboxId, answer: ClientResponse) -> Response {
        let Some(ingress) = &self.ingress else {
            return Self::ingress_disabled();
        };
        if answer.status != 200 {
            return answer.into_response();
        }
        let state = match serde_json::from_slice::<NodeIngress>(&answer.body) {
            Ok(state) if crate::ingress::valid_state(&state) => state,
            _ => return error(502, "node_failed", "the node's answer is not valid"),
        };
        let info = IngressInfo {
            token: state.token.clone(),
            ports: state
                .ports
                .iter()
                .map(|p| PortInfo {
                    port: p.port,
                    public: p.public,
                    url: ingress.url(p.port, &sandbox),
                })
                .collect(),
        };
        ingress.remember(sandbox, state);
        Response::json(200, &info)
    }

    fn ingress_disabled() -> Response {
        error(
            404,
            "ingress_disabled",
            "ingress is not configured on this API",
        )
    }

    /// Does the deletes that waited for node `i`, which answered and runs
    /// `reported`.
    fn finish_deletes(&self, i: usize, reported: &std::collections::HashSet<SandboxId>) {
        let node = &self.nodes.configs()[i];
        for record in self.store.deletes() {
            if record.node != node.name {
                continue;
            }
            let done = if reported.contains(&record.id) {
                let target = format!("/v1/sandboxes/{}", record.id);
                match self.call(
                    node,
                    "DELETE",
                    &target,
                    Some(&record.tenant),
                    b"",
                    NODE_TIMEOUT,
                ) {
                    Ok(a) => {
                        a.status == 204
                            || matches!(
                                a.error_code().as_deref(),
                                Some("sandbox_not_found" | "sandbox_ended")
                            )
                    }
                    Err(err) => {
                        // The node stopped answering: the rest waits for
                        // the next probe rather than holding this one up
                        // for a timeout each.
                        self.node_failed(i, &err);
                        return;
                    }
                }
            } else {
                // Not on the node any more (it ended, or died with it).
                true
            };
            if done {
                self.store.delete_done(&record.id);
                self.meter()
                    .note_delete(unix_ms(), &record.id, &record.tenant, &node.name, true);
                log::info!(
                    "sandbox {} of {}: the delete that waited for node {} is done",
                    record.id,
                    record.tenant,
                    node.name
                );
            }
        }
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
        if let Some(refused) = self.over_budget(tenant) {
            return refused;
        }
        // What its sandbox may use, by the nodes' reports (the largest, as
        // the node is not chosen yet).
        let memory = self
            .nodes
            .template_memory(&body.template, &tenant.name)
            .unwrap_or(0);
        let _slot = match self.store.reserve(
            &tenant.name,
            tenant.max_sandboxes,
            memory,
            tenant.max_memory_bytes,
        ) {
            Ok(slot) => slot,
            Err(Refused::Count) => {
                return error(
                    429,
                    "tenant_limit",
                    &format!("at most {} sandboxes at once", tenant.max_sandboxes),
                )
            }
            Err(Refused::Memory) => {
                return Self::memory_limit(tenant.max_memory_bytes.unwrap_or(0))
            }
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
                        self.made_maybe(i, tenant, id, &body.template, memory);
                        return error(502, "node_failed", "the sandbox could not be made");
                    };
                    self.nodes.done(i, true);
                    let actual = info.memory_limit_bytes.min(MAX_SANDBOX_MEMORY);
                    self.store.insert(Record {
                        id,
                        tenant: tenant.name.clone(),
                        node: node.name.clone(),
                        template: body.template.clone(),
                        memory_limit: actual,
                    });
                    // The sandbox's limit is larger than what was reserved
                    // (no node had reported the template's, or this node's
                    // is larger): checked again with the real one, and the
                    // sandbox removed if the tenant is over.
                    if let Some(max) = tenant.max_memory_bytes.filter(|_| actual > memory) {
                        let (_, held) = self.store.held(&tenant.name);
                        // `held` counts this sandbox and its reservation.
                        if held.saturating_sub(memory) > max {
                            self.store.forget(&id);
                            self.made_maybe(i, tenant, id, &body.template, actual);
                            return Self::memory_limit(max);
                        }
                    }
                    return Response::json(201, &info);
                }
                Ok(answer) => {
                    self.nodes.answered(i);
                    self.nodes.done(i, false);
                    let code = answer.error_code().unwrap_or_default();
                    // What a node says in the ordinary course, and what
                    // an operator should hear of.
                    let expected = matches!(
                        code.as_str(),
                        "template_not_found" | "template_not_ready" | "node_full" | "node_draining"
                    );
                    let level = if expected {
                        log::Level::Debug
                    } else {
                        log::Level::Warn
                    };
                    log::log!(
                        level,
                        "node {}: create refused: {} {:?}: {:?}",
                        node.name,
                        answer.status,
                        code.chars().take(64).collect::<String>(),
                        answer.error_message().chars().take(256).collect::<String>()
                    );
                    answers.push(code);
                    if answers.len() >= MAX_REFUSALS {
                        return Self::no_place(NoPlace::Full, &answers);
                    }
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
                    self.made_maybe(i, tenant, id, &body.template, memory);
                    return Self::unreachable();
                }
            }
        }
    }

    fn memory_limit(max: u64) -> Response {
        error(
            429,
            "memory_limit",
            &format!(
                "the memory limits of all sandboxes may add up to at most {} MiB",
                max >> 20
            ),
        )
    }

    /// Node `i` may have made sandbox `id` (its answer to the create was
    /// lost or broken): it is removed if the node says so, and otherwise
    /// kept in the store, where it counts against the tenant's limit until
    /// the node's next list shows whether it exists (and the tenant sees it
    /// then if it does).
    fn made_maybe(&self, i: usize, tenant: &Tenant, id: SandboxId, template: &str, memory: u64) {
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
                memory_limit: memory,
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
        // The nodes that have sandboxes of this tenant, by the store
        // (which knows every sandbox made here at once, and the others
        // from the last probe), at once; an unreachable one is not asked
        // (its sandboxes are not listed while it is).
        let mut asked: Vec<usize> = self
            .store
            .of_tenant(&tenant.name)
            .iter()
            .filter_map(|r| self.nodes.index(&r.node))
            .filter(|i| self.nodes.reachable(*i))
            .collect();
        asked.sort_unstable();
        asked.dedup();
        let ask = |i: usize| {
            let node = &self.nodes.configs()[i];
            match self.call_max(node, "GET", &target, None, b"", NODE_TIMEOUT, MAX_LIST) {
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
        };
        let lists: Vec<(usize, Option<SandboxList>)> = match asked.as_slice() {
            // The usual case needs no thread.
            [i] => vec![(*i, ask(*i))],
            _ => std::thread::scope(|scope| {
                let ask = &ask;
                let asks: Vec<_> = asked
                    .iter()
                    .map(|&i| (i, scope.spawn(move || ask(i))))
                    .collect();
                asks.into_iter()
                    .map(|(i, a)| (i, a.join().ok().flatten()))
                    .collect()
            }),
        };
        // Deleted while their node did not answer: gone for the tenant.
        let deleted: std::collections::HashSet<String> = self
            .store
            .deletes()
            .into_iter()
            .map(|r| r.id.to_string())
            .collect();
        let mut sandboxes = Vec::new();
        for (i, list) in lists {
            let node = &self.nodes.configs()[i].name;
            match list {
                // Only what this node runs for this tenant.
                Some(list) => sandboxes.extend(list.sandboxes.into_iter().filter(|s| {
                    s.tenant == tenant.name && s.node == *node && !deleted.contains(&s.id)
                })),
                None => log::debug!("node {node}: no sandbox list"),
            }
        }
        sandboxes.sort_by_key(|s| (s.created_at, s.id.clone()));
        for s in &mut sandboxes {
            self.with_ingress_usage(s);
        }
        Response::json(
            200,
            &SandboxList {
                sandboxes,
                ended: None,
                ended_more: false,
                boot: None,
            },
        )
    }

    /// Its tenant deletes a sandbox whose node does not answer: it stops
    /// counting and being listed now, and is deleted on the node once the
    /// node answers (`202`). When too many deletes wait on that node
    /// already, or the sandbox is gone from the store, `502` as before.
    fn delete_later(&self, record: &Record) -> Response {
        match self.store.delete_later(&record.id) {
            Some(r) => {
                // Written before the answer: an API that restarts before
                // the node is back still knows to delete it.
                let lines = {
                    let mut meter = self.meter();
                    meter.note_delete(unix_ms(), &r.id, &r.tenant, &r.node, false);
                    meter.take_lines()
                };
                if let Some(log) = &self.log {
                    log.push(lines);
                    // Not while the log cannot be written: the writer
                    // thread retries that, and this request would only
                    // wait for the same error.
                    if log.status().healthy {
                        log.write_some();
                    }
                }
                log::info!(
                    "sandbox {} of {}: deleted while node {} does not answer; it is deleted \
                     there once it does",
                    r.id,
                    r.tenant,
                    r.node
                );
                Response::empty(202)
            }
            None => Self::unreachable(),
        }
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
        let method = request.method.as_str();
        let delete = method == "DELETE" && rest.is_empty();
        if rest.first() == Some(&"ingress") && self.ingress.is_none() {
            return Self::ingress_disabled();
        }
        if !self.nodes.reachable(i) {
            if delete {
                return self.delete_later(&record);
            }
            return Self::unreachable();
        }
        if method == "POST" && matches!(rest, ["exec" | "execs"]) {
            if let Some(refused) = self.over_budget(tenant) {
                return refused;
            }
        }
        let node = &self.nodes.configs()[i];
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
                FILE_TIMEOUT,
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
            ("GET", ["ingress"]) => (format!("/v1/sandboxes/{sandbox}/ingress"), NODE_TIMEOUT),
            ("POST", ["ingress", "token"]) => (
                format!("/v1/sandboxes/{sandbox}/ingress/token"),
                NODE_TIMEOUT,
            ),
            ("PUT" | "DELETE", ["ingress", "ports", port]) => {
                let Some(port) = check_port(port) else {
                    return error(400, "bad_request", "a port is 1 to 65535");
                };
                if method == "PUT" && !request.body.is_empty() {
                    if let Err(e) = serde_json::from_slice::<types::ExposeRequest>(&request.body) {
                        return error(400, "bad_request", &format!("malformed JSON body: {e}"));
                    }
                }
                (
                    format!("/v1/sandboxes/{sandbox}/ingress/ports/{port}"),
                    NODE_TIMEOUT,
                )
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
                // Whether or not the node got it, the delete is done once
                // it answers again.
                if delete {
                    return self.delete_later(&record);
                }
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
        if rest.first() == Some(&"ingress") {
            return self.ingress_answer(sandbox, answer);
        }
        if method == "GET" && rest.is_empty() && answer.status == 200 {
            if let Ok(mut info) = serde_json::from_slice::<SandboxInfo>(&answer.body) {
                self.with_ingress_usage(&mut info);
                return Response::json(200, &info);
            }
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
        // Only a request with a valid token takes from (its own) bucket.
        if let Some((rate, burst)) = tenant.rate {
            if let Err(wait) = self.limiter.take(&tenant.name, rate, burst, Instant::now()) {
                return error(
                    429,
                    "rate_limited",
                    &format!("more than {rate} requests per second; try again in {wait} s"),
                )
                .with_header("Retry-After", wait.to_string());
            }
        }
        let segments = request.segments();
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["v1", "usage"]) => Response::json(200, &self.usage_of(tenant)),
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
/// | `GET /admin/v1/usage` | every tenant's `TenantUsage`, and the log's state |
/// | `GET /admin/v1/usage/{tenant}` | `TenantUsage` |
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
                api.nodes.reported(i, asked, load, false);
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
            ("GET", ["admin", "v1", "usage"]) => {
                #[derive(serde::Serialize)]
                struct Log {
                    path: String,
                    #[serde(flatten)]
                    status: LogStatus,
                }
                let api = &self.api;
                let tenants: Vec<TenantUsage> =
                    api.tenants.iter().map(|t| api.usage_of(t)).collect();
                let (tracked, odd) = {
                    let meter = api.meter();
                    (meter.tracked(), meter.odd)
                };
                let log = api.log.as_ref().map(|w| Log {
                    path: api
                        .config
                        .metering
                        .log
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    status: w.status(),
                });
                Response::json(
                    200,
                    &serde_json::json!({
                        "tenants": tenants,
                        "sandboxes_metered": tracked,
                        "odd_reports": odd,
                        "deletes_waiting": api.store.deletes().len(),
                        "ingress_connections": api.ingress.as_ref().map(|i| i.open()),
                        "log": log,
                    }),
                )
            }
            ("GET", ["admin", "v1", "usage", name]) => {
                match self.api.tenants.iter().find(|t| t.name == *name) {
                    Some(t) => Response::json(200, &self.api.usage_of(t)),
                    None => error(404, "tenant_not_found", "no such tenant"),
                }
            }
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
