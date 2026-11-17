//! The sandboxes of one node: made from a warm template, reached through
//! the agent in them, removed when asked, idle, too old, over their memory
//! limit, or ended.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm::warm::{Frame, WarmClone};
use hellovm_control::http::Response;
use hellovm_control::ids::SandboxId;
use hellovm_control::types::{
    self, EditRequest, EditResult, ExecRequest, ExecResult, NodeCreate, NodeStatus, SandboxInfo,
    WriteResult,
};
use hellovm_control::unix_ms;
use serde_json::{json, Map, Value};

use crate::agent::{Agent, AgentError};
use crate::config::{valid_name, Config};
use crate::template::Template;

/// How long a new clone may take to run and to greet.
const START_DEADLINE: Duration = Duration::from_secs(15);
/// Longest wait for a file operation's answer.
const FILE_DEADLINE: Duration = Duration::from_secs(60);
/// Extra time for an exec's answer past its timeout.
const EXEC_GRACE: Duration = Duration::from_secs(10);
/// Longest idle timeout and lifetime a sandbox may have: a week.
pub const MAX_LIFETIME: f64 = 7.0 * 24.0 * 3600.0;
/// Ended sandboxes remembered, to tell why they are gone.
const TOMBSTONES: usize = 4096;
/// Bytes of a sandbox's agent log (its stderr) passed to noded's log.
const LOG_BUDGET: usize = 64 * 1024;

/// An error as the node API reports it.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn response(&self) -> Response {
        Response::error(self.status, &self.code, &self.message)
    }

    fn not_found() -> ApiError {
        ApiError::new(404, "sandbox_not_found", "no such sandbox")
    }
}

/// Maps an operation that failed inside the sandbox to a status.
fn failed(code: String, message: String) -> ApiError {
    let status = match code.as_str() {
        "not_found" => 404,
        "permission_denied" => 403,
        "too_large" => 413,
        "no_match" | "ambiguous" => 422,
        "no_space" => 507,
        "agent_error" | "io_error" => 500,
        _ => 400,
    };
    ApiError {
        status,
        code,
        message,
    }
}

pub struct Sandbox {
    pub id: SandboxId,
    pub tenant: String,
    pub template: String,
    created_at: u64,
    created: Instant,
    lifetime: Duration,
    idle_timeout: Duration,
    /// When the last request started or ended (monotonic and Unix ms).
    last_used: Mutex<(Instant, u64)>,
    /// The clone's kernel process (from the template's `S`).
    kernel_pid: u32,
    /// The clone's control connection: shutting it down kills the clone.
    control: UnixStream,
    agent: Mutex<Agent>,
    busy: AtomicBool,
    memory: AtomicU64,
    memory_limit: u64,
    ready_ms: f64,
}

impl Sandbox {
    fn touch(&self) {
        *lock(&self.last_used) = (Instant::now(), unix_ms());
    }

    fn info(&self, node: &str) -> SandboxInfo {
        let (_, last_used_at) = *lock(&self.last_used);
        SandboxInfo {
            id: self.id.to_string(),
            tenant: self.tenant.clone(),
            template: self.template.clone(),
            node: node.to_string(),
            egress_id: format!("{:016x}", self.id.egress_id()),
            created_at: self.created_at,
            last_used_at,
            expires_at: self.created_at + self.lifetime.as_millis() as u64,
            idle_timeout: self.idle_timeout.as_secs_f64(),
            memory_bytes: self.memory.load(Ordering::Relaxed),
            memory_limit_bytes: self.memory_limit,
            ready_ms: self.ready_ms,
        }
    }

    /// Kills the clone: the template sees the connection's write side
    /// close and kills its kernel process.
    fn kill(&self) {
        let _ = self.control.shutdown(Shutdown::Write);
    }
}

/// Holds a sandbox for one operation: the agent serves one at a time.
struct Busy<'a>(&'a Sandbox);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.touch();
        self.0.busy.store(false, Ordering::SeqCst);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Tombstone {
    id: SandboxId,
    tenant: String,
    reason: String,
}

pub struct Node {
    pub config: Config,
    pub templates: Vec<Arc<Template>>,
    sandboxes: Mutex<HashMap<SandboxId, Arc<Sandbox>>>,
    /// Creations in progress, counted against `max_sandboxes`.
    creating: AtomicUsize,
    ended: Mutex<VecDeque<Tombstone>>,
}

/// Counts a creation in progress.
struct Creating<'a>(&'a AtomicUsize);

impl Drop for Creating<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Node {
    pub fn new(config: Config, templates: Vec<Arc<Template>>) -> Node {
        Node {
            config,
            templates,
            sandboxes: Mutex::new(HashMap::new()),
            creating: AtomicUsize::new(0),
            ended: Mutex::new(VecDeque::new()),
        }
    }

    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            node: self.config.node.clone(),
            templates: self.templates.iter().map(|t| t.status()).collect(),
            sandboxes: lock(&self.sandboxes).len(),
            max_sandboxes: self.config.max_sandboxes,
        }
    }

    pub fn list(&self, tenant: Option<&str>) -> Vec<SandboxInfo> {
        let mut list: Vec<SandboxInfo> = lock(&self.sandboxes)
            .values()
            .filter(|s| tenant.is_none_or(|t| s.tenant == t))
            .map(|s| s.info(&self.config.node))
            .collect();
        list.sort_by_key(|s| (s.created_at, s.id.clone()));
        list
    }

    /// The sandbox `id` of `tenant` (any tenant when `None`). Another
    /// tenant's sandbox is reported as missing, like one that never was.
    fn get(&self, id: &str, tenant: Option<&str>) -> Result<Arc<Sandbox>, ApiError> {
        let id = SandboxId::parse(id).ok_or_else(ApiError::not_found)?;
        if let Some(sandbox) = lock(&self.sandboxes).get(&id) {
            if tenant.is_none_or(|t| sandbox.tenant == t) {
                return Ok(Arc::clone(sandbox));
            }
            return Err(ApiError::not_found());
        }
        let ended = lock(&self.ended);
        match ended
            .iter()
            .find(|t| t.id == id && tenant.is_none_or(|tenant| t.tenant == tenant))
        {
            Some(t) => Err(ApiError::new(
                410,
                "sandbox_ended",
                format!("the sandbox ended: {}", t.reason),
            )),
            None => Err(ApiError::not_found()),
        }
    }

    pub fn info(&self, id: &str, tenant: Option<&str>) -> Result<SandboxInfo, ApiError> {
        Ok(self.get(id, tenant)?.info(&self.config.node))
    }

    /// Removes a sandbox and kills it. Returns whether it was there.
    pub fn remove(&self, id: SandboxId, reason: &str) -> bool {
        let Some(sandbox) = lock(&self.sandboxes).remove(&id) else {
            return false;
        };
        sandbox.kill();
        log::info!("sandbox {id} of {} removed: {reason}", sandbox.tenant);
        let mut ended = lock(&self.ended);
        if ended.len() >= TOMBSTONES {
            ended.pop_front();
        }
        ended.push_back(Tombstone {
            id,
            tenant: sandbox.tenant.clone(),
            reason: reason.to_string(),
        });
        true
    }

    pub fn delete(&self, id: &str, tenant: Option<&str>) -> Result<(), ApiError> {
        let sandbox = self.get(id, tenant)?;
        self.remove(sandbox.id, "deleted");
        Ok(())
    }

    /// Makes a sandbox: a clone of the template whose agent has greeted.
    pub fn create(self: &Arc<Self>, request: NodeCreate) -> Result<SandboxInfo, ApiError> {
        let started = Instant::now();
        let id = SandboxId::parse(&request.id)
            .ok_or_else(|| ApiError::new(400, "bad_request", "malformed sandbox id"))?;
        if !valid_name(&request.tenant) {
            return Err(ApiError::new(400, "bad_request", "malformed tenant name"));
        }
        for (what, value) in [
            ("idle_timeout", request.idle_timeout),
            ("lifetime", request.lifetime),
        ] {
            if !(value.is_finite() && value > 0.0 && value <= MAX_LIFETIME) {
                return Err(ApiError::new(
                    400,
                    "bad_request",
                    format!("{what} must be more than 0 and at most {MAX_LIFETIME} seconds"),
                ));
            }
        }
        let template = self
            .templates
            .iter()
            .find(|t| t.config.name == request.template)
            .ok_or_else(|| ApiError::new(404, "template_not_found", "no such template"))?;
        if template
            .config
            .tenant
            .as_ref()
            .is_some_and(|t| *t != request.tenant)
        {
            return Err(ApiError::new(404, "template_not_found", "no such template"));
        }
        if !template.is_ready() {
            return Err(ApiError::new(
                503,
                "template_not_ready",
                "the template is starting; try again shortly",
            ));
        }
        let _creating = {
            let sandboxes = lock(&self.sandboxes);
            if sandboxes.contains_key(&id) {
                return Err(ApiError::new(
                    409,
                    "exists",
                    "a sandbox with this id exists",
                ));
            }
            if sandboxes.len() + self.creating.load(Ordering::SeqCst) >= self.config.max_sandboxes {
                return Err(ApiError::new(503, "node_full", "this node is full"));
            }
            self.creating.fetch_add(1, Ordering::SeqCst);
            Creating(&self.creating)
        };
        let internal = |what: &str, err: &dyn std::fmt::Display| {
            log::warn!("sandbox {id}: {what}: {err}");
            ApiError::new(503, "clone_failed", format!("{what}: {err}"))
        };
        let (in_r, in_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let (out_r, out_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let (err_r, err_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let mut clone = WarmClone::request(
            &template.socket,
            Some(id.egress_id()),
            b"",
            [in_r.as_fd(), out_w.as_fd(), err_w.as_fd()],
        )
        .map_err(|e| internal("asking the template for a clone", &e))?;
        // Only the clone holds these now.
        drop((in_r, out_w, err_w));
        clone
            .stream()
            .set_read_timeout(Some(START_DEADLINE))
            .map_err(|e| internal("the clone connection", &e))?;
        let run = clone
            .start()
            .map_err(|e| internal("starting the clone", &e))?;
        let mut agent = Agent::new(OwnedFd::from(in_w), OwnedFd::from(out_r))
            .map_err(|e| internal("the agent channel", &e))?;
        agent
            .hello(started + START_DEADLINE)
            .map_err(|e| internal("the agent's greeting", &e))?;
        let control = clone
            .stream()
            .try_clone()
            .map_err(|e| internal("the clone connection", &e))?;
        let ready_ms = started.elapsed().as_secs_f64() * 1000.0;
        let sandbox = Arc::new(Sandbox {
            id,
            tenant: request.tenant,
            template: request.template,
            created_at: unix_ms(),
            created: Instant::now(),
            lifetime: Duration::from_secs_f64(request.lifetime),
            idle_timeout: Duration::from_secs_f64(request.idle_timeout),
            last_used: Mutex::new((Instant::now(), unix_ms())),
            kernel_pid: run.pid,
            control,
            agent: Mutex::new(agent),
            busy: AtomicBool::new(false),
            memory: AtomicU64::new(0),
            memory_limit: template.config.memory_limit_mb << 20,
            ready_ms,
        });
        let info = sandbox.info(&self.config.node);
        {
            let mut sandboxes = lock(&self.sandboxes);
            sandboxes.insert(id, Arc::clone(&sandbox));
        }
        let node = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("sandbox-watch".into())
            .spawn(move || node.watch(id, clone, OwnedFd::from(err_r)));
        if let Err(err) = spawned {
            self.remove(id, "no thread to watch it");
            return Err(internal("watching the sandbox", &err));
        }
        log::info!(
            "sandbox {id} of {} from {} ready in {ready_ms:.1} ms (kernel pid {})",
            info.tenant,
            info.template,
            sandbox.kernel_pid
        );
        Ok(info)
    }

    /// Follows a sandbox until it ends: its control connection reports the
    /// end, its stderr (the agent's log) goes to noded's log, bounded.
    fn watch(&self, id: SandboxId, clone: WarmClone, stderr: OwnedFd) {
        let mut logged = 0usize;
        let mut stderr = Some(std::fs::File::from(stderr));
        let reason = loop {
            let mut polls = [
                libc::pollfd {
                    fd: clone.stream().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stderr.as_ref().map_or(-1, |f| f.as_raw_fd()),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: a valid array of pollfds.
            let n = unsafe { libc::poll(polls.as_mut_ptr(), 2, 60_000) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break format!("watching failed: {err}");
            }
            if polls[1].revents != 0 {
                let mut chunk = [0u8; 4096];
                match stderr.as_mut().map(|f| f.read(&mut chunk)) {
                    Some(Ok(n)) if n > 0 => {
                        if logged < LOG_BUDGET {
                            let text = String::from_utf8_lossy(&chunk[..n]);
                            for line in text.lines().filter(|l| !l.is_empty()) {
                                let line: String =
                                    line.chars().filter(|c| !c.is_control()).take(500).collect();
                                log::info!("sandbox {id}: {line}");
                            }
                            logged += n;
                            if logged >= LOG_BUDGET {
                                log::info!("sandbox {id}: more log output is dropped");
                            }
                        }
                    }
                    _ => stderr = None,
                }
            }
            if polls[0].revents != 0 {
                let _ = clone
                    .stream()
                    .set_read_timeout(Some(Duration::from_secs(5)));
                break match Frame::read_from(&mut clone.stream()) {
                    Ok(Some(Frame::Exit(status))) => format!("its agent ended ({status:?})"),
                    Ok(Some(Frame::Error(text))) => format!("the clone failed: {text}"),
                    Ok(Some(other)) => format!("unexpected {other:?} from the template"),
                    Ok(None) => "the template closed its connection".into(),
                    Err(err) => format!("its connection failed: {err}"),
                };
            }
        };
        self.remove(id, &reason);
        drop(clone);
    }

    /// Removes sandboxes past their lifetime, idle too long, or over their
    /// memory limit. Runs for ever.
    pub fn reap(&self) {
        let mut last_memory = Instant::now() - Duration::from_secs(10);
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let sandboxes: Vec<Arc<Sandbox>> = lock(&self.sandboxes).values().cloned().collect();
            for s in &sandboxes {
                if s.created.elapsed() >= s.lifetime {
                    self.remove(s.id, "its lifetime is over");
                } else if !s.busy.load(Ordering::SeqCst)
                    && lock(&s.last_used).0.elapsed() >= s.idle_timeout
                {
                    self.remove(s.id, "it was idle too long");
                }
            }
            if last_memory.elapsed() >= Duration::from_secs(1) && !sandboxes.is_empty() {
                last_memory = Instant::now();
                let pids: Vec<u32> = sandboxes.iter().map(|s| s.kernel_pid).collect();
                let usage = crate::memory::measure(&pids);
                for s in &sandboxes {
                    let bytes = usage.get(&s.kernel_pid).copied().unwrap_or(0);
                    s.memory.store(bytes, Ordering::Relaxed);
                    if bytes > s.memory_limit {
                        self.remove(
                            s.id,
                            &format!(
                                "its memory ({} MiB) went over the limit ({} MiB)",
                                bytes >> 20,
                                s.memory_limit >> 20
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Runs `op` against the sandbox's agent: one operation at a time.
    fn with_agent<T>(
        &self,
        id: &str,
        tenant: Option<&str>,
        op: impl FnOnce(&mut Agent) -> Result<T, AgentError>,
    ) -> Result<T, ApiError> {
        let sandbox = self.get(id, tenant)?;
        if sandbox
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ApiError::new(
                409,
                "busy",
                "the sandbox is running another request",
            ));
        }
        sandbox.touch();
        let _busy = Busy(&sandbox);
        let result = op(&mut lock(&sandbox.agent));
        match result {
            Ok(value) => Ok(value),
            Err(AgentError::Failed { code, message }) => Err(failed(code, message)),
            Err(AgentError::Broken(why)) => {
                // Removed meanwhile (deleted, over a limit): say why.
                if let Err(err) = self.get(id, tenant) {
                    if err.status == 410 {
                        return Err(err);
                    }
                }
                self.remove(sandbox.id, &format!("its agent failed: {why}"));
                Err(ApiError::new(
                    502,
                    "sandbox_failed",
                    format!("the sandbox failed and was removed: {why}"),
                ))
            }
        }
    }

    pub fn exec(
        &self,
        id: &str,
        tenant: Option<&str>,
        request: &ExecRequest,
    ) -> Result<ExecResult, ApiError> {
        let (timeout, max_output) = request
            .validate()
            .map_err(|m| ApiError::new(400, "bad_request", m))?;
        let mut head = Map::new();
        head.insert("op".into(), json!("exec"));
        head.insert("command".into(), json!(request.command));
        head.insert("python".into(), json!(request.python));
        head.insert("timeout".into(), json!(timeout));
        head.insert("max_output".into(), json!(max_output));
        head.insert("cwd".into(), json!(request.cwd));
        head.insert("env".into(), json!(request.env));
        head.insert("has_stdin".into(), json!(request.stdin.is_some()));
        let stdin = request.stdin.as_deref().unwrap_or("").as_bytes();
        let deadline = Instant::now() + Duration::from_secs_f64(timeout) + EXEC_GRACE;
        // Both streams, each at most max_output plus the omission line.
        let max_body = 2 * (max_output + 128);
        let (answer, body) = self.with_agent(id, tenant, |agent| {
            agent.call(head, stdin, deadline, max_body)
        })?;
        exec_result(&answer, &body).map_err(|why| {
            ApiError::new(
                502,
                "sandbox_failed",
                format!("a malformed exec answer: {why}"),
            )
        })
    }

    pub fn read_file(
        &self,
        id: &str,
        tenant: Option<&str>,
        path: &str,
    ) -> Result<Vec<u8>, ApiError> {
        types::check_path(path).map_err(|m| ApiError::new(400, "bad_request", m))?;
        let head = map(json!({"op": "read", "path": path, "max_bytes": types::MAX_FILE}));
        let deadline = Instant::now() + FILE_DEADLINE;
        let (_, body) = self.with_agent(id, tenant, |agent| {
            agent.call(head, b"", deadline, types::MAX_FILE)
        })?;
        Ok(body)
    }

    pub fn write_file(
        &self,
        id: &str,
        tenant: Option<&str>,
        path: &str,
        data: &[u8],
    ) -> Result<WriteResult, ApiError> {
        types::check_path(path).map_err(|m| ApiError::new(400, "bad_request", m))?;
        if data.len() > types::MAX_FILE {
            return Err(ApiError::new(413, "too_large", "the file is too large"));
        }
        let head = map(json!({"op": "write", "path": path}));
        let deadline = Instant::now() + FILE_DEADLINE;
        self.with_agent(id, tenant, |agent| agent.call(head, data, deadline, 0))?;
        Ok(WriteResult {
            bytes: data.len() as u64,
        })
    }

    pub fn edit_file(
        &self,
        id: &str,
        tenant: Option<&str>,
        request: &EditRequest,
    ) -> Result<EditResult, ApiError> {
        types::check_path(&request.path).map_err(|m| ApiError::new(400, "bad_request", m))?;
        if request.old.is_empty() {
            return Err(ApiError::new(400, "bad_request", "old must not be empty"));
        }
        let head = map(
            json!({"op": "edit", "path": request.path, "old": request.old,
            "new": request.new, "replace_all": request.replace_all, "max_bytes": types::MAX_FILE}),
        );
        let deadline = Instant::now() + FILE_DEADLINE;
        let (answer, _) =
            self.with_agent(id, tenant, |agent| agent.call(head, b"", deadline, 0))?;
        let replacements = answer
            .get("replacements")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::new(502, "sandbox_failed", "a malformed edit answer"))?;
        Ok(EditResult { replacements })
    }

    /// Kills every sandbox (at shutdown).
    pub fn remove_all(&self, reason: &str) {
        let ids: Vec<SandboxId> = lock(&self.sandboxes).keys().copied().collect();
        for id in ids {
            self.remove(id, reason);
        }
    }
}

fn map(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// Builds the exec result from the agent's answer, checking every field.
fn exec_result(answer: &Map<String, Value>, body: &[u8]) -> Result<ExecResult, String> {
    let int = |key: &str| -> Result<Option<i32>, String> {
        match answer.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| format!("{key} is not a small integer")),
        }
    };
    let count = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_u64)
            .ok_or(format!("no {key}"))
    };
    let flag = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_bool)
            .ok_or(format!("no {key}"))
    };
    let split = count("stdout_len")? as usize;
    if split > body.len() {
        return Err("stdout_len past the body".into());
    }
    let duration_ms = answer
        .get("duration_ms")
        .and_then(Value::as_f64)
        .filter(|d| d.is_finite() && *d >= 0.0)
        .ok_or("no duration_ms")?;
    Ok(ExecResult {
        exit_code: int("exit_code")?,
        signal: int("signal")?,
        timed_out: flag("timed_out")?,
        stdout: String::from_utf8_lossy(&body[..split]).into_owned(),
        stderr: String::from_utf8_lossy(&body[split..]).into_owned(),
        stdout_truncated: flag("stdout_truncated")?,
        stderr_truncated: flag("stderr_truncated")?,
        stdout_bytes: count("stdout_bytes")?,
        stderr_bytes: count("stderr_bytes")?,
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_answers_are_checked() {
        let good = map(json!({"exit_code": 0, "signal": null, "timed_out": false,
            "stdout_len": 3, "stdout_truncated": false, "stderr_truncated": false,
            "stdout_bytes": 3, "stderr_bytes": 2, "duration_ms": 1.5}));
        let r = exec_result(&good, b"out\xffe").unwrap();
        assert_eq!(r.stdout, "out");
        assert_eq!(r.stderr, "\u{fffd}e");
        let mut past = good.clone();
        past.insert("stdout_len".into(), json!(99));
        assert!(exec_result(&past, b"x").is_err());
        let mut huge = good.clone();
        huge.insert("exit_code".into(), json!(1u64 << 40));
        assert!(exec_result(&huge, b"out").is_err());
        let mut missing = good;
        missing.remove("timed_out");
        assert!(exec_result(&missing, b"out").is_err());
    }
}
