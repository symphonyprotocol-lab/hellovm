//! The sandboxes of one node: made from a warm template, reached through
//! the agent in them, removed when asked, idle, too old, over their memory
//! limit, or ended.
//!
//! Each sandbox has at most one operation outstanding at its agent (an
//! exec, a file operation, a reset): taking it is `busy`, and a second
//! one is refused (`409`). An exec holds the sandbox from its start until
//! its final answer, whether or not anyone waits for it; reading its
//! output, listing it and cancelling it never take the sandbox. The
//! sandbox's watch thread reads everything the agent says as it comes
//! (see `agent.rs`), passes output to the exec it belongs to, completes
//! operations, and removes the sandbox when the agent breaks the protocol
//! or misses a deadline.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm::warm::{Frame as WarmFrame, WarmClone};
use hellovm_control::http::Response;
use hellovm_control::ids::SandboxId;
use hellovm_control::types::{
    self, EditRequest, EditResult, EndedSandbox, ExecError, ExecKind, ExecList, ExecPoll,
    ExecRequest, ExecResult, ExecState, ExecStatus, ExposedPort, NodeCreate, NodeIngress,
    NodeStatus, PollQuery, ResetResult, SandboxInfo, SandboxUsage, WriteResult,
};
use hellovm_control::unix_ms;
use serde_json::{json, Map, Value};

use crate::agent::{self, AgentError, Frame, FrameParser, Writer, FRAME_DEADLINE, OUTPUT_CHUNK};
use crate::config::{valid_name, Config};
use crate::output::{Capture, Stream, StreamLog};
use crate::template::Template;

/// How long a new clone may take to run and to greet, and an exec to
/// start.
const START_DEADLINE: Duration = Duration::from_secs(15);
/// Longest wait for a file operation's answer, and for a request to be
/// written to the agent.
const FILE_DEADLINE: Duration = Duration::from_secs(60);
/// Extra time for an exec's final answer past its timeout (a stateful
/// call takes up to 2 s more to be interrupted, then killed).
const EXEC_GRACE: Duration = Duration::from_secs(10);
/// How long a cancel waits for the exec to end before it answers.
const CANCEL_WAIT: Duration = Duration::from_secs(5);
/// Largest body of an exec's final answer: a stateful call's value and
/// traceback (characters of up to 4 bytes).
const MAX_FINAL_BODY: usize = 4 * (2 * types::MAX_VALUE + types::MAX_TRACEBACK) + 4096;
/// Longest wait for a cancel frame to be written.
const CANCEL_WRITE: Duration = Duration::from_secs(5);
/// Longest idle timeout and lifetime a sandbox may have: a week.
pub const MAX_LIFETIME: f64 = 7.0 * 24.0 * 3600.0;
/// Ended sandboxes remembered, to tell why they are gone.
const TOMBSTONES: usize = 4096;
/// How long after a sandbox ended its egress bytes are still read before
/// its usage is final (flows end when its kernel process does).
const FINAL_AFTER: Duration = Duration::from_secs(2);
/// Time allowed for a question to the egress proxy's stats socket.
const STATS_TIMEOUT: Duration = Duration::from_millis(500);
/// Bytes of a sandbox's agent log (its stderr) passed to noded's log.
const LOG_BUDGET: usize = 64 * 1024;
/// How long handing an inbound connection to a sandbox's kernel process
/// may wait for room in its ingress channel (the kernel process reads it
/// all the time; it is full only when that process is stuck).
const HAND_OVER_TIMEOUT: Duration = Duration::from_secs(1);

/// An error as the node API reports it.
#[derive(Debug, Clone)]
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

    fn ended(reason: &str) -> ApiError {
        ApiError::new(410, "sandbox_ended", format!("the sandbox ended: {reason}"))
    }

    fn failed_sandbox(why: &str) -> ApiError {
        ApiError::new(
            502,
            "sandbox_failed",
            format!("the sandbox failed and was removed: {why}"),
        )
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
        "busy" => 409,
        "agent_error" | "io_error" => 500,
        _ => 400,
    };
    ApiError {
        status,
        code,
        message,
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Waits on `cond` until `done` holds or `deadline` passes.
fn wait_until<'a, T>(
    cond: &Condvar,
    mut guard: MutexGuard<'a, T>,
    deadline: Instant,
    mut done: impl FnMut(&T) -> bool,
) -> MutexGuard<'a, T> {
    while !done(&guard) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        guard = cond
            .wait_timeout(guard, left)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    guard
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Sent; the agent has not said it started.
    Starting,
    Running,
    Done,
}

/// One exec: its output as it comes, then its result.
pub struct Exec {
    /// The agent request's id; the exec id is `ex-{number}`.
    number: u64,
    kind: ExecKind,
    started_at: u64,
    /// How long it may run.
    timeout: Duration,
    state: Mutex<ExecInner>,
    changed: Condvar,
    /// Polls waiting for its output now.
    polls: AtomicUsize,
}

/// Most polls that may wait on one exec at once: each holds a connection
/// (here and at the API) for up to the longest wait, and a tenant must not
/// take the node's connections with polls of one exec.
const MAX_POLLS: usize = 4;

/// Counts a poll while it waits.
struct Polling<'a>(&'a AtomicUsize);

impl Drop for Polling<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ExecInner {
    phase: Phase,
    /// It did not start, or the sandbox went away under it.
    failure: Option<ApiError>,
    stdout: Capture,
    stderr: Capture,
    log: StreamLog,
    cancel_requested: bool,
    result: Option<ExecResult>,
}

impl Exec {
    fn exec_id(&self) -> String {
        format!("ex-{}", self.number)
    }

    fn status(&self) -> ExecStatus {
        let inner = lock(&self.state);
        ExecStatus {
            exec_id: self.exec_id(),
            kind: self.kind,
            state: if inner.phase == Phase::Done {
                ExecState::Done
            } else {
                ExecState::Running
            },
            started_at: self.started_at,
            cancel_requested: inner.cancel_requested,
            result: inner.result.clone(),
        }
    }

    fn update(&self, f: impl FnOnce(&mut ExecInner)) {
        f(&mut lock(&self.state));
        self.changed.notify_all();
    }

    fn fail(&self, error: &ApiError) {
        self.update(|inner| {
            if inner.phase != Phase::Done {
                inner.phase = Phase::Done;
                inner.failure = Some(error.clone());
            }
        });
    }
}

/// Where the answer to a file operation or reset lands.
#[derive(Default)]
struct Slot {
    answer: Mutex<Option<Result<Frame, ApiError>>>,
    ready: Condvar,
}

impl Slot {
    fn fill(&self, answer: Result<Frame, ApiError>) {
        let mut slot = lock(&self.answer);
        if slot.is_none() {
            *slot = Some(answer);
        }
        self.ready.notify_all();
    }
}

enum Waiting {
    Exec(Arc<Exec>),
    Call { slot: Arc<Slot>, max_body: usize },
}

/// The operation outstanding at the agent.
struct InFlight {
    id: u64,
    /// When its next frame (an exec's `started`) or final answer is due.
    deadline: Instant,
    waiting: Waiting,
}

struct Ops {
    next_id: u64,
    in_flight: Option<InFlight>,
    /// The latest exec that started (running or ended).
    latest: Option<Arc<Exec>>,
    /// The channel is gone: why.
    failure: Option<ApiError>,
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
    writer: Mutex<Writer>,
    ops: Mutex<Ops>,
    /// An operation is outstanding (see `Ops::in_flight`).
    busy: AtomicBool,
    memory: AtomicU64,
    memory_limit: u64,
    /// Most host processes (guest processes and threads) it may have.
    max_processes: usize,
    ready_ms: f64,
    /// Its ingress channel (see `hellovm::warm`): inbound connections are
    /// handed to its kernel process here, one at a time.
    ingress_channel: Mutex<UnixStream>,
    ingress: Mutex<Ingress>,
    /// When its kernel process started (clock ticks since boot): with its
    /// pid, what the egress proxy counts its flows by.
    kernel_start: Option<u64>,
    counters: Mutex<Counters>,
}

/// A sandbox's ingress: its token and its exposed ports (whether each is
/// public).
struct Ingress {
    token: String,
    ports: BTreeMap<u16, bool>,
}

impl Ingress {
    fn view(&self) -> NodeIngress {
        NodeIngress {
            token: self.token.clone(),
            ports: self
                .ports
                .iter()
                .map(|(&port, &public)| ExposedPort { port, public })
                .collect(),
        }
    }
}

/// What a sandbox used, as measured so far. Every field only grows.
#[derive(Clone, Copy, Debug, Default)]
struct Counters {
    cpu_ms: u64,
    memory_byte_seconds: u64,
    /// Byte-milliseconds not yet a whole byte-second.
    memory_rest: u64,
    egress_sent_bytes: u64,
    egress_received_bytes: u64,
    /// The last memory measurement.
    measured: Option<Instant>,
}

impl Counters {
    /// A memory measurement of `bytes` at `now`: the time since the last
    /// one is counted at this size.
    fn memory(&mut self, bytes: u64, now: Instant) {
        if let Some(last) = self.measured {
            let ms = now.saturating_duration_since(last).as_millis();
            let total = u128::from(bytes) * ms + u128::from(self.memory_rest);
            let seconds = u64::try_from(total / 1000).unwrap_or(u64::MAX);
            self.memory_byte_seconds = self.memory_byte_seconds.saturating_add(seconds);
            self.memory_rest = (total % 1000) as u64;
        }
        self.measured = Some(now);
    }

    fn egress(&mut self, sent: u64, received: u64) {
        self.egress_sent_bytes = self.egress_sent_bytes.max(sent);
        self.egress_received_bytes = self.egress_received_bytes.max(received);
    }
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
            usage: self.usage(Instant::now()),
        }
    }

    /// What it used, with its run time counted until `until`. Ingress is
    /// counted by the API, which relays it: 0 here.
    fn usage(&self, until: Instant) -> SandboxUsage {
        let c = *lock(&self.counters);
        SandboxUsage {
            run_ms: until.saturating_duration_since(self.created).as_millis() as u64,
            cpu_ms: c.cpu_ms,
            memory_byte_seconds: c.memory_byte_seconds,
            egress_sent_bytes: c.egress_sent_bytes,
            egress_received_bytes: c.egress_received_bytes,
            ..SandboxUsage::default()
        }
    }

    /// Hands `conn`, an inbound connection to guest `port`, to the clone's
    /// kernel process over its ingress channel. The kernel process tells
    /// the other end of `conn` whether a listener took it.
    fn hand_over(&self, port: u16, conn: TcpStream) -> io::Result<()> {
        let channel = lock(&self.ingress_channel);
        hellovm::warm::send_with_fds(&channel, &port.to_le_bytes(), &[conn.as_raw_fd()])
    }

    /// Kills the clone: the template sees the connection's write side
    /// close and kills its kernel process.
    fn kill(&self) {
        let _ = self.control.shutdown(Shutdown::Write);
    }

    /// Takes the sandbox for one operation, or says it is busy.
    fn take(&self) -> Result<(), ApiError> {
        if self
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
        self.touch();
        Ok(())
    }

    fn release(&self) {
        self.touch();
        self.busy.store(false, Ordering::SeqCst);
    }

    /// Sends a request for the sandbox, which the caller has taken:
    /// `waiting` (given the request's id) is what its answer completes.
    /// The sandbox is released when it is answered or fails (here, if the
    /// request cannot be sent).
    fn send(
        &self,
        mut head: Map<String, Value>,
        body: &[u8],
        deadline: Instant,
        waiting: impl FnOnce(u64) -> Waiting,
    ) -> Result<(), SendError> {
        let id = {
            let mut ops = lock(&self.ops);
            if let Some(failure) = &ops.failure {
                let failure = failure.clone();
                drop(ops);
                self.release();
                return Err(SendError::Gone(failure));
            }
            let id = ops.next_id;
            ops.next_id += 1;
            ops.in_flight = Some(InFlight {
                id,
                deadline,
                waiting: waiting(id),
            });
            id
        };
        head.insert("id".into(), json!(id));
        let write_by = Instant::now() + FILE_DEADLINE;
        match lock(&self.writer).send(&head, body, write_by) {
            Ok(()) => Ok(()),
            Err(AgentError::Broken(why)) => Err(SendError::Broken(why)),
            Err(AgentError::Failed { message, .. }) => Err(SendError::Broken(message)),
        }
    }

    /// The longest body the next frame from the agent may have; `None`
    /// when no frame may come.
    fn frame_limit(&self) -> Option<usize> {
        let ops = lock(&self.ops);
        let flight = ops.in_flight.as_ref()?;
        Some(match &flight.waiting {
            Waiting::Exec(exec) => {
                if lock(&exec.state).phase == Phase::Starting {
                    0
                } else {
                    OUTPUT_CHUNK.max(MAX_FINAL_BODY)
                }
            }
            Waiting::Call { max_body, .. } => *max_body,
        })
    }

    /// When the agent must have said something more.
    fn deadline(&self) -> Option<Instant> {
        lock(&self.ops).in_flight.as_ref().map(|f| f.deadline)
    }

    /// Takes one frame from the agent. An error is a protocol violation.
    ///
    /// An answer releases the sandbox before whoever waits for it can see
    /// it (both under `ops`, which the next request needs to be sent):
    /// a client that has its answer must never find the sandbox still
    /// busy with the request it answers.
    fn on_frame(&self, frame: Frame) -> Result<(), String> {
        let mut ops = lock(&self.ops);
        let Some(flight) = ops.in_flight.as_mut() else {
            return Err("a frame when nothing was asked".into());
        };
        if frame.id() != Some(flight.id) {
            return Err("a frame for another request".into());
        }
        let exec = match &flight.waiting {
            Waiting::Exec(exec) => Arc::clone(exec),
            Waiting::Call { slot, .. } => {
                let answer = match frame.outcome() {
                    Some(Ok(())) if frame.op().is_none() => Ok(frame),
                    Some(Err(AgentError::Failed { code, message })) => Err(failed(code, message)),
                    _ => return Err("an answer that is neither success nor failure".into()),
                };
                let slot = Arc::clone(slot);
                ops.in_flight = None;
                self.release();
                slot.fill(answer);
                return Ok(());
            }
        };
        let phase = lock(&exec.state).phase;
        match (frame.op(), phase) {
            (Some("started"), Phase::Starting) => {
                flight.deadline = Instant::now() + exec.timeout + EXEC_GRACE;
                ops.latest = Some(Arc::clone(&exec));
                exec.update(|inner| inner.phase = Phase::Running);
                Ok(())
            }
            (Some("output"), Phase::Running) => {
                let stream = match frame.head.get("stream").and_then(Value::as_u64) {
                    Some(1) => Stream::Stdout,
                    Some(2) => Stream::Stderr,
                    _ => return Err("output of no stream".into()),
                };
                if frame.body.len() > OUTPUT_CHUNK {
                    return Err("an output frame too large".into());
                }
                exec.update(|inner| {
                    match stream {
                        Stream::Stdout => inner.stdout.add(&frame.body),
                        Stream::Stderr => inner.stderr.add(&frame.body),
                    }
                    inner.log.add(stream, &frame.body);
                });
                Ok(())
            }
            (None, Phase::Starting) => match frame.outcome() {
                // It did not start (no such working directory, ...).
                Some(Err(AgentError::Failed { code, message })) => {
                    ops.in_flight = None;
                    self.release();
                    exec.fail(&failed(code, message));
                    Ok(())
                }
                _ => Err("an exec answer before it started".into()),
            },
            (None, Phase::Running) => {
                if !matches!(frame.outcome(), Some(Ok(()))) {
                    return Err("a failed exec after it started".into());
                }
                let mut inner = lock(&exec.state);
                let result = exec_result(&frame, &inner, &exec)?;
                ops.in_flight = None;
                self.release();
                inner.result = Some(result);
                inner.phase = Phase::Done;
                drop(inner);
                exec.changed.notify_all();
                Ok(())
            }
            _ => Err("a frame out of order".into()),
        }
    }

    /// The channel is gone: everything waiting fails with `error`, and no
    /// request is sent any more. The first failure is the one kept.
    fn fail(&self, error: ApiError) {
        let mut ops = lock(&self.ops);
        if ops.failure.is_some() {
            return;
        }
        ops.failure = Some(error.clone());
        let flight = ops.in_flight.take();
        let latest = ops.latest.clone();
        self.release();
        match flight.map(|f| f.waiting) {
            Some(Waiting::Exec(exec)) => exec.fail(&error),
            Some(Waiting::Call { slot, .. }) => slot.fill(Err(error.clone())),
            None => {}
        }
        if let Some(exec) = latest {
            exec.fail(&error);
        }
    }

    /// The latest exec, if it is `exec_id`.
    fn find_exec(&self, exec_id: &str) -> Result<Arc<Exec>, ApiError> {
        let number = types::check_exec_id(exec_id);
        lock(&self.ops)
            .latest
            .clone()
            .filter(|e| Some(e.number) == number)
            .ok_or_else(|| {
                ApiError::new(
                    404,
                    "exec_not_found",
                    "no such exec (a sandbox keeps only its latest)",
                )
            })
    }
}

enum SendError {
    /// The sandbox failed or was removed before.
    Gone(ApiError),
    /// Writing the request failed: the sandbox must go.
    Broken(String),
}

struct Tombstone {
    id: SandboxId,
    tenant: String,
    template: String,
    reason: String,
    memory_limit: u64,
    created_at: u64,
    ended_at: u64,
    /// Its kernel process, for the egress bytes still to come.
    kernel: Option<(u32, u64)>,
    removed: Instant,
    usage: SandboxUsage,
    /// Set once its usage is final ([`FINAL_AFTER`]): its place among the
    /// sandboxes that ended.
    seq: Option<u64>,
}

pub struct Node {
    pub config: Config,
    pub templates: Vec<Arc<Template>>,
    sandboxes: Mutex<HashMap<SandboxId, Arc<Sandbox>>>,
    /// The ids being created, counted against `max_sandboxes` and taken
    /// like those of the sandboxes that exist.
    creating: Mutex<HashSet<SandboxId>>,
    ended: Mutex<VecDeque<Tombstone>>,
    /// Refusing new sandboxes (kept in this process only).
    draining: AtomicBool,
    /// What all sandboxes may hold together, in bytes.
    memory_limit: u64,
    /// Chosen at random when this process started: tells the API that
    /// `seq` numbering started again.
    boot: u64,
    /// The `seq` of the last sandbox whose usage became final.
    last_seq: AtomicU64,
    /// The egress proxy's stats socket and its token.
    egress_stats: Option<(std::path::PathBuf, String)>,
    ticks_per_second: u64,
}

/// An id being created.
struct Creating<'a>(&'a Mutex<HashSet<SandboxId>>, SandboxId);

impl Drop for Creating<'_> {
    fn drop(&mut self) {
        lock(self.0).remove(&self.1);
    }
}

impl Node {
    pub fn new(config: Config, templates: Vec<Arc<Template>>) -> Node {
        Node {
            sandboxes: Mutex::new(HashMap::new()),
            creating: Mutex::new(HashSet::new()),
            ended: Mutex::new(VecDeque::new()),
            draining: AtomicBool::new(config.start_drained),
            memory_limit: match config.max_memory_mb {
                Some(mb) => mb << 20,
                None => crate::memory::host_memory().unwrap_or(u64::MAX),
            },
            boot: SandboxId::random()
                .map(|id| id.egress_id())
                .unwrap_or_else(|_| unix_ms()),
            last_seq: AtomicU64::new(0),
            egress_stats: config.egress_stats().ok().flatten(),
            ticks_per_second: crate::memory::ticks_per_second(),
            config,
            templates,
        }
    }

    pub fn status(&self) -> NodeStatus {
        let (sandboxes, memory_bytes) = {
            let sandboxes = lock(&self.sandboxes);
            (sandboxes.len(), Self::memory_in_use(&sandboxes))
        };
        NodeStatus {
            node: self.config.node.clone(),
            templates: self.templates.iter().map(|t| t.status()).collect(),
            sandboxes,
            creating: lock(&self.creating).len(),
            max_sandboxes: self.config.max_sandboxes,
            memory_bytes,
            memory_limit_bytes: self.memory_limit,
            draining: self.draining.load(Ordering::SeqCst),
            cpus: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
        }
    }

    fn memory_in_use(sandboxes: &HashMap<SandboxId, Arc<Sandbox>>) -> u64 {
        sandboxes
            .values()
            .map(|s| s.memory.load(Ordering::Relaxed))
            .fold(0u64, u64::saturating_add)
    }

    /// Stops or resumes taking new sandboxes; those running are not
    /// touched. Returns the status after the change.
    pub fn set_draining(&self, draining: bool) -> NodeStatus {
        if self.draining.swap(draining, Ordering::SeqCst) != draining {
            log::info!(
                "node state change: node={} draining={draining}",
                self.config.node
            );
        }
        self.status()
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

    /// The sandboxes whose usage became final after `seq`, oldest first,
    /// at most [`types::MAX_ENDED_PER_LIST`], and whether there are more;
    /// and this process's boot number.
    pub fn ended_after(&self, seq: u64) -> (Vec<EndedSandbox>, bool, u64) {
        let ended = lock(&self.ended);
        let mut out: Vec<EndedSandbox> = ended
            .iter()
            .filter(|t| t.seq.is_some_and(|s| s > seq))
            .map(|t| EndedSandbox {
                id: t.id.to_string(),
                tenant: t.tenant.clone(),
                template: t.template.clone(),
                seq: t.seq.unwrap_or(0),
                created_at: t.created_at,
                ended_at: t.ended_at,
                memory_limit_bytes: t.memory_limit,
                usage: t.usage,
            })
            .collect();
        out.sort_by_key(|e| e.seq);
        let more = out.len() > types::MAX_ENDED_PER_LIST;
        out.truncate(types::MAX_ENDED_PER_LIST);
        (out, more, self.boot)
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
            Some(t) => Err(ApiError::ended(&t.reason)),
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
        // Measured once more while its processes still run: the sampling
        // is once a second, and without this a sandbox would not pay for
        // its last second (one that lived less than a second, for nothing).
        self.measure_last(&sandbox);
        let removed = Instant::now();
        sandbox.fail(ApiError::ended(reason));
        sandbox.kill();
        log::info!("sandbox {id} of {} removed: {reason}", sandbox.tenant);
        let mut ended = lock(&self.ended);
        if ended.len() >= TOMBSTONES {
            ended.pop_front();
        }
        ended.push_back(Tombstone {
            id,
            tenant: sandbox.tenant.clone(),
            template: sandbox.template.clone(),
            reason: reason.to_string(),
            memory_limit: sandbox.memory_limit,
            created_at: sandbox.created_at,
            ended_at: unix_ms(),
            kernel: sandbox
                .kernel_start
                .map(|start| (sandbox.kernel_pid, start)),
            removed,
            usage: sandbox.usage(removed),
            seq: None,
        });
        true
    }

    /// The sandbox's agent broke the protocol, missed a deadline, or does
    /// not take requests: whatever waits fails with `502`, and it goes.
    fn agent_failed(&self, sandbox: &Sandbox, why: &str) -> ApiError {
        let error = ApiError::failed_sandbox(why);
        sandbox.fail(error.clone());
        self.remove(sandbox.id, &format!("its agent failed: {why}"));
        // Whichever failure came first (a removal for another reason, say).
        lock(&sandbox.ops).failure.clone().unwrap_or(error)
    }

    fn send_failed(&self, sandbox: &Sandbox, err: SendError) -> ApiError {
        match err {
            SendError::Gone(error) => error,
            SendError::Broken(why) => self.agent_failed(sandbox, &why),
        }
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
            let mut creating = lock(&self.creating);
            if sandboxes.contains_key(&id) || creating.contains(&id) {
                return Err(ApiError::new(
                    409,
                    "exists",
                    "a sandbox with this id exists",
                ));
            }
            if self.draining.load(Ordering::SeqCst) {
                return Err(ApiError::new(
                    503,
                    "node_draining",
                    "this node takes no new sandboxes",
                ));
            }
            if sandboxes.len() + creating.len() >= self.config.max_sandboxes
                || Self::memory_in_use(&sandboxes) >= self.memory_limit
            {
                return Err(ApiError::new(503, "node_full", "this node is full"));
            }
            creating.insert(id);
            Creating(&self.creating, id)
        };
        let internal = |what: &str, err: &dyn std::fmt::Display| {
            log::warn!("sandbox {id}: {what}: {err}");
            ApiError::new(503, "clone_failed", format!("{what}: {err}"))
        };
        let (in_r, in_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let (out_r, out_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let (err_r, err_w) = std::io::pipe().map_err(|e| internal("pipes", &e))?;
        let (ingress_channel, theirs) =
            UnixStream::pair().map_err(|e| internal("the ingress channel", &e))?;
        ingress_channel
            .set_write_timeout(Some(HAND_OVER_TIMEOUT))
            .map_err(|e| internal("the ingress channel", &e))?;
        let token =
            hellovm_control::ids::random_token().map_err(|e| internal("an ingress token", &e))?;
        let mut clone = WarmClone::request_with(
            &template.socket,
            Some(id.egress_id()),
            b"",
            [in_r.as_fd(), out_w.as_fd(), err_w.as_fd()],
            Some(theirs.as_fd()),
        )
        .map_err(|e| internal("asking the template for a clone", &e))?;
        // Only the clone holds these now.
        drop((in_r, out_w, err_w, theirs));
        clone
            .stream()
            .set_read_timeout(Some(START_DEADLINE))
            .map_err(|e| internal("the clone connection", &e))?;
        let run = clone
            .start()
            .map_err(|e| internal("starting the clone", &e))?;
        let from = OwnedFd::from(out_r);
        agent::set_nonblocking(&from).map_err(|e| internal("the agent channel", &e))?;
        let mut from = File::from(from);
        agent::hello(&mut from, started + START_DEADLINE)
            .map_err(|e| internal("the agent's greeting", &e))?;
        let writer =
            Writer::new(OwnedFd::from(in_w)).map_err(|e| internal("the agent channel", &e))?;
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
            writer: Mutex::new(writer),
            ops: Mutex::new(Ops {
                next_id: 1,
                in_flight: None,
                latest: None,
                failure: None,
            }),
            busy: AtomicBool::new(false),
            memory: AtomicU64::new(0),
            memory_limit: template.config.memory_limit_mb << 20,
            max_processes: template.config.max_processes,
            ready_ms,
            ingress_channel: Mutex::new(ingress_channel),
            ingress: Mutex::new(Ingress {
                token,
                ports: BTreeMap::new(),
            }),
            kernel_start: crate::memory::stat_of(run.pid).map(|s| s.start),
            counters: Mutex::new(Counters::default()),
        });
        let info = sandbox.info(&self.config.node);
        {
            let mut sandboxes = lock(&self.sandboxes);
            sandboxes.insert(id, Arc::clone(&sandbox));
        }
        let node = Arc::clone(self);
        let watched = Arc::clone(&sandbox);
        let spawned = std::thread::Builder::new()
            .name("sandbox-watch".into())
            .spawn(move || node.watch(watched, clone, OwnedFd::from(err_r), from));
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

    /// Follows a sandbox until it ends: reads everything its agent says
    /// (frames, as they come), passes its stderr (the agent's log) to
    /// noded's log, bounded, enforces the agent's deadlines, and learns
    /// from the control connection when the clone ended.
    fn watch(&self, sandbox: Arc<Sandbox>, clone: WarmClone, stderr: OwnedFd, mut from: File) {
        let id = sandbox.id;
        let mut logged = 0usize;
        let mut stderr = Some(File::from(stderr));
        let mut parser = FrameParser::new();
        let mut chunk = vec![0u8; 1 << 16];
        let ended = |clone: &WarmClone| {
            let _ = clone
                .stream()
                .set_read_timeout(Some(Duration::from_secs(5)));
            match WarmFrame::read_from(&mut clone.stream()) {
                Ok(Some(WarmFrame::Exit(status))) => format!("its agent ended ({status:?})"),
                Ok(Some(WarmFrame::Error(text))) => format!("the clone failed: {text}"),
                Ok(Some(other)) => format!("unexpected {other:?} from the template"),
                Ok(None) => "the template closed its connection".into(),
                Err(err) => format!("its connection failed: {err}"),
            }
        };
        // `Err` is the agent's fault (the sandbox failed); `Ok` an end.
        let outcome: Result<String, String> = loop {
            let now = Instant::now();
            let mut due = now + Duration::from_secs(1);
            if let Some(at) = sandbox.deadline() {
                due = due.min(at);
            }
            if let Some(at) = parser.started() {
                due = due.min(at + FRAME_DEADLINE);
            }
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
                libc::pollfd {
                    fd: from.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let ms = due
                .saturating_duration_since(now)
                .as_millis()
                .clamp(1, 1000) as libc::c_int;
            // SAFETY: a valid array of pollfds.
            let n = unsafe { libc::poll(polls.as_mut_ptr(), 3, ms) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break Ok(format!("watching failed: {err}"));
            }
            if polls[1].revents != 0 {
                let mut log_chunk = [0u8; 4096];
                match stderr.as_mut().map(|f| f.read(&mut log_chunk)) {
                    Some(Ok(n)) if n > 0 => {
                        if logged < LOG_BUDGET {
                            let text = String::from_utf8_lossy(&log_chunk[..n]);
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
            if polls[2].revents != 0 {
                match from.read(&mut chunk) {
                    Ok(0) => break Ok(ended(&clone)),
                    Ok(n) => {
                        let mut data = &chunk[..n];
                        let mut violation = None;
                        while !data.is_empty() {
                            match parser.push(&mut data, sandbox.frame_limit()) {
                                Ok(Some(frame)) => {
                                    if let Err(why) = sandbox.on_frame(frame) {
                                        violation = Some(why);
                                        break;
                                    }
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    violation = Some(err.to_string());
                                    break;
                                }
                            }
                        }
                        if let Some(why) = violation {
                            break Err(why);
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(err) => break Err(format!("reading from it: {err}")),
                }
            }
            if polls[0].revents != 0 {
                break Ok(ended(&clone));
            }
            let now = Instant::now();
            if parser
                .started()
                .is_some_and(|at| now >= at + FRAME_DEADLINE)
            {
                break Err("a frame not finished in time".into());
            }
            if sandbox.deadline().is_some_and(|at| now >= at) {
                break Err("no answer in time".into());
            }
        };
        match outcome {
            Ok(reason) => {
                self.remove(id, &reason);
            }
            Err(why) => {
                self.agent_failed(&sandbox, &why);
            }
        }
        drop(clone);
    }

    /// A sandbox's ingress: its token and exposed ports.
    pub fn ingress(&self, id: &str, tenant: Option<&str>) -> Result<NodeIngress, ApiError> {
        Ok(lock(&self.get(id, tenant)?.ingress).view())
    }

    /// Exposes `port` (or changes whether it is public). At most
    /// [`types::MAX_EXPOSED_PORTS`] per sandbox.
    pub fn expose(
        &self,
        id: &str,
        tenant: Option<&str>,
        port: u16,
        public: bool,
    ) -> Result<NodeIngress, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let mut ingress = lock(&sandbox.ingress);
        if !ingress.ports.contains_key(&port) && ingress.ports.len() >= types::MAX_EXPOSED_PORTS {
            return Err(ApiError::new(
                409,
                "too_many_ports",
                format!(
                    "at most {} ports may be exposed at once",
                    types::MAX_EXPOSED_PORTS
                ),
            ));
        }
        ingress.ports.insert(port, public);
        Ok(ingress.view())
    }

    /// Stops exposing `port` (nothing happens when it is not).
    /// Connections already made go on.
    pub fn unexpose(
        &self,
        id: &str,
        tenant: Option<&str>,
        port: u16,
    ) -> Result<NodeIngress, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let mut ingress = lock(&sandbox.ingress);
        ingress.ports.remove(&port);
        Ok(ingress.view())
    }

    /// Replaces the ingress token with a new random one.
    pub fn rotate_token(&self, id: &str, tenant: Option<&str>) -> Result<NodeIngress, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let token = hellovm_control::ids::random_token()
            .map_err(|e| ApiError::new(503, "internal", format!("a token: {e}")))?;
        let mut ingress = lock(&sandbox.ingress);
        ingress.token = token;
        Ok(ingress.view())
    }

    /// The answer to `POST .../ingress/connect?port=P`: `200`, after which
    /// the connection itself is handed to the sandbox's kernel process for
    /// guest port `port`, which must be exposed. Counts as use of the
    /// sandbox. The caller (the API) checked the token.
    pub fn connect(&self, id: &str, tenant: Option<&str>, port: u16) -> Result<Response, ApiError> {
        let sandbox = self.get(id, tenant)?;
        if !lock(&sandbox.ingress).ports.contains_key(&port) {
            return Err(ApiError::new(
                404,
                "port_not_exposed",
                "the port is not exposed",
            ));
        }
        sandbox.touch();
        Ok(Response::empty(200).take_over(move |conn| {
            if let Err(err) = sandbox.hand_over(port, conn) {
                log::debug!(
                    "sandbox {}: an inbound connection was not handed over: {err}",
                    sandbox.id
                );
            }
        }))
    }

    /// Sandboxes used through ingress: their idle timeouts start again.
    /// Unknown ids are skipped. Returns how many were touched.
    pub fn touch(&self, ids: &[String]) -> usize {
        let sandboxes = lock(&self.sandboxes);
        ids.iter()
            .filter_map(|id| SandboxId::parse(id))
            .filter_map(|id| sandboxes.get(&id))
            .map(|s| s.touch())
            .count()
    }

    /// Removes sandboxes past their lifetime or idle too long. Runs for
    /// ever, on a thread of its own: nothing a sandbox does delays it.
    pub fn reap(&self) {
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
        }
    }

    /// Measures every sandbox once a second (memory, processes, CPU time,
    /// egress bytes) and removes those over their memory limit or with too
    /// many processes; makes the usage of sandboxes that ended final. Runs
    /// for ever, on a thread of its own.
    pub fn watch_usage(&self) {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            self.measure();
            self.egress();
            self.finalize();
        }
    }

    /// The last measurement of a sandbox that is being removed: its CPU
    /// time and memory until now.
    fn measure_last(&self, sandbox: &Sandbox) {
        let usage = crate::memory::measure(&[(sandbox.kernel_pid, sandbox.max_processes)]);
        let Some(usage) = usage.get(&sandbox.kernel_pid) else {
            return;
        };
        let mut c = lock(&sandbox.counters);
        if !usage.too_many {
            c.memory(usage.bytes, Instant::now());
        }
        let cpu_ms = usage.cpu_ticks.saturating_mul(1000) / self.ticks_per_second;
        c.cpu_ms = c.cpu_ms.max(cpu_ms);
    }

    fn measure(&self) {
        let sandboxes: Vec<Arc<Sandbox>> = lock(&self.sandboxes).values().cloned().collect();
        if sandboxes.is_empty() {
            return;
        }
        let pids: Vec<(u32, usize)> = sandboxes
            .iter()
            .map(|s| (s.kernel_pid, s.max_processes))
            .collect();
        let usage = crate::memory::measure(&pids);
        let now = Instant::now();
        for s in &sandboxes {
            let usage = usage.get(&s.kernel_pid).copied().unwrap_or_default();
            if usage.too_many {
                self.remove(
                    s.id,
                    &format!("it had more than {} processes and threads", s.max_processes),
                );
                continue;
            }
            s.memory.store(usage.bytes, Ordering::Relaxed);
            {
                let mut c = lock(&s.counters);
                c.memory(usage.bytes, now);
                // The processes that make up the sum change (one ends and
                // its parent has not waited for it yet): never down.
                let cpu_ms = usage.cpu_ticks.saturating_mul(1000) / self.ticks_per_second;
                c.cpu_ms = c.cpu_ms.max(cpu_ms);
            }
            if usage.bytes > s.memory_limit {
                let largest: Vec<String> = usage
                    .largest
                    .iter()
                    .filter(|&&(pid, _)| pid != 0)
                    .map(|&(pid, bytes)| {
                        format!(
                            "{} (pid {pid}) {} MiB",
                            crate::memory::command_of(pid),
                            bytes >> 20
                        )
                    })
                    .collect();
                log::info!(
                    "sandbox {} over its memory limit: {} MiB in {} processes; largest: {}",
                    s.id,
                    usage.bytes >> 20,
                    usage.processes,
                    largest.join(", ")
                );
                self.remove(
                    s.id,
                    &format!(
                        "its memory ({} MiB in {} processes) went over the limit ({} MiB)",
                        usage.bytes >> 20,
                        usage.processes,
                        s.memory_limit >> 20
                    ),
                );
            }
        }
    }

    /// Reads the egress bytes of every sandbox, and of those that ended
    /// whose usage is not final yet, from the egress proxy.
    fn egress(&self) {
        #[cfg(target_os = "linux")]
        {
            use hellovm_egress::usage::{ask, Key};
            let Some((socket, token)) = &self.egress_stats else {
                return;
            };
            let sandboxes: Vec<Arc<Sandbox>> = lock(&self.sandboxes).values().cloned().collect();
            let mut keys: Vec<Key> = sandboxes
                .iter()
                .filter_map(|s| {
                    s.kernel_start.map(|start| Key {
                        pid: s.kernel_pid,
                        start,
                    })
                })
                .collect();
            keys.extend(
                lock(&self.ended)
                    .iter()
                    .filter(|t| t.seq.is_none())
                    .filter_map(|t| t.kernel.map(|(pid, start)| Key { pid, start })),
            );
            if keys.is_empty() {
                return;
            }
            let answer = keys
                .chunks(hellovm_egress::usage::MAX_KEYS)
                .map(|chunk| ask(socket, token, chunk, STATS_TIMEOUT))
                .collect::<io::Result<Vec<_>>>();
            let bytes: HashMap<(u32, u64), (u64, u64)> = match answer {
                Ok(answers) => answers
                    .into_iter()
                    .flatten()
                    .map(|(k, sent, received)| ((k.pid, k.start), (sent, received)))
                    .collect(),
                Err(err) => {
                    log::debug!("egress stats {}: {err}", socket.display());
                    return;
                }
            };
            for s in &sandboxes {
                if let Some(&(sent, received)) = s
                    .kernel_start
                    .and_then(|start| bytes.get(&(s.kernel_pid, start)))
                {
                    lock(&s.counters).egress(sent, received);
                }
            }
            for t in lock(&self.ended).iter_mut().filter(|t| t.seq.is_none()) {
                if let Some(&(sent, received)) = t.kernel.and_then(|k| bytes.get(&k)) {
                    t.usage.egress_sent_bytes = t.usage.egress_sent_bytes.max(sent);
                    t.usage.egress_received_bytes = t.usage.egress_received_bytes.max(received);
                }
            }
        }
    }

    /// Makes final the usage of sandboxes that ended [`FINAL_AFTER`] ago.
    fn finalize(&self) {
        let mut ended = lock(&self.ended);
        for t in ended.iter_mut() {
            if t.seq.is_none() && t.removed.elapsed() >= FINAL_AFTER {
                t.seq = Some(self.last_seq.fetch_add(1, Ordering::SeqCst) + 1);
            }
        }
    }

    /// One request that is not an exec: its answer.
    fn call(
        &self,
        id: &str,
        tenant: Option<&str>,
        head: Map<String, Value>,
        body: &[u8],
        max_body: usize,
    ) -> Result<Frame, ApiError> {
        let sandbox = self.get(id, tenant)?;
        sandbox.take()?;
        let slot = Arc::new(Slot::default());
        let deadline = Instant::now() + FILE_DEADLINE;
        let waiting = {
            let slot = Arc::clone(&slot);
            move |_| Waiting::Call { slot, max_body }
        };
        if let Err(err) = sandbox.send(head, body, deadline, waiting) {
            return Err(self.send_failed(&sandbox, err));
        }
        let mut answer = wait_until(
            &slot.ready,
            lock(&slot.answer),
            deadline + Duration::from_secs(5),
            |a| a.is_some(),
        );
        match answer.take() {
            Some(answer) => answer,
            // The watch thread enforces the deadline; this is a backstop.
            None => {
                drop(answer);
                Err(self.agent_failed(&sandbox, "no answer in time"))
            }
        }
    }

    /// Starts an exec; returns once the agent started it.
    pub fn start_exec(
        &self,
        id: &str,
        tenant: Option<&str>,
        request: &ExecRequest,
    ) -> Result<Arc<Exec>, ApiError> {
        let (timeout, max_output) = request
            .validate()
            .map_err(|m| ApiError::new(400, "bad_request", m))?;
        let mut head = Map::new();
        head.insert("op".into(), json!("exec"));
        head.insert("command".into(), json!(request.command));
        head.insert("python".into(), json!(request.python));
        head.insert("stateful".into(), json!(request.stateful));
        head.insert("timeout".into(), json!(timeout));
        head.insert("cwd".into(), json!(request.cwd));
        head.insert("env".into(), json!(request.env));
        head.insert("has_stdin".into(), json!(request.stdin.is_some()));
        let stdin = request.stdin.as_deref().unwrap_or("").as_bytes();
        let kind = match (&request.command, request.stateful) {
            (Some(_), _) => ExecKind::Command,
            (None, false) => ExecKind::Python,
            (None, true) => ExecKind::Stateful,
        };
        let sandbox = self.get(id, tenant)?;
        sandbox.take()?;
        let mut made = None;
        let waiting = |number| {
            let exec = Arc::new(Exec {
                number,
                kind,
                started_at: unix_ms(),
                timeout: Duration::from_secs_f64(timeout),
                state: Mutex::new(ExecInner {
                    phase: Phase::Starting,
                    failure: None,
                    stdout: Capture::new(max_output),
                    stderr: Capture::new(max_output),
                    log: StreamLog::new(max_output),
                    cancel_requested: false,
                    result: None,
                }),
                changed: Condvar::new(),
                polls: AtomicUsize::new(0),
            });
            made = Some(Arc::clone(&exec));
            Waiting::Exec(exec)
        };
        let deadline = Instant::now() + START_DEADLINE;
        if let Err(err) = sandbox.send(head, stdin, deadline, waiting) {
            return Err(self.send_failed(&sandbox, err));
        }
        let Some(exec) = made else {
            return Err(ApiError::new(500, "internal", "no exec"));
        };
        let inner = wait_until(
            &exec.changed,
            lock(&exec.state),
            deadline + Duration::from_secs(5),
            |i| i.phase != Phase::Starting,
        );
        if let Some(failure) = &inner.failure {
            return Err(failure.clone());
        }
        if inner.phase == Phase::Starting {
            drop(inner);
            return Err(self.agent_failed(&sandbox, "the exec did not start in time"));
        }
        drop(inner);
        Ok(exec)
    }

    /// Runs an exec to its end.
    pub fn exec(
        &self,
        id: &str,
        tenant: Option<&str>,
        request: &ExecRequest,
    ) -> Result<ExecResult, ApiError> {
        let exec = self.start_exec(id, tenant, request)?;
        // The watch thread ends it by its deadline; the wait's own bound
        // is a backstop.
        let deadline = Instant::now() + exec.timeout + EXEC_GRACE + Duration::from_secs(5);
        let inner = wait_until(&exec.changed, lock(&exec.state), deadline, |i| {
            i.phase == Phase::Done
        });
        if let Some(failure) = &inner.failure {
            return Err(failure.clone());
        }
        match &inner.result {
            Some(result) => Ok(result.clone()),
            None => Err(ApiError::new(
                504,
                "timeout",
                "the exec did not end in time",
            )),
        }
    }

    pub fn start(
        &self,
        id: &str,
        tenant: Option<&str>,
        request: &ExecRequest,
    ) -> Result<ExecStatus, ApiError> {
        Ok(self.start_exec(id, tenant, request)?.status())
    }

    pub fn execs(&self, id: &str, tenant: Option<&str>) -> Result<ExecList, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let latest = lock(&sandbox.ops).latest.clone();
        Ok(ExecList {
            execs: latest.map(|e| e.status()).into_iter().collect(),
        })
    }

    /// The output of an exec from `query.cursor` on; waits up to
    /// `query.wait` for some, or for its end.
    pub fn poll(
        &self,
        id: &str,
        tenant: Option<&str>,
        exec_id: &str,
        query: PollQuery,
    ) -> Result<ExecPoll, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let exec = sandbox.find_exec(exec_id)?;
        sandbox.touch();
        if exec.polls.fetch_add(1, Ordering::SeqCst) >= MAX_POLLS {
            exec.polls.fetch_sub(1, Ordering::SeqCst);
            return Err(ApiError::new(
                429,
                "too_many_polls",
                format!("at most {MAX_POLLS} polls of one exec at once"),
            ));
        }
        let _polling = Polling(&exec.polls);
        let deadline = Instant::now() + Duration::from_secs_f64(query.wait);
        let mut inner = lock(&exec.state);
        loop {
            if let Some(failure) = &inner.failure {
                return Err(failure.clone());
            }
            let done = inner.phase == Phase::Done;
            let read = inner.log.read(query.cursor, query.max_bytes, done);
            if !read.events.is_empty() || done || Instant::now() >= deadline {
                let eof = done && read.next_cursor == inner.log.total();
                return Ok(ExecPoll {
                    exec_id: exec.exec_id(),
                    state: if done {
                        ExecState::Done
                    } else {
                        ExecState::Running
                    },
                    events: read.events,
                    next_cursor: read.next_cursor,
                    eof,
                    result: inner.result.clone(),
                });
            }
            let left = deadline.saturating_duration_since(Instant::now());
            inner = exec
                .changed
                .wait_timeout(inner, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Cancels an exec: its process group is killed (a stateful call is
    /// interrupted first). Waits up to [`CANCEL_WAIT`] for its end.
    pub fn cancel(
        &self,
        id: &str,
        tenant: Option<&str>,
        exec_id: &str,
    ) -> Result<ExecStatus, ApiError> {
        let sandbox = self.get(id, tenant)?;
        let exec = sandbox.find_exec(exec_id)?;
        let first = {
            let mut inner = lock(&exec.state);
            let first = inner.phase != Phase::Done && !inner.cancel_requested;
            if first {
                inner.cancel_requested = true;
            }
            first
        };
        if first {
            let head = match json!({"op": "cancel", "id": 0, "target": exec.number}) {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            let sent = lock(&sandbox.writer).send(&head, b"", Instant::now() + CANCEL_WRITE);
            if let Err(err) = sent {
                return Err(self.agent_failed(&sandbox, &err.to_string()));
            }
        }
        let inner = wait_until(
            &exec.changed,
            lock(&exec.state),
            Instant::now() + CANCEL_WAIT,
            |i| i.phase == Phase::Done,
        );
        if let Some(failure) = &inner.failure {
            return Err(failure.clone());
        }
        drop(inner);
        Ok(exec.status())
    }

    /// Discards the sandbox's stateful interpreter.
    pub fn reset(&self, id: &str, tenant: Option<&str>) -> Result<ResetResult, ApiError> {
        let frame = self.call(id, tenant, map(json!({"op": "reset"})), b"", 0)?;
        let had_state = frame
            .head
            .get("had_state")
            .and_then(Value::as_bool)
            .ok_or_else(|| ApiError::new(502, "sandbox_failed", "a malformed reset answer"))?;
        Ok(ResetResult { had_state })
    }

    pub fn read_file(
        &self,
        id: &str,
        tenant: Option<&str>,
        path: &str,
    ) -> Result<Vec<u8>, ApiError> {
        types::check_path(path).map_err(|m| ApiError::new(400, "bad_request", m))?;
        let head = map(json!({"op": "read", "path": path, "max_bytes": types::MAX_FILE}));
        Ok(self.call(id, tenant, head, b"", types::MAX_FILE)?.body)
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
        self.call(id, tenant, head, data, 0)?;
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
        let frame = self.call(id, tenant, head, b"", 0)?;
        let replacements = frame
            .head
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

/// At most `limit` characters of `text`.
fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// Builds an exec's result from the agent's final answer and the output
/// held, checking every field.
fn exec_result(frame: &Frame, inner: &ExecInner, exec: &Exec) -> Result<ExecResult, String> {
    let answer = &frame.head;
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
    let flag = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_bool)
            .ok_or(format!("no {key}"))
    };
    let length = |key: &str| -> Result<usize, String> {
        match answer.get(key) {
            None | Some(Value::Null) => Ok(0),
            Some(v) => v
                .as_u64()
                .map(|n| n as usize)
                .ok_or_else(|| format!("{key} is not a length")),
        }
    };
    let duration_ms = answer
        .get("duration_ms")
        .and_then(Value::as_f64)
        .filter(|d| d.is_finite() && *d >= 0.0)
        .ok_or("no duration_ms")?;
    let (stdout, stdout_truncated) = inner.stdout.result();
    let (stderr, stderr_truncated) = inner.stderr.result();
    let mut result = ExecResult {
        exec_id: exec.exec_id(),
        exit_code: int("exit_code")?,
        signal: int("signal")?,
        timed_out: flag("timed_out")?,
        cancelled: flag("cancelled")?,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        stdout_truncated,
        stderr_truncated,
        stdout_bytes: inner.stdout.total(),
        stderr_bytes: inner.stderr.total(),
        duration_ms,
        value: None,
        error: None,
        state_lost: None,
    };
    if exec.kind == ExecKind::Stateful {
        let value_len = length("value_len")?;
        let message_len = length("message_len")?;
        let traceback_len = length("traceback_len")?;
        let total = value_len
            .checked_add(message_len)
            .and_then(|n| n.checked_add(traceback_len));
        if total != Some(frame.body.len()) {
            return Err("value, message and traceback lengths do not match the body".into());
        }
        let (value, rest) = frame.body.split_at(value_len);
        let (message, traceback) = rest.split_at(message_len);
        if answer.get("value_len").is_some_and(|v| !v.is_null()) {
            result.value = Some(clip(
                &String::from_utf8_lossy(value),
                types::MAX_VALUE + 100,
            ));
        }
        result.error = match answer.get("error") {
            None | Some(Value::Null) => None,
            Some(Value::Object(error)) => {
                let text = |key: &str| {
                    error
                        .get(key)
                        .and_then(Value::as_str)
                        .ok_or(format!("error without {key}"))
                };
                Some(ExecError {
                    kind: clip(text("type")?, 200),
                    message: clip(&String::from_utf8_lossy(message), types::MAX_VALUE + 100),
                    traceback: clip(
                        &String::from_utf8_lossy(traceback),
                        types::MAX_TRACEBACK + 100,
                    ),
                })
            }
            Some(_) => return Err("error is not an object".into()),
        };
        result.state_lost = Some(flag("state_lost")?);
    } else if !frame.body.is_empty() {
        return Err("a body in an exec's answer".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner(limit: usize) -> ExecInner {
        ExecInner {
            phase: Phase::Running,
            failure: None,
            stdout: Capture::new(limit),
            stderr: Capture::new(limit),
            log: StreamLog::new(limit),
            cancel_requested: false,
            result: None,
        }
    }

    fn exec(kind: ExecKind) -> Exec {
        Exec {
            number: 7,
            kind,
            started_at: 0,
            timeout: Duration::from_secs(1),
            state: Mutex::new(inner(64)),
            changed: Condvar::new(),
            polls: AtomicUsize::new(0),
        }
    }

    fn frame(head: Value, body: &[u8]) -> Frame {
        Frame {
            head: map(head),
            body: body.to_vec(),
        }
    }

    #[test]
    fn exec_answers_are_checked() {
        let mut held = inner(1024);
        held.stdout.add(b"out");
        held.stderr.add(b"\xffe");
        let good = json!({"exit_code": 0, "signal": null, "timed_out": false, "cancelled": false,
            "duration_ms": 1.5});
        let command = exec(ExecKind::Command);
        let r = exec_result(&frame(good.clone(), b""), &held, &command).unwrap();
        assert_eq!(r.exec_id, "ex-7");
        assert_eq!(r.stdout, "out");
        assert_eq!(r.stderr, "\u{fffd}e");
        assert_eq!(r.stdout_bytes, 3);
        assert!(r.value.is_none() && r.state_lost.is_none());
        // A body where none belongs.
        assert!(exec_result(&frame(good.clone(), b"x"), &held, &command).is_err());
        let mut huge = good.clone();
        huge["exit_code"] = json!(1u64 << 40);
        assert!(exec_result(&frame(huge, b""), &held, &command).is_err());
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("cancelled");
        assert!(exec_result(&frame(missing, b""), &held, &command).is_err());

        // Stateful: value and traceback split the body.
        let stateful = exec(ExecKind::Stateful);
        let mut answer = good.clone();
        answer["value_len"] = json!(2);
        answer["message_len"] = json!(3);
        answer["traceback_len"] = json!(5);
        answer["error"] = json!({"type": "ValueError"});
        answer["state_lost"] = json!(false);
        let r = exec_result(&frame(answer.clone(), b"42badTrace"), &held, &stateful).unwrap();
        assert_eq!(r.value.as_deref(), Some("42"));
        let error = r.error.unwrap();
        assert_eq!(
            (
                error.kind.as_str(),
                error.message.as_str(),
                error.traceback.as_str()
            ),
            ("ValueError", "bad", "Trace")
        );
        assert_eq!(r.state_lost, Some(false));
        // Lengths that do not add up, or that overflow.
        assert!(exec_result(&frame(answer.clone(), b"42badTrac"), &held, &stateful).is_err());
        answer["value_len"] = json!(u64::MAX);
        assert!(exec_result(&frame(answer.clone(), b"42badTrace"), &held, &stateful).is_err());
        answer["value_len"] = json!(2);
        answer["error"] = json!("nope");
        assert!(exec_result(&frame(answer, b"42badTrace"), &held, &stateful).is_err());
    }
}
