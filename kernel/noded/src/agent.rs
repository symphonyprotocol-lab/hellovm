//! The channel to the agent inside a sandbox: frames on the clone's
//! console (see `agent.py`).
//!
//! ```text
//! [header length u32 BE][body length u32 BE][header: JSON object][body]
//! ```
//!
//! Requests go to the agent's stdin ([`Writer`]); everything it says
//! comes back on its stdout, read as it arrives by [`FrameParser`]: the
//! answer to a request, and while an exec runs its `started` answer, its
//! `output` frames and its final answer. `noded` has at most one request
//! outstanding per sandbox (and a `cancel`, which is never answered).
//!
//! The agent runs as the guest, and the guest can write to its own console
//! (`/dev/console`), so every frame read here is untrusted: its lengths are
//! checked against what the request outstanding can legitimately produce
//! before anything is allocated, a frame that started must end within
//! [`FRAME_DEADLINE`], every write has a deadline, and a frame must belong
//! to the request outstanding. Any violation ends the conversation (the
//! caller then removes the sandbox: it can only have broken itself).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

/// Largest frame header accepted.
pub const MAX_HEADER: usize = 64 * 1024;
/// Largest `output` frame body the agent sends.
pub const OUTPUT_CHUNK: usize = 64 * 1024;
/// A frame whose first byte arrived must be complete within this.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(30);
/// The protocol version the agent greets with.
pub const VERSION: u64 = 2;

/// The agent's own script, run as `python3 -I -c AGENT MODULE...`.
pub const AGENT_SOURCE: &str = include_str!("agent.py");

#[derive(Debug)]
pub enum AgentError {
    /// The operation failed in the sandbox (no such file, ...): the
    /// agent's error code and message. The channel is fine.
    Failed { code: String, message: String },
    /// The channel broke or the agent answered nonsense: the sandbox must
    /// go.
    Broken(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Failed { code, message } => write!(f, "{code}: {message}"),
            AgentError::Broken(why) => write!(f, "the agent channel broke: {why}"),
        }
    }
}

pub fn broken(why: impl Into<String>) -> AgentError {
    AgentError::Broken(why.into())
}

/// A frame from the agent.
#[derive(Debug)]
pub struct Frame {
    pub head: Map<String, Value>,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn id(&self) -> Option<u64> {
        self.head.get("id").and_then(Value::as_u64)
    }

    pub fn op(&self) -> Option<&str> {
        self.head.get("op").and_then(Value::as_str)
    }

    /// The agent's error, if the frame is a failure: `Some(Ok(()))` for
    /// success, `Some(Err(..))` for a failure, `None` without `ok`.
    pub fn outcome(&self) -> Option<Result<(), AgentError>> {
        match self.head.get("ok") {
            Some(Value::Bool(true)) => Some(Ok(())),
            Some(Value::Bool(false)) => {
                let text = |key: &str| {
                    let s = self.head.get(key).and_then(Value::as_str).unwrap_or("");
                    s.chars().take(1000).collect::<String>()
                };
                Some(Err(AgentError::Failed {
                    code: text("code"),
                    message: text("message"),
                }))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Lengths,
    Head,
    Body,
}

/// Reads frames out of the bytes as they arrive, in any pieces.
#[derive(Debug)]
pub struct FrameParser {
    stage: Stage,
    lengths: [u8; 8],
    have: usize,
    head: Vec<u8>,
    head_len: usize,
    body: Vec<u8>,
    body_len: usize,
    started: Option<Instant>,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    pub fn new() -> FrameParser {
        FrameParser {
            stage: Stage::Lengths,
            lengths: [0; 8],
            have: 0,
            head: Vec::new(),
            head_len: 0,
            body: Vec::new(),
            body_len: 0,
            started: None,
        }
    }

    /// When the first byte of the frame being read arrived; `None`
    /// between frames.
    pub fn started(&self) -> Option<Instant> {
        self.started
    }

    /// Takes bytes from the front of `data` until a frame is complete, and
    /// returns it. `max_body` is the longest body a frame may have now
    /// (checked once its lengths are in, before anything is allocated);
    /// `None` when no frame may come at all.
    pub fn push(
        &mut self,
        data: &mut &[u8],
        max_body: Option<usize>,
    ) -> Result<Option<Frame>, AgentError> {
        while !data.is_empty() {
            if self.started.is_none() {
                self.started = Some(Instant::now());
            }
            match self.stage {
                Stage::Lengths => {
                    let take = (8 - self.have).min(data.len());
                    self.lengths[self.have..self.have + take].copy_from_slice(&data[..take]);
                    self.have += take;
                    *data = &data[take..];
                    if self.have < 8 {
                        continue;
                    }
                    let Some(max_body) = max_body else {
                        return Err(broken("a frame when nothing was asked"));
                    };
                    let head_len = u32::from_be_bytes(self.lengths[..4].try_into().unwrap());
                    let body_len = u32::from_be_bytes(self.lengths[4..].try_into().unwrap());
                    let (head_len, body_len) = (head_len as usize, body_len as usize);
                    if head_len > MAX_HEADER {
                        return Err(broken(format!("a frame header of {head_len} bytes")));
                    }
                    if body_len > max_body {
                        return Err(broken(format!(
                            "a frame body of {body_len} bytes, more than the {max_body} expected"
                        )));
                    }
                    self.head_len = head_len;
                    self.body_len = body_len;
                    self.head = Vec::new();
                    self.head
                        .try_reserve_exact(head_len)
                        .map_err(|_| broken("no memory for a frame"))?;
                    self.stage = Stage::Head;
                }
                Stage::Head => {
                    let take = (self.head_len - self.head.len()).min(data.len());
                    self.head.extend_from_slice(&data[..take]);
                    *data = &data[take..];
                }
                Stage::Body => {
                    let take = (self.body_len - self.body.len()).min(data.len());
                    self.body.extend_from_slice(&data[..take]);
                    *data = &data[take..];
                }
            }
            if let Some(frame) = self.advance()? {
                return Ok(Some(frame));
            }
        }
        // A frame with empty parts completes without more bytes.
        if self.stage != Stage::Lengths {
            return self.advance();
        }
        Ok(None)
    }

    /// Moves on from a part that is complete; returns a finished frame.
    fn advance(&mut self) -> Result<Option<Frame>, AgentError> {
        if self.stage == Stage::Head && self.head.len() == self.head_len {
            self.body = Vec::new();
            self.body
                .try_reserve_exact(self.body_len)
                .map_err(|_| broken("no memory for a frame"))?;
            self.stage = Stage::Body;
        }
        if self.stage == Stage::Body && self.body.len() == self.body_len {
            self.stage = Stage::Lengths;
            self.have = 0;
            self.started = None;
            let head = std::mem::take(&mut self.head);
            let body = std::mem::take(&mut self.body);
            return match serde_json::from_slice::<Value>(&head) {
                Ok(Value::Object(head)) => Ok(Some(Frame { head, body })),
                _ => Err(broken("a frame header that is not a JSON object")),
            };
        }
        Ok(None)
    }
}

pub fn set_nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Waits until `fd` is ready for `events` or `deadline` passes.
pub fn wait(fd: &impl AsRawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        let ms = left.as_millis().clamp(1, 60_000) as libc::c_int;
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut poll, 1, ms) };
        if n > 0 {
            return Ok(());
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

/// Encodes one frame.
pub fn encode(head: &Map<String, Value>, body: &[u8]) -> Result<Vec<u8>, AgentError> {
    let head = serde_json::to_vec(head).map_err(|e| broken(e.to_string()))?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(8 + head.len() + body.len())
        .map_err(|_| broken("no memory for a request"))?;
    frame.extend_from_slice(&(head.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&head);
    frame.extend_from_slice(body);
    Ok(frame)
}

/// The write side of the channel: the agent's stdin.
pub struct Writer {
    to: File,
}

impl Writer {
    pub fn new(to: OwnedFd) -> io::Result<Writer> {
        set_nonblocking(&to)?;
        Ok(Writer { to: File::from(to) })
    }

    /// Writes one frame, all of it before `deadline`.
    pub fn send(
        &mut self,
        head: &Map<String, Value>,
        body: &[u8],
        deadline: Instant,
    ) -> Result<(), AgentError> {
        let frame = encode(head, body)?;
        let mut data = &frame[..];
        while !data.is_empty() {
            match self.to.write(data) {
                Ok(0) => return Err(broken("the console does not take input")),
                Ok(n) => data = &data[n..],
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    wait(&self.to, libc::POLLOUT, deadline).map_err(|err| {
                        broken(format!("the agent does not read its requests: {err}"))
                    })?
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(broken(format!("writing a request: {err}"))),
            }
        }
        Ok(())
    }
}

/// Reads from `from` (non-blocking) until `parser` has a frame or
/// `deadline` passes.
pub fn read_frame(
    from: &mut File,
    parser: &mut FrameParser,
    max_body: usize,
    deadline: Instant,
) -> Result<Frame, AgentError> {
    let mut chunk = [0u8; 4096];
    loop {
        // One byte at a time past what a frame needs is never taken: read
        // only up to the end of the lengths, then of the frame.
        let want = match parser.stage {
            Stage::Lengths => 8 - parser.have,
            Stage::Head => parser.head_len - parser.head.len(),
            Stage::Body => parser.body_len - parser.body.len(),
        }
        .clamp(1, chunk.len());
        match from.read(&mut chunk[..want]) {
            Ok(0) => return Err(broken("the sandbox ended")),
            Ok(n) => {
                let mut data = &chunk[..n];
                if let Some(frame) = parser.push(&mut data, Some(max_body))? {
                    return Ok(frame);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                wait(from, libc::POLLIN, deadline)
                    .map_err(|err| broken(format!("no answer from the agent: {err}")))?
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(broken(format!("reading from the agent: {err}"))),
        }
    }
}

/// Waits for the agent's greeting after the clone started.
pub fn hello(from: &mut File, deadline: Instant) -> Result<Map<String, Value>, AgentError> {
    let mut parser = FrameParser::new();
    let frame = read_frame(from, &mut parser, 0, deadline)?;
    if frame.op() != Some("hello")
        || frame.head.get("version").and_then(Value::as_u64) != Some(VERSION)
    {
        return Err(broken(format!(
            "the agent did not greet with version {VERSION}"
        )));
    }
    Ok(frame.head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(head: &str, body: &[u8]) -> Vec<u8> {
        let mut out = (head.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn frames_parse_in_any_pieces() {
        let mut stream = frame(r#"{"id":1,"op":"output","stream":1}"#, b"hello");
        stream.extend(frame(r#"{"id":1,"ok":true}"#, b""));
        stream.extend(frame(r#"{"id":2}"#, b"xy"));
        // All at once, then byte by byte, then in pieces of 3.
        for piece in [stream.len(), 1, 3] {
            let mut parser = FrameParser::new();
            let mut frames = Vec::new();
            for chunk in stream.chunks(piece) {
                let mut data = chunk;
                while let Some(frame) = parser.push(&mut data, Some(16)).unwrap() {
                    frames.push(frame);
                }
                assert!(data.is_empty());
            }
            assert_eq!(frames.len(), 3, "pieces of {piece}");
            assert_eq!(frames[0].op(), Some("output"));
            assert_eq!(frames[0].body, b"hello");
            assert_eq!(frames[1].id(), Some(1));
            assert!(matches!(frames[1].outcome(), Some(Ok(()))));
            assert_eq!(frames[2].body, b"xy");
            assert!(parser.started().is_none());
        }
        // Started, not finished: the parser knows since when.
        let mut parser = FrameParser::new();
        let mut data = &stream[..5];
        assert!(parser.push(&mut data, Some(16)).unwrap().is_none());
        assert!(parser.started().is_some());
    }

    #[test]
    fn bad_frames_break_the_channel() {
        let push = |bytes: &[u8], max: Option<usize>| {
            let mut parser = FrameParser::new();
            let mut data = bytes;
            parser.push(&mut data, max)
        };
        // A body larger than allowed, before any of it arrives.
        assert!(push(&frame("{}", &[0; 17])[..8], Some(16)).is_err());
        // A header larger than any allowed.
        assert!(push(b"\xff\xff\xff\xff\0\0\0\0", Some(16)).is_err());
        // Not an object.
        assert!(push(&frame("[]", b""), Some(16)).is_err());
        assert!(push(&frame("{nope", b""), Some(16)).is_err());
        // Any frame when none may come.
        assert!(push(&frame("{}", b""), None).is_err());
        // A failure carries its code.
        let mut parser = FrameParser::new();
        let mut data = &frame(
            r#"{"id":3,"ok":false,"code":"not_found","message":"m"}"#,
            b"",
        )[..];
        let f = parser.push(&mut data, Some(0)).unwrap().unwrap();
        match f.outcome() {
            Some(Err(AgentError::Failed { code, .. })) => assert_eq!(code, "not_found"),
            other => panic!("{other:?}"),
        }
        assert!(frame_without_ok().outcome().is_none());
    }

    fn frame_without_ok() -> Frame {
        Frame {
            head: Map::new(),
            body: Vec::new(),
        }
    }

    fn obj(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    /// The agent run by the host's Python, outside any sandbox: its clone
    /// point is an ordinary file there, so it greets and serves at once.
    /// Exercises the protocol; the sandboxed agent is covered end to end.
    struct HostAgent {
        child: std::process::Child,
        writer: Writer,
        from: File,
        parser: FrameParser,
        next: u64,
    }

    /// What one request brought back.
    #[derive(Debug, Default)]
    struct Answer {
        head: Map<String, Value>,
        body: Vec<u8>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        /// Both streams, `o:`/`e:` tagged, in the order they came.
        order: String,
    }

    impl HostAgent {
        fn start(home: &std::path::Path) -> Option<HostAgent> {
            if !std::path::Path::new("/usr/bin/python3").exists() {
                eprintln!("no /usr/bin/python3: agent protocol test not run");
                return None;
            }
            // The script opens /dev/hellovm-clone, which the host lacks:
            // give it an empty stand-in.
            let source = AGENT_SOURCE.replace("/dev/hellovm-clone", "/dev/null");
            let mut child = std::process::Command::new("/usr/bin/python3")
                .args(["-I", "-c", &source, "json"])
                .env("HOME", home)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let to: OwnedFd = child.stdin.take().unwrap().into();
            let from: OwnedFd = child.stdout.take().unwrap().into();
            set_nonblocking(&from).unwrap();
            let mut from = File::from(from);
            let head = hello(&mut from, soon()).unwrap();
            assert_eq!(head["preloaded"], json!(["json"]));
            Some(HostAgent {
                child,
                writer: Writer::new(to).unwrap(),
                from,
                parser: FrameParser::new(),
                next: 1,
            })
        }

        fn send(&mut self, mut head: Map<String, Value>, body: &[u8]) -> u64 {
            let id = self.next;
            self.next += 1;
            head.insert("id".into(), json!(id));
            self.writer.send(&head, body, soon()).unwrap();
            id
        }

        fn cancel(&mut self, target: u64) {
            let head = obj(json!({"op": "cancel", "id": 0, "target": target}));
            self.writer.send(&head, b"", soon()).unwrap();
        }

        /// Frames until the final answer of `id`.
        fn answer(&mut self, id: u64) -> Result<Answer, AgentError> {
            let mut answer = Answer::default();
            loop {
                let frame = read_frame(&mut self.from, &mut self.parser, 1 << 20, soon())?;
                assert_eq!(frame.id(), Some(id), "{:?}", frame.head);
                match frame.op() {
                    Some("started") => continue,
                    Some("output") => {
                        let (out, tag) = match frame.head["stream"].as_u64() {
                            Some(1) => (&mut answer.stdout, 'o'),
                            _ => (&mut answer.stderr, 'e'),
                        };
                        out.extend_from_slice(&frame.body);
                        answer.order.push(tag);
                        answer.order.push_str(&String::from_utf8_lossy(&frame.body));
                        continue;
                    }
                    _ => {}
                }
                if let Some(Err(err)) = frame.outcome() {
                    return Err(err);
                }
                answer.head = frame.head;
                answer.body = frame.body;
                return Ok(answer);
            }
        }

        fn call(&mut self, head: Value, body: &[u8]) -> Result<Answer, AgentError> {
            let id = self.send(obj(head), body);
            self.answer(id)
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }

    #[test]
    fn the_agent_execs_and_handles_files() {
        let home = std::env::temp_dir().join(format!("hvagent-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let Some(mut agent) = HostAgent::start(&home) else {
            return;
        };
        let a = agent
            .call(
                json!({"op": "exec", "command": "echo out; echo err >&2; exit 3", "timeout": 10.0}),
                b"",
            )
            .unwrap();
        assert_eq!(a.head["exit_code"], json!(3));
        assert_eq!(a.head["cancelled"], json!(false));
        assert_eq!(a.stdout, b"out\n");
        assert_eq!(a.stderr, b"err\n");
        assert!(a.body.is_empty());

        // All of the output comes, in frames of at most OUTPUT_CHUNK.
        let a = agent
            .call(
                json!({"op": "exec", "command": "seq 1 100000", "timeout": 10.0}),
                b"",
            )
            .unwrap();
        assert_eq!(a.stdout.len(), 588895);
        assert!(a.stdout.ends_with(b"99999\n100000\n"));

        // A timeout kills the process group.
        let a = agent
            .call(
                json!({"op": "exec", "command": "sleep 30 & sleep 30", "timeout": 0.3}),
                b"",
            )
            .unwrap();
        assert_eq!(a.head["timed_out"], json!(true));
        assert_eq!(a.head["signal"], json!(9));

        // A cancel stops it, and says so.
        let id = agent.send(
            obj(json!({"op": "exec", "command": "echo go; sleep 30", "timeout": 20.0})),
            b"",
        );
        let started = Instant::now();
        agent.cancel(id);
        let a = agent.answer(id).unwrap();
        assert_eq!(a.head["cancelled"], json!(true), "{:?}", a.head);
        assert_eq!(a.head["timed_out"], json!(false));
        assert!(started.elapsed() < Duration::from_secs(10));
        // A cancel that comes after the end is ignored.
        agent.cancel(id);

        // stdin, python in a fork with the preloaded modules.
        let a = agent
            .call(
                json!({"op": "exec", "python": "import sys; print(sys.stdin.read().upper(), 'json' in sys.modules)",
                    "timeout": 10.0, "has_stdin": true}),
                b"abc",
            )
            .unwrap();
        assert_eq!(a.head["exit_code"], json!(0), "{:?}", a);
        assert_eq!(a.stdout, b"ABC True\n");

        // The stateful interpreter keeps its namespace.
        let stateful =
            |code: &str| json!({"op": "exec", "python": code, "stateful": true, "timeout": 10.0});
        let a = agent
            .call(stateful("import json\nx = 40\nprint('set')"), b"")
            .unwrap();
        assert_eq!(a.stdout, b"set\n");
        assert_eq!(a.head["state_lost"], json!(false));
        assert!(a.head.get("value_len").is_none());
        let a = agent.call(stateful("x + 2"), b"").unwrap();
        assert_eq!(a.body, b"42");
        assert_eq!(a.head["value_len"], json!(2));
        let a = agent.call(stateful("1/0"), b"").unwrap();
        assert_eq!(a.head["error"]["type"], json!("ZeroDivisionError"));
        assert_eq!(a.head["exit_code"], json!(1));
        let trace = String::from_utf8_lossy(&a.body);
        assert!(
            trace.contains("ZeroDivisionError") && trace.contains("1/0"),
            "{trace}"
        );
        let a = agent.call(stateful("json.dumps(x)"), b"").unwrap();
        assert_eq!(a.body, b"'40'");
        // Interrupted at its timeout: the state survives.
        let a = agent
            .call(
                json!({"op": "exec", "python": "import time\ny = 1\ntime.sleep(30)",
                    "stateful": true, "timeout": 0.5}),
                b"",
            )
            .unwrap();
        assert_eq!(a.head["timed_out"], json!(true));
        assert_eq!(a.head["error"]["type"], json!("KeyboardInterrupt"));
        assert_eq!(a.head["state_lost"], json!(false));
        let a = agent.call(stateful("x + y"), b"").unwrap();
        assert_eq!(a.body, b"41");
        // Reset: a fresh one.
        let a = agent.call(json!({"op": "reset"}), b"").unwrap();
        assert_eq!(a.head["had_state"], json!(true));
        let a = agent.call(stateful("'x' in dir()"), b"").unwrap();
        assert_eq!(a.body, b"False");
        assert_eq!(a.head["state_lost"], json!(false));
        // Code that ignores the interrupt: killed, and the state is lost.
        agent
            .call(
                stateful("import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nz = 1"),
                b"",
            )
            .unwrap();
        let started = Instant::now();
        let a = agent
            .call(
                json!({"op": "exec", "python": "while True: pass", "stateful": true, "timeout": 0.3}),
                b"",
            )
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(a.head["error"]["type"], json!("InterpreterKilled"), "{a:?}");
        assert_eq!(a.head["state_lost"], json!(true));
        assert_eq!(a.head["signal"], json!(9));
        let a = agent.call(stateful("'z' in dir()"), b"").unwrap();
        assert_eq!(a.body, b"False");
        assert_eq!(a.head["state_lost"], json!(false));
        // An interpreter that ends.
        let a = agent.call(stateful("import os\nos._exit(3)"), b"").unwrap();
        assert_eq!(a.head["error"]["type"], json!("InterpreterExited"), "{a:?}");
        assert_eq!(a.head["exit_code"], json!(3));
        assert_eq!(a.head["state_lost"], json!(true));
        let a = agent.call(stateful("2 * 21"), b"").unwrap();
        assert_eq!(a.body, b"42");

        // Files.
        agent
            .call(json!({"op": "write", "path": "d/f.txt"}), b"hello world")
            .unwrap();
        let a = agent
            .call(
                json!({"op": "read", "path": "d/f.txt", "max_bytes": 100}),
                b"",
            )
            .unwrap();
        assert_eq!(a.body, b"hello world");
        let a = agent
            .call(
                json!({"op": "edit", "path": "d/f.txt", "old": "world", "new": "there", "max_bytes": 100}),
                b"",
            )
            .unwrap();
        assert_eq!(a.head["replacements"], json!(1));
        assert_eq!(std::fs::read(home.join("d/f.txt")).unwrap(), b"hello there");
        match agent.call(
            json!({"op": "read", "path": "missing", "max_bytes": 100}),
            b"",
        ) {
            Err(AgentError::Failed { code, .. }) => assert_eq!(code, "not_found"),
            other => panic!("{other:?}"),
        }
        drop(agent.writer);
        agent.child.wait().unwrap();
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn silence_is_a_timeout_not_a_hang() {
        let (from_r, _from_w) = std::io::pipe().unwrap();
        let from: OwnedFd = from_r.into();
        set_nonblocking(&from).unwrap();
        let mut from = File::from(from);
        let start = Instant::now();
        let result = hello(&mut from, Instant::now() + Duration::from_millis(200));
        assert!(matches!(result, Err(AgentError::Broken(_))));
        assert!(start.elapsed() < Duration::from_secs(2));
        // A greeting of another version.
        let (from_r, mut from_w) = std::io::pipe().unwrap();
        from_w
            .write_all(&frame(r#"{"id":0,"op":"hello","version":1}"#, b""))
            .unwrap();
        let from: OwnedFd = from_r.into();
        set_nonblocking(&from).unwrap();
        let result = hello(&mut File::from(from), soon());
        assert!(matches!(result, Err(AgentError::Broken(_))));
    }
}
