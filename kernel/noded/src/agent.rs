//! The channel to the agent inside a sandbox: frames on the clone's
//! console (see `agent.py`).
//!
//! ```text
//! [header length u32 BE][body length u32 BE][header: JSON object][body]
//! ```
//!
//! The agent runs as the guest, and the guest can write to its own console
//! (`/dev/console`), so every frame read here is untrusted: its lengths are
//! checked against what the request can legitimately produce before
//! anything is allocated, every read and write has a deadline, the answer
//! must carry the request's id, and any violation ends the conversation
//! (the caller then removes the sandbox: it can only have broken itself).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Instant;

use serde_json::{json, Map, Value};

/// Largest answer header accepted.
pub const MAX_HEADER: usize = 64 * 1024;

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

fn broken(why: impl Into<String>) -> AgentError {
    AgentError::Broken(why.into())
}

/// One sandbox's agent.
pub struct Agent {
    to: File,
    from: File,
    next_id: u64,
}

fn set_nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
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
fn wait(fd: &impl AsRawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
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

impl Agent {
    /// `to` is the write end of the clone's stdin, `from` the read end of
    /// its stdout.
    pub fn new(to: OwnedFd, from: OwnedFd) -> io::Result<Agent> {
        set_nonblocking(&to)?;
        set_nonblocking(&from)?;
        Ok(Agent {
            to: File::from(to),
            from: File::from(from),
            next_id: 1,
        })
    }

    fn write_all(&mut self, mut data: &[u8], deadline: Instant) -> Result<(), AgentError> {
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
                Err(err) => return Err(broken(format!("writing the request: {err}"))),
            }
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), AgentError> {
        let mut have = 0;
        while have < buf.len() {
            match self.from.read(&mut buf[have..]) {
                Ok(0) => return Err(broken("the sandbox ended")),
                Ok(n) => have += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    wait(&self.from, libc::POLLIN, deadline)
                        .map_err(|err| broken(format!("no answer from the agent: {err}")))?
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(broken(format!("reading the answer: {err}"))),
            }
        }
        Ok(())
    }

    /// Reads one frame whose body may be at most `max_body` bytes.
    fn read_frame(
        &mut self,
        deadline: Instant,
        max_body: usize,
    ) -> Result<(Map<String, Value>, Vec<u8>), AgentError> {
        let mut lengths = [0u8; 8];
        self.read_exact(&mut lengths, deadline)?;
        let head_len = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
        let body_len = u32::from_be_bytes(lengths[4..].try_into().unwrap()) as usize;
        if head_len > MAX_HEADER {
            return Err(broken(format!("an answer header of {head_len} bytes")));
        }
        if body_len > max_body {
            return Err(broken(format!(
                "an answer body of {body_len} bytes, more than the {max_body} expected"
            )));
        }
        let mut head = vec![0u8; head_len];
        self.read_exact(&mut head, deadline)?;
        let mut body = vec![0u8; body_len];
        self.read_exact(&mut body, deadline)?;
        match serde_json::from_slice::<Value>(&head) {
            Ok(Value::Object(map)) => Ok((map, body)),
            _ => Err(broken("an answer header that is not a JSON object")),
        }
    }

    /// Waits for the agent's greeting after the clone started.
    pub fn hello(&mut self, deadline: Instant) -> Result<Map<String, Value>, AgentError> {
        let (head, _) = self.read_frame(deadline, 0)?;
        if head.get("op").and_then(Value::as_str) != Some("hello")
            || head.get("version").and_then(Value::as_u64) != Some(1)
        {
            return Err(broken("the agent did not greet with version 1"));
        }
        Ok(head)
    }

    /// Sends one request and returns the answer's header and body. `request`
    /// must be a JSON object; its `id` is set here.
    pub fn call(
        &mut self,
        mut request: Map<String, Value>,
        body: &[u8],
        deadline: Instant,
        max_body: usize,
    ) -> Result<(Map<String, Value>, Vec<u8>), AgentError> {
        let id = self.next_id;
        self.next_id += 1;
        request.insert("id".into(), json!(id));
        let head = serde_json::to_vec(&request).map_err(|e| broken(e.to_string()))?;
        let mut frame = Vec::with_capacity(8 + head.len() + body.len());
        frame.extend_from_slice(&(head.len() as u32).to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&head);
        frame.extend_from_slice(body);
        self.write_all(&frame, deadline)?;
        drop(frame);
        let (answer, body) = self.read_frame(deadline, max_body)?;
        if answer.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(broken("an answer to another request"));
        }
        match answer.get("ok") {
            Some(Value::Bool(true)) => Ok((answer, body)),
            Some(Value::Bool(false)) => {
                let text = |key: &str| {
                    let s = answer.get(key).and_then(Value::as_str).unwrap_or("");
                    s.chars().take(1000).collect::<String>()
                };
                Err(AgentError::Failed {
                    code: text("code"),
                    message: text("message"),
                })
            }
            _ => Err(broken("an answer without `ok`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The agent run by the host's Python, outside any sandbox: its clone
    /// point is an ordinary file there, so it greets and serves at once.
    /// Exercises the protocol; the sandboxed agent is covered end to end.
    fn host_agent(home: &std::path::Path) -> Option<(std::process::Child, Agent)> {
        if !std::path::Path::new("/usr/bin/python3").exists() {
            eprintln!("no /usr/bin/python3: agent protocol test not run");
            return None;
        }
        // The script opens /dev/hellovm-clone, which the host lacks: give
        // it an empty stand-in.
        let source = AGENT_SOURCE.replace("/dev/hellovm-clone", "/dev/null");
        let child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-c", &source, "json"])
            .env("HOME", home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = child;
        let to: OwnedFd = child.stdin.take().unwrap().into();
        let from: OwnedFd = child.stdout.take().unwrap().into();
        Some((child, Agent::new(to, from).unwrap()))
    }

    fn obj(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    #[test]
    fn the_agent_execs_and_handles_files() {
        let home = std::env::temp_dir().join(format!("hvagent-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let Some((mut child, mut agent)) = host_agent(&home) else {
            return;
        };
        let soon = || Instant::now() + Duration::from_secs(20);
        let hello = agent.hello(soon()).unwrap();
        assert_eq!(hello["preloaded"], json!(["json"]));

        let (head, body) = agent
            .call(
                obj(
                    json!({"op": "exec", "command": "echo out; echo err >&2; exit 3",
                    "timeout": 10.0, "max_output": 1024}),
                ),
                b"",
                soon(),
                4096,
            )
            .unwrap();
        assert_eq!(head["exit_code"], json!(3));
        let split = head["stdout_len"].as_u64().unwrap() as usize;
        assert_eq!(&body[..split], b"out\n");
        assert_eq!(&body[split..], b"err\n");

        // Long output keeps its head and tail.
        let (head, body) = agent
            .call(
                obj(json!({"op": "exec", "command": "seq 1 100000",
                    "timeout": 10.0, "max_output": 1000})),
                b"",
                soon(),
                4096,
            )
            .unwrap();
        assert_eq!(head["stdout_truncated"], json!(true));
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with("1\n2\n"), "{text}");
        assert!(text.ends_with("99999\n100000\n"), "{text}");
        assert!(text.contains("bytes omitted ...]"), "{text}");

        // A timeout kills the process group.
        let (head, _) = agent
            .call(
                obj(json!({"op": "exec", "command": "sleep 30 & sleep 30",
                    "timeout": 0.3, "max_output": 1024})),
                b"",
                soon(),
                4096,
            )
            .unwrap();
        assert_eq!(head["timed_out"], json!(true));
        assert_eq!(head["signal"], json!(9));

        // stdin, python in a fork with the preloaded modules.
        let (head, body) = agent
            .call(
                obj(json!({"op": "exec", "python": "import sys; print(sys.stdin.read().upper(), 'json' in sys.modules)",
                    "timeout": 10.0, "max_output": 1024, "has_stdin": true})),
                b"abc",
                soon(),
                4096,
            )
            .unwrap();
        assert_eq!(head["exit_code"], json!(0), "{head:?} {body:?}");
        assert_eq!(body, b"ABC True\n");

        // Files.
        agent
            .call(
                obj(json!({"op": "write", "path": "d/f.txt"})),
                b"hello world",
                soon(),
                0,
            )
            .unwrap();
        let (_, body) = agent
            .call(
                obj(json!({"op": "read", "path": "d/f.txt", "max_bytes": 100})),
                b"",
                soon(),
                100,
            )
            .unwrap();
        assert_eq!(body, b"hello world");
        let (head, _) = agent
            .call(
                obj(json!({"op": "edit", "path": "d/f.txt", "old": "world", "new": "there", "max_bytes": 100})),
                b"",
                soon(),
                0,
            )
            .unwrap();
        assert_eq!(head["replacements"], json!(1));
        assert_eq!(std::fs::read(home.join("d/f.txt")).unwrap(), b"hello there");
        match agent.call(
            obj(json!({"op": "read", "path": "missing", "max_bytes": 100})),
            b"",
            soon(),
            100,
        ) {
            Err(AgentError::Failed { code, .. }) => assert_eq!(code, "not_found"),
            other => panic!("{other:?}"),
        }
        // An answer larger than the caller allows breaks the channel.
        match agent.call(
            obj(json!({"op": "read", "path": "d/f.txt", "max_bytes": 100})),
            b"",
            soon(),
            4,
        ) {
            Err(AgentError::Broken(_)) => {}
            other => panic!("{other:?}"),
        }
        drop(agent);
        child.wait().unwrap();
        std::fs::remove_dir_all(&home).unwrap();
    }

    impl std::fmt::Debug for Agent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Agent")
        }
    }

    #[test]
    fn garbage_from_the_sandbox_breaks_the_channel() {
        for garbage in [
            &b"\xff\xff\xff\xff\0\0\0\0"[..],
            b"\0\0\0\x02\0\0\0\0[]",
            b"\0\0\0\x0b\0\0\0\0{\"id\":999}",
            b"\0\0",
        ] {
            let (to_r, to_w) = std::io::pipe().unwrap();
            let (from_r, mut from_w) = std::io::pipe().unwrap();
            let mut agent = Agent::new(to_w.into(), from_r.into()).unwrap();
            from_w.write_all(garbage).unwrap();
            drop(from_w);
            let result = agent.call(
                Map::new(),
                b"",
                Instant::now() + Duration::from_secs(2),
                1024,
            );
            assert!(matches!(result, Err(AgentError::Broken(_))), "{garbage:?}");
            drop(to_r);
        }
        // Silence is a timeout, not a hang.
        let (_to_r, to_w) = std::io::pipe().unwrap();
        let (from_r, _from_w) = std::io::pipe().unwrap();
        let mut agent = Agent::new(to_w.into(), from_r.into()).unwrap();
        let start = Instant::now();
        let result = agent.call(
            Map::new(),
            b"",
            Instant::now() + Duration::from_millis(200),
            1024,
        );
        assert!(matches!(result, Err(AgentError::Broken(_))));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
