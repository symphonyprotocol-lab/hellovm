//! The JSON bodies of the public API (`hellovm-api`) and of the node API
//! (`hellovm-noded`). Unknown fields are refused, so a misspelt option is
//! an error rather than silently ignored.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Most bytes of a file `read_file` returns and `write_file` accepts.
pub const MAX_FILE: usize = 16 << 20;
/// Default and largest output kept per stream of an exec.
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;
pub const MAX_OUTPUT: usize = 1 << 20;
/// Default and longest exec timeout, in seconds.
pub const DEFAULT_EXEC_TIMEOUT: f64 = 60.0;
pub const MAX_EXEC_TIMEOUT: f64 = 3600.0;
/// Longest command, Python source, or stdin of an exec.
pub const MAX_COMMAND: usize = 1 << 20;
/// Most environment variables an exec may set, and their total size.
pub const MAX_ENV: usize = 256;
pub const MAX_ENV_BYTES: usize = 64 * 1024;
/// Longest path in a file operation.
pub const MAX_PATH: usize = 4096;
/// Largest JSON request body.
pub const MAX_JSON: usize = 4 << 20;
/// Longest a poll of an exec's output waits for something new, in
/// seconds.
pub const MAX_POLL_WAIT: f64 = 30.0;
/// Default, smallest and largest output a poll returns, in bytes.
pub const DEFAULT_POLL_BYTES: usize = 256 * 1024;
pub const MIN_POLL_BYTES: usize = 1024;
pub const MAX_POLL_BYTES: usize = 1 << 20;
/// Most characters of a stateful call's value (`repr`) and of its
/// traceback; longer ones keep their start and end.
pub const MAX_VALUE: usize = 16 * 1024;
pub const MAX_TRACEBACK: usize = 16 * 1024;

/// `POST /v1/sandboxes` (public API).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreateSandbox {
    /// A template name the node keeps warm (`python`, say).
    pub template: String,
    /// Seconds without any request after which the sandbox is removed.
    #[serde(default)]
    pub idle_timeout: Option<f64>,
    /// Seconds after creation after which the sandbox is removed.
    #[serde(default)]
    pub lifetime: Option<f64>,
}

/// `POST /v1/sandboxes` on a node: the public request plus what the API
/// decided.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeCreate {
    pub id: String,
    pub tenant: String,
    pub template: String,
    pub idle_timeout: f64,
    pub lifetime: f64,
}

/// A sandbox as both APIs describe it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxInfo {
    pub id: String,
    pub tenant: String,
    pub template: String,
    /// Which node runs it.
    pub node: String,
    /// The id in the egress proxy's audit lines (16 hex digits).
    pub egress_id: String,
    /// Unix milliseconds.
    pub created_at: u64,
    pub last_used_at: u64,
    pub expires_at: u64,
    pub idle_timeout: f64,
    /// Private memory of the sandbox's processes at the last measurement.
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    /// How long the request that made it took on the node, in ms (ready
    /// means the agent in the sandbox answered).
    pub ready_ms: f64,
}

/// `GET /v1/sandboxes`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxList {
    pub sandboxes: Vec<SandboxInfo>,
}

/// `POST /v1/sandboxes/{id}/exec` and `POST /v1/sandboxes/{id}/execs`.
/// Exactly one of `command` (run by `/bin/sh -c`) and `python` is given.
/// `python` runs in a fresh fork of the sandbox's warm interpreter, or,
/// with `stateful`, in the sandbox's interpreter whose namespace persists
/// between calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
    /// Seconds; the command is killed after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    /// Working directory (default: the sandbox's home, `/root`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Added to the environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    /// Given to the command on its stdin (otherwise it reads end of file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Bytes kept per stream; the rest is cut from the middle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output: Option<usize>,
    /// With `python`: run it in the sandbox's long-lived interpreter, whose
    /// variables, imports and objects persist between calls.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stateful: bool,
}

impl ExecRequest {
    /// Checks the bounds and fills in defaults: the timeout and the output
    /// limit it will run with.
    pub fn validate(&self) -> Result<(f64, usize), String> {
        match (&self.command, &self.python) {
            (Some(code), None) | (None, Some(code)) => {
                if code.len() > MAX_COMMAND {
                    return Err(format!("the command is longer than {MAX_COMMAND} bytes"));
                }
                if code.contains('\0') {
                    return Err("the command contains a NUL byte".into());
                }
            }
            _ => return Err("give exactly one of `command` and `python`".into()),
        }
        if self.stateful {
            if self.python.is_none() {
                return Err("`stateful` goes with `python`".into());
            }
            if self.cwd.is_some() || self.env.is_some() {
                return Err(
                    "a stateful call runs in the interpreter's own working directory and \
                     environment (change them with os.chdir and os.environ): no `cwd` or `env`"
                        .into(),
                );
            }
        }
        let timeout = self.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
        if !(timeout.is_finite() && timeout > 0.0 && timeout <= MAX_EXEC_TIMEOUT) {
            return Err(format!(
                "timeout must be more than 0 and at most {MAX_EXEC_TIMEOUT} seconds"
            ));
        }
        let max_output = self.max_output.unwrap_or(DEFAULT_MAX_OUTPUT);
        if !(256..=MAX_OUTPUT).contains(&max_output) {
            return Err(format!("max_output must be between 256 and {MAX_OUTPUT}"));
        }
        if let Some(cwd) = &self.cwd {
            check_path(cwd)?;
        }
        if let Some(stdin) = &self.stdin {
            if stdin.len() > MAX_COMMAND {
                return Err(format!("stdin is longer than {MAX_COMMAND} bytes"));
            }
        }
        if let Some(env) = &self.env {
            if env.len() > MAX_ENV {
                return Err(format!("more than {MAX_ENV} environment variables"));
            }
            let mut bytes = 0;
            for (name, value) in env {
                if name.is_empty()
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || name.as_bytes()[0].is_ascii_digit()
                {
                    return Err(format!("malformed environment variable name {name:?}"));
                }
                if value.contains('\0') {
                    return Err(format!("environment variable {name} contains a NUL byte"));
                }
                bytes += name.len() + value.len() + 2;
            }
            if bytes > MAX_ENV_BYTES {
                return Err(format!(
                    "the environment is larger than {MAX_ENV_BYTES} bytes"
                ));
            }
        }
        Ok((timeout, max_output))
    }
}

/// A path in a file operation: non-empty, no NUL, bounded. Relative paths
/// are relative to the sandbox's home.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') {
        return Err(format!(
            "a path must be 1 to {MAX_PATH} bytes without NUL bytes"
        ));
    }
    Ok(())
}

/// What an exec did.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecResult {
    /// The exec's id in its sandbox (`ex-N`).
    #[serde(default)]
    pub exec_id: String,
    /// The exit status, when the command exited (a stateful call: 0, or 1
    /// when it raised).
    pub exit_code: Option<i32>,
    /// The signal that killed it, when one did (9 after a timeout or a
    /// cancel).
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// Ended by a cancel.
    #[serde(default)]
    pub cancelled: bool,
    /// Output decoded as UTF-8 (invalid bytes replaced). When longer than
    /// `max_output`, the middle is replaced by a line saying how many
    /// bytes were left out.
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    /// Bytes the command wrote to each stream in all.
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub duration_ms: f64,
    /// A stateful call: the `repr` of the value of the code's last
    /// expression, when it ends in one whose value is not `None` (at most
    /// [`MAX_VALUE`] characters, the middle cut).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// A stateful call: the exception it raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExecError>,
    /// A stateful call: whether the interpreter's state (its namespace)
    /// was lost, by this call or since the last one: the interpreter could
    /// not be interrupted and was killed, or it ended. The next call starts
    /// a fresh one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_lost: Option<bool>,
}

/// The exception a stateful call raised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecError {
    /// Its class name (`ZeroDivisionError`, `KeyboardInterrupt`).
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
    /// The formatted traceback (at most [`MAX_TRACEBACK`] characters, the
    /// middle cut).
    pub traceback: String,
}

/// Whether an exec runs or ended.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Running,
    Done,
}

/// What an exec runs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecKind {
    Command,
    Python,
    Stateful,
}

/// An exec as `POST .../execs`, `GET .../execs` and `.../cancel` describe
/// it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecStatus {
    pub exec_id: String,
    pub kind: ExecKind,
    pub state: ExecState,
    /// Unix milliseconds.
    pub started_at: u64,
    /// Set once cancelled, until it ends.
    pub cancel_requested: bool,
    /// Once it ended.
    pub result: Option<ExecResult>,
}

/// `GET /v1/sandboxes/{id}/execs`: the sandbox's latest exec, if any.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecList {
    pub execs: Vec<ExecStatus>,
}

/// One piece of an exec's output stream, in the order it was produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputEvent {
    Stdout { data: String },
    Stderr { data: String },
    /// Output that was not kept (nobody read it while it was held, and
    /// more came after it): this many bytes.
    Omitted { bytes: u64 },
}

/// `GET /v1/sandboxes/{id}/execs/{exec}?cursor=&wait=&max_bytes=`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecPoll {
    pub exec_id: String,
    pub state: ExecState,
    /// The output after `cursor`, oldest first.
    pub events: Vec<OutputEvent>,
    /// The cursor of the next poll (a byte position in the exec's output).
    pub next_cursor: u64,
    /// The exec ended and `next_cursor` is the end of its output: nothing
    /// more will come.
    pub eof: bool,
    /// Once it ended.
    pub result: Option<ExecResult>,
}

/// `POST /v1/sandboxes/{id}/python/reset`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResetResult {
    /// Whether there was an interpreter (and so state) to discard.
    pub had_state: bool,
}

/// The query of a poll, checked: `cursor` (default 0), `wait` seconds
/// (default 0, at most [`MAX_POLL_WAIT`]), `max_bytes` (default
/// [`DEFAULT_POLL_BYTES`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PollQuery {
    pub cursor: u64,
    pub wait: f64,
    pub max_bytes: usize,
}

impl PollQuery {
    pub fn parse(
        cursor: Option<&str>,
        wait: Option<&str>,
        max_bytes: Option<&str>,
    ) -> Result<PollQuery, String> {
        let cursor = match cursor {
            None => 0,
            Some(c) => c
                .parse::<u64>()
                .map_err(|_| "cursor must be a byte position".to_string())?,
        };
        let wait = match wait {
            None => 0.0,
            Some(w) => w
                .parse::<f64>()
                .ok()
                .filter(|w| w.is_finite() && (0.0..=MAX_POLL_WAIT).contains(w))
                .ok_or(format!("wait must be 0 to {MAX_POLL_WAIT} seconds"))?,
        };
        let max_bytes = match max_bytes {
            None => DEFAULT_POLL_BYTES,
            Some(m) => m
                .parse::<usize>()
                .ok()
                .filter(|m| (MIN_POLL_BYTES..=MAX_POLL_BYTES).contains(m))
                .ok_or(format!(
                    "max_bytes must be {MIN_POLL_BYTES} to {MAX_POLL_BYTES}"
                ))?,
        };
        Ok(PollQuery {
            cursor,
            wait,
            max_bytes,
        })
    }

    /// The query string that says the same.
    pub fn to_query(&self) -> String {
        format!(
            "cursor={}&wait={}&max_bytes={}",
            self.cursor, self.wait, self.max_bytes
        )
    }
}

/// An exec id: `ex-` and a decimal number.
pub fn check_exec_id(id: &str) -> Option<u64> {
    let n = id.strip_prefix("ex-")?;
    if n.is_empty() || n.len() > 19 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// `POST /v1/sandboxes/{id}/files/edit`: replace `old` by `new` in the
/// file; `old` must occur exactly once unless `replace_all`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EditRequest {
    pub path: String,
    pub old: String,
    pub new: String,
    #[serde(default)]
    pub replace_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EditResult {
    pub replacements: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WriteResult {
    pub bytes: u64,
}

/// One template, as a node reports it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateStatus {
    pub name: String,
    pub ready: bool,
    /// How often it was (re)started.
    pub starts: u64,
    /// The one tenant it serves, if it is not shared.
    pub tenant: Option<String>,
    /// The template's `hellovm` process, while it runs.
    pub pid: Option<u32>,
}

/// `GET /v1/node`: what a node offers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeStatus {
    pub node: String,
    pub templates: Vec<TemplateStatus>,
    pub sandboxes: usize,
    pub max_sandboxes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_requests_are_checked() {
        let ok = ExecRequest {
            command: Some("echo hi".into()),
            ..ExecRequest::default()
        };
        assert_eq!(
            ok.validate(),
            Ok((DEFAULT_EXEC_TIMEOUT, DEFAULT_MAX_OUTPUT))
        );
        let both = ExecRequest {
            python: Some("1".into()),
            ..ok.clone()
        };
        assert!(both.validate().is_err());
        assert!(ExecRequest::default().validate().is_err());
        for timeout in [0.0, -1.0, f64::NAN, f64::INFINITY, MAX_EXEC_TIMEOUT + 1.0] {
            let bad = ExecRequest {
                timeout: Some(timeout),
                ..ok.clone()
            };
            assert!(bad.validate().is_err(), "{timeout}");
        }
        let env = ExecRequest {
            env: Some([("1X".to_string(), "y".to_string())].into()),
            ..ok.clone()
        };
        assert!(env.validate().is_err());
        let output = ExecRequest {
            max_output: Some(MAX_OUTPUT + 1),
            ..ok.clone()
        };
        assert!(output.validate().is_err());
        assert!(serde_json::from_str::<ExecRequest>(r#"{"command":"x","bogus":1}"#).is_err());
        let stateful = ExecRequest {
            python: Some("x = 1".into()),
            stateful: true,
            ..ExecRequest::default()
        };
        assert!(stateful.validate().is_ok());
        assert!(ExecRequest {
            stateful: true,
            ..ok.clone()
        }
        .validate()
        .is_err());
        assert!(ExecRequest {
            cwd: Some("/tmp".into()),
            ..stateful.clone()
        }
        .validate()
        .is_err());
        // `stateful: false` is the default and not written out.
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"command":"echo hi"}"#);
    }

    #[test]
    fn poll_queries_are_checked() {
        let q = PollQuery::parse(Some("12"), Some("1.5"), Some("2048")).unwrap();
        assert_eq!((q.cursor, q.wait, q.max_bytes), (12, 1.5, 2048));
        assert_eq!(q.to_query(), "cursor=12&wait=1.5&max_bytes=2048");
        let d = PollQuery::parse(None, None, None).unwrap();
        assert_eq!((d.cursor, d.wait, d.max_bytes), (0, 0.0, DEFAULT_POLL_BYTES));
        for (c, w, m) in [
            (Some("-1"), None, None),
            (Some("x"), None, None),
            (None, Some("31"), None),
            (None, Some("NaN"), None),
            (None, Some("-0.5"), None),
            (None, None, Some("10")),
            (None, None, Some("99999999")),
        ] {
            assert!(PollQuery::parse(c, w, m).is_err(), "{c:?} {w:?} {m:?}");
        }
        assert_eq!(check_exec_id("ex-17"), Some(17));
        for bad in ["ex-", "ex-1a", "17", "ex-99999999999999999999", "ex--1"] {
            assert_eq!(check_exec_id(bad), None, "{bad}");
        }
        let event = serde_json::to_string(&OutputEvent::Omitted { bytes: 3 }).unwrap();
        assert_eq!(event, r#"{"type":"omitted","bytes":3}"#);
    }
}
