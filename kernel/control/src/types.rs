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

/// `POST /v1/sandboxes/{id}/exec`. Exactly one of `command` (run by
/// `/bin/sh -c`) and `python` (run by the sandbox's warm interpreter in a
/// fresh fork of it) is given.
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
    /// The exit status, when the command exited.
    pub exit_code: Option<i32>,
    /// The signal that killed it, when one did (9 after a timeout).
    pub signal: Option<i32>,
    pub timed_out: bool,
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
    }
}
