//! `noded`'s configuration file (JSON).
//!
//! ```json
//! {
//!   "node": "node-1",
//!   "listen": "127.0.0.1:7071",
//!   "token_file": "/etc/hellovm/node.token",
//!   "hellovm": "/usr/local/bin/hellovm",
//!   "state_dir": "/run/hellovm-noded",
//!   "egress": "/run/hellovm/egress.sock",
//!   "max_sandboxes": 64,
//!   "templates": [
//!     {"name": "python", "root": "/", "python": "/usr/bin/python3",
//!      "preload": ["json", "decimal"], "memory_limit_mb": 1024,
//!      "fs_limit_mb": 512}
//!   ]
//! }
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This node's name, reported to the API.
    pub node: String,
    /// `HOST:PORT` of the node API (the API service calls it).
    pub listen: String,
    /// The bearer token the API presents, or a file holding it.
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// The `hellovm` binary.
    pub hellovm: PathBuf,
    /// A directory only noded uses: the templates' sockets and a lock.
    pub state_dir: PathBuf,
    /// The egress proxy's socket (`hellovm --egress`); none: no network.
    #[serde(default)]
    pub egress: Option<PathBuf>,
    #[serde(default = "default_max_sandboxes")]
    pub max_sandboxes: usize,
    pub templates: Vec<TemplateConfig>,
}

fn default_max_sandboxes() -> usize {
    64
}

/// How strictly a template's kernel process is hardened (`hellovm
/// --sandbox`).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    Require,
    BestEffort,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateConfig {
    pub name: String,
    /// The image directory.
    pub root: PathBuf,
    /// The interpreter inside the image that runs the agent.
    #[serde(default = "default_python")]
    pub python: String,
    /// Modules imported before the clone point.
    #[serde(default)]
    pub preload: Vec<String>,
    /// Extra environment of the sandbox (`hellovm --env`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// A sandbox whose processes hold more private memory than this is
    /// removed.
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: u64,
    /// The writable layer's limit (`hellovm --fs-limit`): writes past it
    /// fail with `ENOSPC`.
    #[serde(default = "default_fs_limit")]
    pub fs_limit_mb: u64,
    /// Most processes and threads a sandbox may have (each is a host
    /// process, the sandbox's kernel process is one more); one over is
    /// removed.
    #[serde(default = "default_max_processes")]
    pub max_processes: usize,
    /// The one tenant this template serves. A shared template (none) runs
    /// with `--sandbox require`, which needs Landlock to fence its clones
    /// from each other.
    #[serde(default)]
    pub tenant: Option<String>,
    /// For a template of one tenant: `best-effort` allows a host without
    /// Landlock.
    #[serde(default)]
    pub sandbox: Option<SandboxMode>,
}

fn default_python() -> String {
    "/usr/bin/python3".into()
}

fn default_memory_limit() -> u64 {
    1024
}

/// Most host processes (guest processes and threads, plus the kernel
/// process) a sandbox's limit may be.
pub const MAX_PROCESSES: usize = 4096;

fn default_max_processes() -> usize {
    MAX_PROCESSES
}

fn default_fs_limit() -> u64 {
    1024
}

/// A name of a template or tenant: what can safely be a file name and a
/// log field.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_module(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

impl TemplateConfig {
    pub fn sandbox_mode(&self) -> SandboxMode {
        match (&self.tenant, self.sandbox) {
            (Some(_), Some(mode)) => mode,
            _ => SandboxMode::Require,
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let config: Config = serde_json::from_str(text).map_err(|e| e.to_string())?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), String> {
        if !valid_name(&self.node) {
            return Err(format!(
                "node name {:?}: use 1-64 letters, digits, - and _",
                self.node
            ));
        }
        if self.max_sandboxes == 0 || self.max_sandboxes > 4096 {
            return Err("max_sandboxes must be 1 to 4096".into());
        }
        if self.templates.is_empty() {
            return Err("no templates".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for t in &self.templates {
            if !valid_name(&t.name) {
                return Err(format!(
                    "template name {:?}: use 1-64 letters, digits, - and _",
                    t.name
                ));
            }
            if !names.insert(&t.name) {
                return Err(format!("template {} is defined twice", t.name));
            }
            if let Some(m) = t.preload.iter().find(|m| !valid_module(m)) {
                return Err(format!("template {}: {m:?} is not a module name", t.name));
            }
            if !t.python.starts_with('/') {
                return Err(format!(
                    "template {}: python must be an absolute path",
                    t.name
                ));
            }
            if let Some(tenant) = &t.tenant {
                if !valid_name(tenant) {
                    return Err(format!(
                        "template {}: tenant {tenant:?} is not a valid name",
                        t.name
                    ));
                }
            } else if t.sandbox.is_some_and(|m| m != SandboxMode::Require) {
                return Err(format!(
                    "template {}: a shared template (no tenant) must run with --sandbox require",
                    t.name
                ));
            }
            if t.max_processes < 8 || t.max_processes > MAX_PROCESSES {
                return Err(format!(
                    "template {}: max_processes must be 8 to {}",
                    t.name, MAX_PROCESSES
                ));
            }
            if t.memory_limit_mb == 0 || t.fs_limit_mb == 0 {
                return Err(format!("template {}: limits must be positive", t.name));
            }
            for (k, v) in &t.env {
                if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
                    return Err(format!(
                        "template {}: malformed environment variable {k:?}",
                        t.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// The token, from `token` or `token_file`.
    pub fn token(&self) -> Result<String, String> {
        let token = match (&self.token, &self.token_file) {
            (Some(t), None) => t.clone(),
            (None, Some(path)) => std::fs::read_to_string(path)
                .map_err(|e| format!("token_file {}: {e}", path.display()))?
                .trim()
                .to_string(),
            _ => return Err("give exactly one of token and token_file".into()),
        };
        if token.len() < hellovm_control::ids::MIN_TOKEN_LEN
            || !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(format!(
                "the token must be at least {} printable characters",
                hellovm_control::ids::MIN_TOKEN_LEN
            ));
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{"node":"n1","listen":"127.0.0.1:0","token":"0123456789abcdef0123456789",
        "hellovm":"/bin/hellovm","state_dir":"/tmp/x","templates":[TEMPLATES]}"#;

    fn with(templates: &str) -> Result<Config, String> {
        Config::parse(&BASE.replace("TEMPLATES", templates))
    }

    #[test]
    fn configs_are_checked() {
        let ok = with(r#"{"name":"python","root":"/","preload":["json","xml.etree.ElementTree"]}"#)
            .unwrap();
        assert_eq!(ok.templates[0].sandbox_mode(), SandboxMode::Require);
        assert_eq!(ok.token().unwrap().len(), 26);
        for bad in [
            r#"{"name":"../x","root":"/"}"#,
            r#"{"name":"p","root":"/","preload":["os; import x"]}"#,
            r#"{"name":"p","root":"/","sandbox":"best-effort"}"#,
            r#"{"name":"p","root":"/","python":"python3"}"#,
            r#"{"name":"p","root":"/","bogus":1}"#,
            r#"{"name":"p","root":"/"},{"name":"p","root":"/"}"#,
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }
        let one =
            with(r#"{"name":"p","root":"/","tenant":"acme","sandbox":"best-effort"}"#).unwrap();
        assert_eq!(one.templates[0].sandbox_mode(), SandboxMode::BestEffort);
    }
}
