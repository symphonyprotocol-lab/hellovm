//! `hellovm-api`'s configuration file (JSON).
//!
//! ```json
//! {
//!   "listen": "127.0.0.1:7070",
//!   "tenants": [{"name": "acme", "token_file": "/etc/hellovm/acme.token", "max_sandboxes": 10}],
//!   "nodes": [{"name": "node-1", "addr": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token"}],
//!   "default_idle_timeout": 600, "max_idle_timeout": 86400,
//!   "default_lifetime": 3600, "max_lifetime": 86400
//! }
//! ```

use std::path::PathBuf;

use hellovm_control::ids::MIN_TOKEN_LEN;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub tenants: Vec<TenantConfig>,
    pub nodes: Vec<NodeConfig>,
    #[serde(default = "default_idle")]
    pub default_idle_timeout: f64,
    #[serde(default = "default_max")]
    pub max_idle_timeout: f64,
    #[serde(default = "default_lifetime")]
    pub default_lifetime: f64,
    #[serde(default = "default_max")]
    pub max_lifetime: f64,
    /// Seconds between two reconciliations with the nodes.
    #[serde(default = "default_reconcile")]
    pub reconcile_interval: f64,
    /// Connections served at once from one IP address (of 256 in all), so
    /// that one client, with a token or without, cannot take every
    /// connection. Behind a reverse proxy every client has the proxy's
    /// address: raise it there and limit per client in the proxy.
    #[serde(default = "default_per_client")]
    pub max_connections_per_client: usize,
}

fn default_per_client() -> usize {
    // Following an exec's output takes a connection per sandbox for up to
    // 30 s at a time: room for a client with many sandboxes, and still
    // half of all connections left for the others.
    128
}

fn default_idle() -> f64 {
    600.0
}
fn default_lifetime() -> f64 {
    3600.0
}
fn default_max() -> f64 {
    86400.0
}
fn default_reconcile() -> f64 {
    2.0
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub name: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Sandboxes this tenant may have at once.
    pub max_sandboxes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub name: String,
    /// `HOST:PORT` of its node API.
    pub addr: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

fn load_token(
    token: &Option<String>,
    file: &Option<PathBuf>,
    what: &str,
) -> Result<String, String> {
    let token = match (token, file) {
        (Some(t), None) => t.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| format!("{what}: token_file {}: {e}", path.display()))?
            .trim()
            .to_string(),
        _ => return Err(format!("{what}: give exactly one of token and token_file")),
    };
    if token.len() < MIN_TOKEN_LEN || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "{what}: the token must be at least {MIN_TOKEN_LEN} printable characters"
        ));
    }
    Ok(token)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A tenant with its token loaded.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub name: String,
    pub token: String,
    pub max_sandboxes: usize,
}

/// A node with its token loaded.
#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub addr: String,
    pub token: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let config: Config = serde_json::from_str(text).map_err(|e| e.to_string())?;
        for (what, value, max) in [
            (
                "default_idle_timeout",
                config.default_idle_timeout,
                config.max_idle_timeout,
            ),
            (
                "default_lifetime",
                config.default_lifetime,
                config.max_lifetime,
            ),
            ("reconcile_interval", config.reconcile_interval, 3600.0),
        ] {
            if !(value.is_finite() && value > 0.0 && value <= max) {
                return Err(format!("{what} must be more than 0 and at most {max}"));
            }
        }
        if !(1..=256).contains(&config.max_connections_per_client) {
            return Err("max_connections_per_client must be 1 to 256".into());
        }
        for (what, value) in [
            ("max_idle_timeout", config.max_idle_timeout),
            ("max_lifetime", config.max_lifetime),
        ] {
            if !(value.is_finite() && value > 0.0 && value <= 7.0 * 86400.0) {
                return Err(format!("{what} must be more than 0 and at most a week"));
            }
        }
        if config.nodes.is_empty() {
            return Err("no nodes".into());
        }
        Ok(config)
    }

    pub fn tenants(&self) -> Result<Vec<Tenant>, String> {
        let mut out: Vec<Tenant> = Vec::new();
        for t in &self.tenants {
            if !valid_name(&t.name) {
                return Err(format!(
                    "tenant name {:?}: use 1-64 letters, digits, - and _",
                    t.name
                ));
            }
            if out.iter().any(|o| o.name == t.name) {
                return Err(format!("tenant {} is defined twice", t.name));
            }
            let token = load_token(&t.token, &t.token_file, &format!("tenant {}", t.name))?;
            if out.iter().any(|o| o.token == token) {
                return Err(format!("tenant {} has another tenant's token", t.name));
            }
            out.push(Tenant {
                name: t.name.clone(),
                token,
                max_sandboxes: t.max_sandboxes,
            });
        }
        Ok(out)
    }

    pub fn nodes(&self) -> Result<Vec<Node>, String> {
        let mut out: Vec<Node> = Vec::new();
        for n in &self.nodes {
            if !valid_name(&n.name) || out.iter().any(|o| o.name == n.name) {
                return Err(format!("node name {:?} is malformed or used twice", n.name));
            }
            out.push(Node {
                name: n.name.clone(),
                addr: n.addr.clone(),
                token: load_token(&n.token, &n.token_file, &format!("node {}", n.name))?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_are_checked() {
        let base = r#"{"listen":"127.0.0.1:0",
            "tenants":[{"name":"a","token":"aaaaaaaaaaaaaaaaaaaaaaaa","max_sandboxes":2},
                       {"name":"b","token":"TOKEN_B","max_sandboxes":2}],
            "nodes":[{"name":"n","addr":"127.0.0.1:1","token":"nnnnnnnnnnnnnnnnnnnnnnnn"}]}"#;
        let ok = Config::parse(&base.replace("TOKEN_B", "bbbbbbbbbbbbbbbbbbbbbbbb")).unwrap();
        assert_eq!(ok.tenants().unwrap().len(), 2);
        assert_eq!(ok.nodes().unwrap()[0].name, "n");
        let same = Config::parse(&base.replace("TOKEN_B", "aaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        assert!(same.tenants().is_err());
        let short = Config::parse(&base.replace("TOKEN_B", "short")).unwrap();
        assert!(short.tenants().is_err());
        assert!(Config::parse(&base.replace("\"listen\"", "\"bogus\":1,\"listen\"")).is_err());
    }
}
