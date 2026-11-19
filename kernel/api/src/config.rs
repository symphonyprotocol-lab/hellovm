//! `hellovm-api`'s configuration file (JSON).
//!
//! ```json
//! {
//!   "listen": "127.0.0.1:7070",
//!   "tenants": [{"name": "acme", "token_file": "/etc/hellovm/acme.token", "max_sandboxes": 10}],
//!   "nodes": [{"name": "node-1", "addr": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token"}],
//!   "default_idle_timeout": 600, "max_idle_timeout": 86400,
//!   "default_lifetime": 3600, "max_lifetime": 86400,
//!   "admin": {"listen": "127.0.0.1:7079", "token_file": "/etc/hellovm/admin.token"},
//!   "ingress": {"listen": "0.0.0.0:7080", "domain": "sandbox.example.com"}
//! }
//! ```

use std::path::PathBuf;

use hellovm_control::ids::MIN_TOKEN_LEN;
use serde::{Deserialize, Deserializer};

use crate::meter::Periods;

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
    /// Seconds a probe of a node (its status) may take.
    #[serde(default = "default_node_timeout")]
    pub node_timeout: f64,
    /// Failures in a row (probes, or requests that got no answer) that
    /// make a node unreachable.
    #[serde(default = "default_unhealthy_after")]
    pub unhealthy_after: u32,
    /// Good probes in a row that make an unreachable node healthy again.
    #[serde(default = "default_healthy_after")]
    pub healthy_after: u32,
    /// The operators' API, on a listener of its own; none: not served.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// The metering period and log.
    #[serde(default)]
    pub metering: MeteringConfig,
    /// HTTP ingress to sandboxes, on a listener of its own; none: not
    /// served.
    #[serde(default)]
    pub ingress: Option<IngressConfig>,
}

/// HTTP ingress (see `crate::ingress`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    /// `HOST:PORT` the ingress listener binds (behind the TLS proxy).
    pub listen: String,
    /// Requests for `PORT-SANDBOX.DOMAIN` reach that sandbox's port.
    pub domain: String,
    /// The scheme clients use (`https` behind a TLS proxy): in the URLs
    /// the API reports, `X-Forwarded-Proto`, and the cookie's `Secure`.
    #[serde(default = "default_scheme")]
    pub scheme: String,
    /// The port in the URLs the API reports, when not the scheme's own.
    #[serde(default)]
    pub url_port: Option<u16>,
    /// The listener is reached only through a reverse proxy that sets
    /// `X-Forwarded-For` and `X-Forwarded-Proto`: those are taken from it
    /// (and the peer appended) instead of replaced.
    #[serde(default)]
    pub behind_proxy: bool,
    #[serde(default = "default_ingress_max")]
    pub max_connections: usize,
    #[serde(default = "default_ingress_per_tenant")]
    pub max_connections_per_tenant: usize,
    #[serde(default = "default_ingress_per_sandbox")]
    pub max_connections_per_sandbox: usize,
    #[serde(default = "default_ingress_per_client")]
    pub max_connections_per_client: usize,
    /// Seconds a request head may take to arrive.
    #[serde(default = "default_head_timeout")]
    pub head_timeout: f64,
    /// Seconds without a byte in either direction that end a connection.
    #[serde(default = "default_ingress_idle")]
    pub idle_timeout: f64,
    /// Seconds a connection may last at most (a WebSocket, a long
    /// download).
    #[serde(default = "default_max_duration")]
    pub max_duration: f64,
}

fn default_scheme() -> String {
    "https".into()
}
fn default_ingress_max() -> usize {
    512
}
fn default_ingress_per_tenant() -> usize {
    128
}
fn default_ingress_per_sandbox() -> usize {
    32
}
fn default_ingress_per_client() -> usize {
    64
}
fn default_head_timeout() -> f64 {
    10.0
}
fn default_ingress_idle() -> f64 {
    60.0
}
fn default_max_duration() -> f64 {
    3600.0
}

/// Whether `domain` is a DNS name of at least two labels of lowercase
/// letters, digits and `-` (not at either end), at most 200 bytes.
pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 200
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl IngressConfig {
    fn check(&self) -> Result<(), String> {
        if !valid_domain(&self.domain) {
            return Err("ingress.domain must be a lowercase DNS name of two labels or more".into());
        }
        if self.scheme != "https" && self.scheme != "http" {
            return Err("ingress.scheme must be https or http".into());
        }
        if self.url_port == Some(0) {
            return Err("ingress.url_port must be 1 to 65535".into());
        }
        if !(1..=4096).contains(&self.max_connections) {
            return Err("ingress.max_connections must be 1 to 4096".into());
        }
        for (what, value) in [
            (
                "max_connections_per_tenant",
                self.max_connections_per_tenant,
            ),
            (
                "max_connections_per_sandbox",
                self.max_connections_per_sandbox,
            ),
            (
                "max_connections_per_client",
                self.max_connections_per_client,
            ),
        ] {
            if !(1..=self.max_connections).contains(&value) {
                return Err(format!("ingress.{what} must be 1 to max_connections"));
            }
        }
        for (what, value, max) in [
            ("head_timeout", self.head_timeout, 60.0),
            ("idle_timeout", self.idle_timeout, 3600.0),
            ("max_duration", self.max_duration, 7.0 * 86400.0),
        ] {
            if !(value.is_finite() && value > 0.0 && value <= max) {
                return Err(format!(
                    "ingress.{what} must be more than 0 and at most {max}"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeteringConfig {
    /// Seconds per period, aligned to multiples of it since the Unix
    /// epoch (86400: UTC days), or `"month"`: calendar months in UTC. The
    /// per-period budgets start again at every boundary.
    #[serde(default = "default_period", deserialize_with = "periods")]
    pub period: Periods,
    /// The usage log's path prefix: records of a period go to
    /// `LOG.YYYYMMDDTHHMMSSZ.jsonl` (the period's start), then `.1.jsonl`,
    /// `.2.jsonl`... past `max_file_mb`. None: no log.
    #[serde(default)]
    pub log: Option<PathBuf>,
    /// Seconds between two records of a running sandbox.
    #[serde(default = "default_record_interval")]
    pub interval: f64,
    /// Size at which a log file is closed and the next one begun.
    #[serde(default = "default_max_file_mb")]
    pub max_file_mb: u64,
    /// Most bytes read from the log at start-up.
    #[serde(default = "default_max_read_mb")]
    pub max_read_mb: u64,
}

impl Default for MeteringConfig {
    fn default() -> MeteringConfig {
        MeteringConfig {
            period: default_period(),
            log: None,
            interval: default_record_interval(),
            max_file_mb: default_max_file_mb(),
            max_read_mb: default_max_read_mb(),
        }
    }
}

fn default_period() -> Periods {
    Periods::Seconds(86400)
}

/// `metering.period`: a number of seconds or `"month"`.
fn periods<'de, D: Deserializer<'de>>(d: D) -> Result<Periods, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Text {
        Seconds(u64),
        Name(String),
    }
    match Text::deserialize(d)? {
        Text::Seconds(s) => Ok(Periods::Seconds(s)),
        Text::Name(n) if n == "month" => Ok(Periods::Months),
        Text::Name(_) => Err(serde::de::Error::custom(
            "metering.period must be a number of seconds or \"month\"",
        )),
    }
}
fn default_record_interval() -> f64 {
    60.0
}
fn default_max_file_mb() -> u64 {
    256
}
fn default_max_read_mb() -> u64 {
    1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// `HOST:PORT`; keep it on loopback or a private network.
    pub listen: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

fn default_node_timeout() -> f64 {
    5.0
}
fn default_unhealthy_after() -> u32 {
    3
}
fn default_healthy_after() -> u32 {
    2
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
    /// The memory limits of its sandboxes together, in MiB.
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    /// Requests per second, on average (a token bucket per tenant).
    #[serde(default)]
    pub requests_per_second: Option<f64>,
    /// Requests at once above the average (the bucket's size; default:
    /// two seconds' worth, at least 10).
    #[serde(default)]
    pub request_burst: Option<u32>,
    /// CPU seconds its sandboxes may use per period.
    #[serde(default)]
    pub cpu_seconds_per_period: Option<f64>,
    /// Egress bytes (sent and received) its sandboxes may move per period.
    #[serde(default)]
    pub egress_bytes_per_period: Option<u64>,
    /// Ingress connections to its sandboxes at once (default and at most
    /// `ingress.max_connections_per_tenant`).
    #[serde(default)]
    pub max_ingress_connections: Option<usize>,
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

pub(crate) fn valid_name(name: &str) -> bool {
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
    pub max_memory_bytes: Option<u64>,
    /// `(per second, burst)`.
    pub rate: Option<(f64, u32)>,
    pub cpu_ms_per_period: Option<u64>,
    pub egress_bytes_per_period: Option<u64>,
    /// Ingress connections to its sandboxes at once.
    pub max_ingress_connections: Option<usize>,
}

impl Tenant {
    /// As the tenant is told of them.
    pub fn quotas(&self) -> hellovm_control::types::Quotas {
        hellovm_control::types::Quotas {
            max_sandboxes: self.max_sandboxes,
            max_memory_bytes: self.max_memory_bytes,
            requests_per_second: self.rate.map(|(r, _)| r),
            request_burst: self.rate.map(|(_, b)| b),
            cpu_seconds_per_period: self.cpu_ms_per_period.map(|ms| ms as f64 / 1000.0),
            egress_bytes_per_period: self.egress_bytes_per_period,
            max_ingress_connections: self.max_ingress_connections,
        }
    }
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
            ("node_timeout", config.node_timeout, 60.0),
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
        for (what, value) in [
            ("unhealthy_after", config.unhealthy_after),
            ("healthy_after", config.healthy_after),
        ] {
            if !(1..=100).contains(&value) {
                return Err(format!("{what} must be 1 to 100"));
            }
        }
        if config.nodes.is_empty() {
            return Err("no nodes".into());
        }
        let m = &config.metering;
        if let Periods::Seconds(p) = m.period {
            if !(1..=366 * 86400).contains(&p) {
                return Err("metering.period must be 1 to 31622400 seconds, or \"month\"".into());
            }
        }
        if let Some(ingress) = &config.ingress {
            ingress.check()?;
        }
        if !(m.interval.is_finite() && m.interval >= 1.0 && m.interval <= 86400.0) {
            return Err("metering.interval must be 1 to 86400 seconds".into());
        }
        if !(1..=1 << 20).contains(&m.max_file_mb) || !(1..=1 << 20).contains(&m.max_read_mb) {
            return Err("metering.max_file_mb and max_read_mb must be 1 to 2^20".into());
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
            let what = |field: &str| format!("tenant {}: {field}", t.name);
            if t.max_memory_mb.is_some_and(|mb| mb == 0 || mb > 1 << 30) {
                return Err(what("max_memory_mb must be 1 to 2^30"));
            }
            let rate = match (t.requests_per_second, t.request_burst) {
                (None, None) => None,
                (None, Some(_)) => return Err(what("request_burst needs requests_per_second")),
                (Some(r), burst) => {
                    if !(r.is_finite() && r > 0.0 && r <= 1e6) {
                        return Err(what("requests_per_second must be more than 0, at most 1e6"));
                    }
                    let burst = burst.unwrap_or_else(|| ((2.0 * r).ceil() as u32).max(10));
                    if !(1..=1_000_000).contains(&burst) {
                        return Err(what("request_burst must be 1 to 1e6"));
                    }
                    Some((r, burst))
                }
            };
            let cpu_ms_per_period = match t.cpu_seconds_per_period {
                None => None,
                Some(s) if (0.0..=1e12).contains(&s) => Some((s * 1000.0) as u64),
                Some(_) => return Err(what("cpu_seconds_per_period must be 0 to 1e12")),
            };
            let max_ingress_connections = match (&self.ingress, t.max_ingress_connections) {
                (None, _) => None,
                (Some(i), None) => Some(i.max_connections_per_tenant),
                (Some(i), Some(n)) if (1..=i.max_connections_per_tenant).contains(&n) => Some(n),
                (Some(_), Some(_)) => {
                    return Err(what(
                        "max_ingress_connections must be 1 to ingress.max_connections_per_tenant",
                    ))
                }
            };
            out.push(Tenant {
                max_ingress_connections,
                name: t.name.clone(),
                token,
                max_sandboxes: t.max_sandboxes,
                max_memory_bytes: t.max_memory_mb.map(|mb| mb << 20),
                rate,
                cpu_ms_per_period,
                egress_bytes_per_period: t.egress_bytes_per_period,
            });
        }
        Ok(out)
    }

    /// The admin token, if the admin API is configured. It may not be a
    /// tenant's or a node's token.
    pub fn admin_token(
        &self,
        tenants: &[Tenant],
        nodes: &[Node],
    ) -> Result<Option<String>, String> {
        let Some(admin) = &self.admin else {
            return Ok(None);
        };
        let token = load_token(&admin.token, &admin.token_file, "admin")?;
        if tenants.iter().any(|t| t.token == token) || nodes.iter().any(|n| n.token == token) {
            return Err("admin: the token is also a tenant's or a node's".into());
        }
        Ok(Some(token))
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

        let with = |extra: &str| {
            Config::parse(&base.replace("\"listen\"", &format!("{extra},\"listen\"")))
        };
        let ok = ok.tenants().unwrap();
        let admin =
            with(r#""admin":{"listen":"127.0.0.1:0","token":"dddddddddddddddddddddddd"}"#).unwrap();
        let nodes = admin.nodes().unwrap();
        assert!(admin.admin_token(&ok, &nodes).unwrap().is_some());
        let tenant_token =
            with(r#""admin":{"listen":"127.0.0.1:0","token":"aaaaaaaaaaaaaaaaaaaaaaaa"}"#).unwrap();
        assert!(tenant_token.admin_token(&ok, &nodes).is_err());
        let node_token =
            with(r#""admin":{"listen":"127.0.0.1:0","token":"nnnnnnnnnnnnnnnnnnnnnnnn"}"#).unwrap();
        assert!(node_token.admin_token(&ok, &nodes).is_err());
        assert!(with(r#""admin":{"listen":"127.0.0.1:0"}"#)
            .unwrap()
            .admin_token(&ok, &nodes)
            .is_err());
        assert!(with(r#""unhealthy_after":0"#).is_err());
        assert!(with(r#""healthy_after":101"#).is_err());
        assert!(with(r#""node_timeout":0"#).is_err());
        assert_eq!(with(r#""unhealthy_after":5"#).unwrap().unhealthy_after, 5);
        assert!(with(r#""metering":{"period":0}"#).is_err());
        assert!(with(r#""metering":{"interval":0.5}"#).is_err());
        assert!(with(r#""metering":{"bogus":1}"#).is_err());
        let m = with(r#""metering":{"period":3600,"log":"/tmp/u"}"#).unwrap();
        assert_eq!(m.metering.period, Periods::Seconds(3600));
        let m = with(r#""metering":{"period":"month"}"#).unwrap();
        assert_eq!(m.metering.period, Periods::Months);
        assert!(with(r#""metering":{"period":"week"}"#).is_err());
        assert!(with(r#""metering":{"period":-1}"#).is_err());
        let i = with(r#""ingress":{"listen":"127.0.0.1:0","domain":"sb.example.com"}"#).unwrap();
        let i = i.ingress.unwrap();
        assert_eq!(
            (i.scheme.as_str(), i.max_connections_per_sandbox),
            ("https", 32)
        );
        for bad in [
            r#""ingress":{"listen":"x","domain":"Example.com"}"#,
            r#""ingress":{"listen":"x","domain":"com"}"#,
            r#""ingress":{"listen":"x","domain":"a..b"}"#,
            r#""ingress":{"listen":"x","domain":"-a.b"}"#,
            r#""ingress":{"listen":"x","domain":"a.b","scheme":"ftp"}"#,
            r#""ingress":{"listen":"x","domain":"a.b","max_connections":0}"#,
            r#""ingress":{"listen":"x","domain":"a.b","max_connections":10,"max_connections_per_sandbox":11}"#,
            r#""ingress":{"listen":"x","domain":"a.b","idle_timeout":0}"#,
            r#""ingress":{"listen":"x","domain":"a.b","bogus":1}"#,
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }

        let base_ok = base.replace("TOKEN_B", "bbbbbbbbbbbbbbbbbbbbbbbb");
        let quota = |extra: &str| {
            let text = base_ok.replacen(
                "\"max_sandboxes\":2}",
                &format!("\"max_sandboxes\":2,{extra}}}"),
                1,
            );
            Config::parse(&text).unwrap().tenants()
        };
        let t = quota(r#""max_memory_mb":1024,"requests_per_second":2.5,"cpu_seconds_per_period":1.5,"egress_bytes_per_period":99"#).unwrap();
        assert_eq!(t[0].max_memory_bytes, Some(1 << 30));
        assert_eq!(t[0].rate, Some((2.5, 10)));
        assert_eq!(t[0].cpu_ms_per_period, Some(1500));
        assert_eq!(t[0].egress_bytes_per_period, Some(99));
        assert_eq!(t[1].rate, None);
        assert_eq!(
            quota(r#""requests_per_second":100"#).unwrap()[0].rate,
            Some((100.0, 200))
        );
        for bad in [
            r#""requests_per_second":0"#,
            r#""request_burst":5"#,
            r#""requests_per_second":1,"request_burst":0"#,
            r#""max_memory_mb":0"#,
            r#""cpu_seconds_per_period":-1"#,
        ] {
            assert!(quota(bad).is_err(), "{bad}");
        }
    }
}
