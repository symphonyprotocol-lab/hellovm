//! The domain allowlist. Default deny: a flow passes only if some rule
//! names its hostname and port.
//!
//! A rule is `PATTERN[:PORT[,PORT...]]`:
//!
//! * `pypi.org` matches exactly that name;
//! * `*.githubusercontent.com` matches any name *under* that suffix (one or
//!   more extra labels), not the suffix itself. The suffix needs at least
//!   two labels, so `*.com` and `*` are rejected;
//! * without ports, a rule allows 443 only. Plain HTTP (port 80) must be
//!   asked for (`pypi.org:80,443`): it is not encrypted, and the proxy
//!   carries one request per connection on it (see [`crate::sniff`]).
//!
//! A policy file holds one `allow RULE` per line; blank lines and lines
//! starting with `#` are ignored. Names are case-insensitive.

use crate::wire::{normalize_hostname, valid_hostname};

/// Ports a rule allows when it names none.
pub const DEFAULT_PORTS: [u16; 1] = [443];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    /// Matches names ending in `.suffix`.
    Under(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pattern: Pattern,
    ports: Vec<u16>,
}

impl Rule {
    /// Parses `PATTERN[:PORT[,PORT...]]`.
    pub fn parse(text: &str) -> Result<Rule, String> {
        let text = text.trim();
        let (name, ports) = match text.split_once(':') {
            Some((name, ports)) => (name, Some(ports)),
            None => (text, None),
        };
        let pattern = if let Some(suffix) = name.strip_prefix("*.") {
            let suffix = normalize_hostname(suffix)
                .ok_or_else(|| format!("{text}: `*.` must be followed by a hostname"))?;
            Pattern::Under(suffix)
        } else {
            Pattern::Exact(normalize_hostname(name).ok_or_else(|| {
                format!(
                    "{text}: not a hostname (need at least two labels of letters, digits and -)"
                )
            })?)
        };
        let ports = match ports {
            None => DEFAULT_PORTS.to_vec(),
            Some(list) => {
                let mut ports = Vec::new();
                for p in list.split(',') {
                    let port: u16 = p
                        .trim()
                        .parse()
                        .ok()
                        .filter(|&p| p != 0)
                        .ok_or_else(|| format!("{text}: bad port {p:?}"))?;
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
                ports
            }
        };
        Ok(Rule { pattern, ports })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if !self.ports.contains(&port) {
            return false;
        }
        match &self.pattern {
            Pattern::Exact(name) => host == name,
            Pattern::Under(suffix) => host
                .strip_suffix(suffix.as_str())
                .is_some_and(|head| head.len() > 1 && head.ends_with('.')),
        }
    }
}

/// The allowlist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    pub fn new() -> Policy {
        Policy::default()
    }

    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Adds the rules of a policy file.
    pub fn add_file(&mut self, text: &str) -> Result<(), String> {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rule = line
                .strip_prefix("allow")
                .filter(|rest| rest.starts_with([' ', '\t']))
                .ok_or_else(|| format!("line {}: expected `allow RULE`", n + 1))?;
            self.push(Rule::parse(rule).map_err(|err| format!("line {}: {err}", n + 1))?);
        }
        Ok(())
    }

    /// Whether `host` (a valid, normalized hostname) may be reached on `port`.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        valid_hostname(host.as_bytes()) && self.rules.iter().any(|r| r.matches(host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> Policy {
        let mut p = Policy::new();
        p.add_file(text).unwrap();
        p
    }

    #[test]
    fn default_deny() {
        let p = Policy::new();
        assert!(!p.allows("pypi.org", 443));
    }

    #[test]
    fn exact_names_and_default_ports() {
        let p = policy("# comment\n\nallow PyPI.org\n");
        assert!(p.allows("pypi.org", 443));
        // Plain HTTP is not a default: it must be asked for.
        assert!(!p.allows("pypi.org", 80));
        assert!(policy("allow pypi.org:80,443\n").allows("pypi.org", 80));
        assert!(!p.allows("pypi.org", 22));
        assert!(!p.allows("files.pypi.org", 443));
        assert!(!p.allows("evilpypi.org", 443));
        assert!(!p.allows("pypi.org.evil.com", 443));
    }

    #[test]
    fn wildcards_match_only_below_the_suffix() {
        let p = policy("allow *.github.com:443\n");
        assert!(p.allows("api.github.com", 443));
        assert!(p.allows("a.b.github.com", 443));
        assert!(!p.allows("github.com", 443));
        assert!(!p.allows("evilgithub.com", 443));
        assert!(!p.allows("api.github.com", 80));
    }

    #[test]
    fn explicit_ports() {
        let p = policy("allow example.com:8443, 80\n");
        assert!(p.allows("example.com", 8443));
        assert!(p.allows("example.com", 80));
        assert!(!p.allows("example.com", 443));
    }

    #[test]
    fn bad_rules_are_errors() {
        for bad in [
            "*",
            "*.com",
            "localhost",
            "a.b:0",
            "a.b:x",
            "a.b:70000",
            "1.2.3.4",
            "a_b.com",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
        let mut p = Policy::new();
        assert!(p.add_file("deny a.b\n").is_err());
        assert!(p.add_file("allowa.b\n").is_err());
    }
}
