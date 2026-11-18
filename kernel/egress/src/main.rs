//! `hellovm-egress`: the egress proxy. See the crate documentation and the
//! README for the policy and audit formats.
//!
//! ```text
//! hellovm-egress --listen PATH [--policy FILE]... [--allow RULE]...
//!                [--audit FILE] [--max-flows N] [--max-flows-per-sandbox N]
//!                [--idle-timeout SECONDS] [--connect-timeout SECONDS]
//!                [--stats PATH --stats-token-file FILE]
//! ```

use std::fs::OpenOptions;
use std::process::ExitCode;
use std::time::Duration;

use hellovm_egress::audit::AuditSink;
use hellovm_egress::policy::{Policy, Rule};
use hellovm_egress::resolve::Resolver;
use hellovm_egress::{Config, Limits, Proxy};

const USAGE: &str = "usage: hellovm-egress --listen PATH [--policy FILE]... [--allow RULE]... \
[--audit FILE] [--max-flows N] [--max-flows-per-sandbox N] [--idle-timeout SECONDS] \
[--connect-timeout SECONDS] [--stats PATH --stats-token-file FILE]\n\
RULE is NAME or *.SUFFIX, optionally :PORT[,PORT...] (default ports 80 and 443).\n\
A policy file holds one `allow RULE` per line. Everything else is denied.\n\
--stats serves the bytes relayed per kernel process to noded (keep PATH in a directory \
of its own, apart from the flow socket's).";

struct Options {
    listen: std::path::PathBuf,
    config: Config,
    /// The stats socket and its token.
    stats: Option<(std::path::PathBuf, String)>,
}

fn seconds(flag: &str, value: Option<String>) -> Result<Duration, String> {
    let value = value.ok_or_else(|| format!("{flag} needs a number of seconds"))?;
    value
        .parse::<f64>()
        .ok()
        .filter(|s| *s > 0.0)
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
        .ok_or_else(|| format!("{flag} {value}: expected a positive number of seconds"))
}

fn count(flag: &str, value: Option<String>) -> Result<usize, String> {
    let value = value.ok_or_else(|| format!("{flag} needs a number"))?;
    value
        .parse::<usize>()
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("{flag} {value}: expected a positive number"))
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut listen = None;
    let mut policy = Policy::new();
    let mut limits = Limits::default();
    let mut audit = None;
    let mut stats = None;
    let mut stats_token = None;
    let resolver = Resolver::System;
    #[cfg(feature = "insecure-test-hooks")]
    let mut resolver = resolver;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = Some(args.next().ok_or("--listen needs a path")?.into()),
            "--policy" => {
                let path = args.next().ok_or("--policy needs a file")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|err| format!("--policy {path}: {err}"))?;
                policy
                    .add_file(&text)
                    .map_err(|err| format!("--policy {path}: {err}"))?;
            }
            "--allow" => {
                let rule = args.next().ok_or("--allow needs a rule")?;
                policy.push(Rule::parse(&rule).map_err(|err| format!("--allow {err}"))?);
            }
            "--stats" => stats = Some(args.next().ok_or("--stats needs a path")?.into()),
            "--stats-token-file" => {
                let path = args.next().ok_or("--stats-token-file needs a file")?;
                let token = std::fs::read_to_string(&path)
                    .map_err(|err| format!("--stats-token-file {path}: {err}"))?
                    .trim()
                    .to_string();
                if token.len() < 22 || !token.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(format!(
                        "--stats-token-file {path}: the token must be at least 22 printable characters"
                    ));
                }
                stats_token = Some(token);
            }
            "--audit" => audit = Some(args.next().ok_or("--audit needs a file")?),
            "--max-flows" => limits.max_flows = count(&arg, args.next())?,
            "--max-flows-per-sandbox" => limits.max_flows_per_sandbox = count(&arg, args.next())?,
            "--idle-timeout" => limits.idle_timeout = seconds(&arg, args.next())?,
            "--connect-timeout" => limits.connect_timeout = seconds(&arg, args.next())?,
            #[cfg(feature = "insecure-test-hooks")]
            "--insecure-test-hosts" => {
                let path = args.next().ok_or("--insecure-test-hosts needs a file")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|err| format!("--insecure-test-hosts {path}: {err}"))?;
                resolver = Resolver::parse_test_table(&text)
                    .map_err(|err| format!("--insecure-test-hosts {path}: {err}"))?;
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
    }
    let listen = listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?;
    let stats = match (stats, stats_token) {
        (Some(path), Some(token)) => Some((path, token)),
        (None, None) => None,
        _ => return Err("--stats and --stats-token-file go together".into()),
    };
    let audit = match audit {
        None => AuditSink::stdout(),
        Some(path) => AuditSink::new(Box::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|err| format!("--audit {path}: {err}"))?,
        )),
    };
    Ok(Options {
        listen,
        config: Config {
            policy,
            limits,
            audit,
            resolver,
        },
        stats,
    })
}

fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if let Err(err) = hellovm_egress::seal_process() {
        eprintln!("hellovm-egress: cannot make the process non-dumpable: {err}");
        return ExitCode::from(1);
    }
    if options.config.policy.is_empty() {
        eprintln!("hellovm-egress: warning: the allowlist is empty; every flow is denied");
    }
    let proxy = match Proxy::bind(&options.listen, options.config) {
        Ok(proxy) => proxy,
        Err(err) => {
            eprintln!("hellovm-egress: {}: {err}", options.listen.display());
            return ExitCode::from(1);
        }
    };
    if let Some((path, token)) = options.stats {
        if let Err(err) = proxy.serve_stats(&path, token) {
            eprintln!("hellovm-egress: --stats {}: {err}", path.display());
            return ExitCode::from(1);
        }
        eprintln!("hellovm-egress: stats on {}", path.display());
    }
    eprintln!("hellovm-egress: listening on {}", proxy.path().display());
    match proxy.serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("hellovm-egress: {err}");
            ExitCode::from(1)
        }
    }
}
