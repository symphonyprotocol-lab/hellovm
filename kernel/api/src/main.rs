//! `hellovm-api --config FILE`: the public API (see the crate
//! documentation and the README, "Control plane").

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hellovm_api::config::Config;
use hellovm_api::nodes::{HealthPolicy, Nodes};
use hellovm_api::service::{Admin, Api};
use hellovm_api::store::MemoryStore;

const USAGE: &str = "usage: hellovm-api --config FILE";

fn main() -> ExitCode {
    hellovm_control::init_logging("api");
    let mut args = std::env::args().skip(1);
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--config"), Some(path), None) => path,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let config = Config::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let tenants = config.tenants()?;
    let nodes = config.nodes()?;
    let admin_token = config.admin_token(&tenants, &nodes)?;
    let limits = hellovm_control::http::Limits {
        max_connections_per_peer: config.max_connections_per_client,
        ..Default::default()
    };
    // Operators are few: a handful of connections is plenty.
    let admin_limits = hellovm_control::http::Limits {
        max_connections: 16,
        max_connections_per_peer: 16,
        ..Default::default()
    };
    // Each connection served may hold one more, to a node (an ingress
    // connection too); and every node is probed at once.
    let ingress_connections = config.ingress.as_ref().map_or(0, |i| i.max_connections);
    hellovm_control::ensure_fd_limit(
        (limits.max_connections + admin_limits.max_connections + ingress_connections) as u64 * 2
            + nodes.len() as u64 * 2
            + 64,
    )?;
    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| format!("listen {}: {e}", config.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let admin_listener = match &config.admin {
        Some(admin) => Some(
            std::net::TcpListener::bind(&admin.listen)
                .map_err(|e| format!("admin listen {}: {e}", admin.listen))?,
        ),
        None => None,
    };
    let ingress_listener = match &config.ingress {
        Some(ingress) => Some(
            std::net::TcpListener::bind(&ingress.listen)
                .map_err(|e| format!("ingress listen {}: {e}", ingress.listen))?,
        ),
        None => None,
    };
    // What is never forwarded to a guest: every token of hellovm's own.
    let secrets: Vec<String> = tenants
        .iter()
        .map(|t| t.token.clone())
        .chain(nodes.iter().map(|n| n.token.clone()))
        .chain(admin_token.clone())
        .collect();
    let ingress = config
        .ingress
        .clone()
        .map(|c| hellovm_api::ingress::IngressState::new(c, secrets));
    let interval = Duration::from_secs_f64(config.reconcile_interval);
    let policy = HealthPolicy {
        unhealthy_after: config.unhealthy_after,
        healthy_after: config.healthy_after,
    };
    let record_every = Duration::from_secs_f64(config.metering.interval);
    let mut api = Api::new(
        config,
        tenants,
        Nodes::new(nodes, policy),
        Arc::new(MemoryStore::default()),
    );
    api.ingress = ingress;
    let api = Arc::new(api);
    // What runs already (after a restart of this service) and the state of
    // every node are known before the first request is served.
    api.reconcile();
    if let Some(log) = &api.log {
        let log = Arc::clone(log);
        std::thread::Builder::new()
            .name("usage-log".into())
            .spawn(move || log.run())
            .map_err(|e| e.to_string())?;
    }
    {
        let api = Arc::clone(&api);
        std::thread::Builder::new()
            .name("meter".into())
            .spawn(move || {
                let mut recorded = std::time::Instant::now();
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let flush = recorded.elapsed() >= record_every;
                    if flush {
                        recorded = std::time::Instant::now();
                    }
                    api.tick(flush);
                }
            })
            .map_err(|e| e.to_string())?;
    }
    // Each node is probed on a thread of its own, so a slow one does not
    // delay the others.
    for i in 0..api.nodes.configs().len() {
        let api = Arc::clone(&api);
        std::thread::Builder::new()
            .name(format!("probe-{}", api.nodes.configs()[i].name))
            .spawn(move || loop {
                std::thread::sleep(interval);
                api.probe(i);
            })
            .map_err(|e| e.to_string())?;
    }
    if let (Some(listener), Some(token)) = (admin_listener, admin_token) {
        let admin_addr = listener.local_addr().map_err(|e| e.to_string())?;
        let admin = Arc::new(Admin {
            api: Arc::clone(&api),
            token,
        });
        std::thread::Builder::new()
            .name("admin".into())
            .spawn(move || {
                if let Err(err) = hellovm_control::http::serve(listener, admin, admin_limits) {
                    log::error!("serving the admin API: {err}");
                }
            })
            .map_err(|e| e.to_string())?;
        log::info!("admin API at {admin_addr}");
    }
    if let Some(listener) = ingress_listener {
        let ingress_addr = listener.local_addr().map_err(|e| e.to_string())?;
        let api = Arc::clone(&api);
        std::thread::Builder::new()
            .name("ingress".into())
            .spawn(move || hellovm_api::ingress::serve(listener, api))
            .map_err(|e| e.to_string())?;
        log::info!("ingress at {ingress_addr}");
    }
    log::info!("listening on {addr}");
    hellovm_control::http::serve(listener, api, limits).map_err(|e| format!("serving: {e}"))
}
