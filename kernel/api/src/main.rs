//! `hellovm-api --config FILE`: the public API (see the crate
//! documentation and the README, "Control plane").

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hellovm_api::config::Config;
use hellovm_api::service::Api;
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
    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| format!("listen {}: {e}", config.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let interval = Duration::from_secs_f64(config.reconcile_interval);
    let api = Arc::new(Api {
        config,
        tenants,
        nodes,
        store: Arc::new(MemoryStore::default()),
    });
    // What runs already (after a restart of this service) is known before
    // the first request is served.
    api.reconcile();
    {
        let api = Arc::clone(&api);
        std::thread::Builder::new()
            .name("reconcile".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                api.reconcile();
            })
            .map_err(|e| e.to_string())?;
    }
    log::info!("listening on {addr}");
    hellovm_control::http::serve(listener, api, hellovm_control::http::Limits::default())
        .map_err(|e| format!("serving: {e}"))
}
