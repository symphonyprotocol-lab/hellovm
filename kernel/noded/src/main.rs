//! `hellovm-noded --config FILE`: the node daemon (see the crate
//! documentation and the README, "Control plane").

use std::process::ExitCode;

const USAGE: &str = "usage: hellovm-noded --config FILE";

fn main() -> ExitCode {
    hellovm_control::init_logging("noded");
    let mut args = std::env::args().skip(1);
    let config = match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--config"), Some(path), None) => path,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_config: &str) -> Result<(), String> {
    Err("noded runs sandboxes, which needs Linux".into())
}

#[cfg(target_os = "linux")]
fn run(config_path: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use hellovm_noded::config::Config;
    use hellovm_noded::node::Node;
    use hellovm_noded::server::NodeApi;
    use hellovm_noded::template::{self, Template, SHUTDOWN};

    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_signal(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }

    let text = std::fs::read_to_string(config_path).map_err(|e| format!("{config_path}: {e}"))?;
    let config = Config::parse(&text).map_err(|e| format!("{config_path}: {e}"))?;
    let token = config.token()?;
    if let Some((stats, _)) = config.egress_stats()? {
        // Every kernel process sees the egress socket's directory.
        if let Some(egress) = &config.egress {
            if stats.parent() == egress.parent() {
                return Err(
                    "egress_stats: the stats socket must not be in the egress socket's \
                     directory (every sandbox's kernel process can see that one)"
                        .into(),
                );
            }
        }
    }
    if !config.hellovm.is_file() {
        return Err(format!(
            "hellovm binary {} not found",
            config.hellovm.display()
        ));
    }
    // Per sandbox: its control connection twice, the agent's two pipes and
    // its log pipe. Per template: its process's two output pipes and the
    // socket of a ping. Then the API's connections and noded's own files.
    let limits = hellovm_control::http::Limits::default();
    let fds = config.max_sandboxes as u64 * 5
        + config.templates.len() as u64 * 4
        + limits.max_connections as u64
        + 64;
    hellovm_control::ensure_fd_limit(fds)?;
    let egress = config
        .egress
        .as_deref()
        .map(std::path::absolute)
        .transpose()
        .map_err(|e| format!("egress: {e}"))?;

    // The state directory is noded's alone: the template sockets in it let
    // whoever reaches them make clones.
    let sockets = config.state_dir.join("templates");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&sockets)
        .map_err(|e| format!("{}: {e}", sockets.display()))?;
    let lock_path = config.state_dir.join("noded.lock");
    let lock =
        std::fs::File::create(&lock_path).map_err(|e| format!("{}: {e}", lock_path.display()))?;
    // SAFETY: flock on an fd we own; held until the process exits.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "{}: another noded uses this state directory",
            config.state_dir.display()
        ));
    }
    template::clean_dir(&sockets).map_err(|e| format!("{}: {e}", sockets.display()))?;

    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| format!("listen {}: {e}", config.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    let templates: Vec<Arc<Template>> = config
        .templates
        .iter()
        .map(|t| Arc::new(Template::new(t.clone(), &sockets)))
        .collect();
    for t in &templates {
        let (t, hellovm, egress) = (Arc::clone(t), config.hellovm.clone(), egress.clone());
        std::thread::Builder::new()
            .name(format!("template-{}", t.config.name))
            .spawn(move || template::supervise(t, hellovm, egress))
            .map_err(|e| e.to_string())?;
    }
    let node = Arc::new(Node::new(config, templates.clone()));
    {
        let node = Arc::clone(&node);
        std::thread::Builder::new()
            .name("reaper".into())
            .spawn(move || node.reap())
            .map_err(|e| e.to_string())?;
    }
    {
        let node = Arc::clone(&node);
        std::thread::Builder::new()
            .name("usage".into())
            .spawn(move || node.watch_usage())
            .map_err(|e| e.to_string())?;
    }
    {
        let api = Arc::new(NodeApi {
            node: Arc::clone(&node),
            token,
        });
        std::thread::Builder::new()
            .name("http".into())
            .spawn(move || {
                if let Err(err) = hellovm_control::http::serve(listener, api, limits) {
                    log::error!("serving the node API: {err}");
                    STOP.store(true, Ordering::SeqCst);
                }
            })
            .map_err(|e| e.to_string())?;
    }
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    if node.config.start_drained {
        log::info!(
            "node state change: node={} draining=true (start_drained)",
            node.config.node
        );
    }
    log::info!("node {} listening on {addr}", node.config.node);
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    log::info!("shutting down: removing every sandbox and template");
    SHUTDOWN.store(true, Ordering::SeqCst);
    node.remove_all("the node shut down");
    for t in &templates {
        t.kill();
    }
    std::thread::sleep(Duration::from_millis(200));
    for t in &templates {
        let _ = std::fs::remove_file(&t.socket);
    }
    Ok(())
}
