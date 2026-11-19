//! Keeping warm templates alive: one supervisor thread per template starts
//! `hellovm --template` with the agent, waits until it is frozen, and
//! starts it again when it ends, after removing its socket file (the
//! confined template cannot remove it itself). Templates die with noded
//! (`PR_SET_PDEATHSIG`, tied to the supervisor thread, which never ends),
//! and their clones die with them.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hellovm::warm::{Frame, Kind, Request};
use hellovm_control::types::TemplateStatus;

use crate::agent::AGENT_SOURCE;
use crate::config::{SandboxMode, TemplateConfig};

/// Set when noded shuts down: supervisors stop restarting.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long a template may take from start to frozen.
const START_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Template {
    pub config: TemplateConfig,
    pub socket: PathBuf,
    ready: AtomicBool,
    starts: AtomicU64,
    /// The running `hellovm --template`, 0 when none.
    pid: AtomicU32,
}

impl Template {
    pub fn new(config: TemplateConfig, dir: &Path) -> Template {
        let socket = dir.join(format!("{}.sock", config.name));
        Template {
            config,
            socket,
            ready: AtomicBool::new(false),
            starts: AtomicU64::new(0),
            pid: AtomicU32::new(0),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn status(&self) -> TemplateStatus {
        TemplateStatus {
            name: self.config.name.clone(),
            ready: self.is_ready(),
            starts: self.starts.load(Ordering::SeqCst),
            tenant: self.config.tenant.clone(),
            pid: self.pid(),
            memory_limit_bytes: Some(self.config.memory_limit_mb << 20),
        }
    }

    /// The running template process, if any.
    pub fn pid(&self) -> Option<u32> {
        Some(self.pid.load(Ordering::SeqCst)).filter(|&p| p != 0)
    }

    /// Kills the template process (at shutdown); its clones die with it.
    pub fn kill(&self) {
        if let Some(pid) = self.pid() {
            // SAFETY: plain kill of our own child.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }

    fn command(&self, hellovm: &Path, egress: Option<&Path>) -> Command {
        let c = &self.config;
        let mut cmd = Command::new(hellovm);
        cmd.arg("--template").arg(&self.socket);
        cmd.arg("--sandbox").arg(match c.sandbox_mode() {
            SandboxMode::Require => "require",
            SandboxMode::BestEffort => "best-effort",
        });
        if let Some(egress) = egress {
            cmd.arg("--egress").arg(egress);
        }
        cmd.arg("--fs-limit").arg((c.fs_limit_mb << 20).to_string());
        for (k, v) in &c.env {
            cmd.arg("--env").arg(format!("{k}={v}"));
        }
        cmd.arg("--root").arg(&c.root).arg("--");
        cmd.args([c.python.as_str(), "-I", "-c", AGENT_SOURCE]);
        cmd.args(&c.preload);
        cmd
    }
}

/// Removes `path` if it is a socket nobody listens on any more. Returns
/// whether it was removed.
pub fn remove_stale_socket(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_socket() {
        return false;
    }
    match UnixStream::connect(path) {
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path).is_ok()
        }
        Err(_) => false,
        Ok(_) => {
            log::warn!(
                "{}: a process still serves this socket; it is not a template of this noded",
                path.display()
            );
            false
        }
    }
}

/// Removes the stale template sockets in `dir`, at start-up: what a
/// previous noded's templates left.
pub fn clean_dir(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "sock") && remove_stale_socket(&path) {
            log::info!("removed the stale socket {}", path.display());
            removed += 1;
        }
    }
    Ok(removed)
}

/// Asks the template whether it is frozen, with a deadline.
pub fn ping(socket: &Path, timeout: Duration) -> io::Result<(u64, u32)> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = Request {
        kind: Kind::Ping,
        sandbox_id: None,
        ingress: false,
        input: Vec::new(),
    };
    stream.write_all(&request.encode())?;
    match Frame::read_from(&mut stream)? {
        Some(Frame::Ready { stored, areas }) => Ok((stored, areas)),
        Some(Frame::Error(text)) => Err(io::Error::other(text)),
        other => Err(io::Error::other(format!("unexpected answer {other:?}"))),
    }
}

/// Forwards the template's output (its guest's console before the
/// freeze, hellovm's log lines, its clones' kernel processes' log lines)
/// to noded's log, a bounded line at a time.
fn forward(name: String, stream: impl Read + Send + 'static) {
    let thread = format!("template-{name}-log");
    let spawned = std::thread::Builder::new()
        .name(thread.clone())
        .spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            loop {
                line.clear();
                match (&mut reader).take(4096).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        let text = String::from_utf8_lossy(&line);
                        log::info!("template {name}: {}", text.trim_end());
                    }
                }
            }
        });
    if let Err(err) = spawned {
        log::warn!("{thread}: no thread for the template's output: {err}");
    }
}

/// Runs the template once: until its process ends.
fn run_once(t: &Template, hellovm: &Path, egress: Option<&Path>) -> io::Result<()> {
    let name = &t.config.name;
    if std::fs::symlink_metadata(&t.socket).is_ok() {
        std::fs::remove_file(&t.socket)?;
    }
    let mut cmd = t.command(hellovm, egress);
    // SAFETY: getpid is async-signal-safe.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the closure only makes async-signal-safe calls.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            // The parent may have died before the prctl.
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            Ok(())
        });
    }
    let started = Instant::now();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    t.pid.store(child.id(), Ordering::SeqCst);
    t.starts.fetch_add(1, Ordering::SeqCst);
    if let Some(out) = child.stdout.take() {
        forward(name.clone(), out);
    }
    if let Some(err) = child.stderr.take() {
        forward(name.clone(), err);
    }
    // Until the socket exists and the template answers that it is frozen.
    let ready = loop {
        if let Some(status) = child.try_wait()? {
            break Err(format!("ended before it was ready ({status})"));
        }
        if started.elapsed() > START_TIMEOUT {
            break Err(format!("not ready after {START_TIMEOUT:?}"));
        }
        if t.socket.exists() {
            match ping(&t.socket, START_TIMEOUT) {
                // The socket file is there from `bind` on, a moment before
                // the template listens on it: ask again.
                Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {}
                other => break other.map_err(|e| e.to_string()),
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    match ready {
        Ok((stored, areas)) => {
            t.ready.store(true, Ordering::SeqCst);
            log::info!(
                "template {name} ready in {:?} (pid {}, {} MiB in {areas} areas)",
                started.elapsed(),
                child.id(),
                stored >> 20
            );
        }
        Err(why) => {
            log::warn!("template {name}: {why}");
            let _ = child.kill();
        }
    }
    let status = child.wait()?;
    t.ready.store(false, Ordering::SeqCst);
    t.pid.store(0, Ordering::SeqCst);
    if !SHUTDOWN.load(Ordering::SeqCst) {
        log::warn!("template {name} ended ({status}); its sandboxes are gone");
    }
    let _ = std::fs::remove_file(&t.socket);
    Ok(())
}

/// Keeps `t` running until noded shuts down. Must run on a thread that
/// lives as long as noded: the template's parent-death signal is tied to
/// it.
pub fn supervise(t: Arc<Template>, hellovm: PathBuf, egress: Option<PathBuf>) {
    let mut delay = Duration::from_millis(250);
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let started = Instant::now();
        if let Err(err) = run_once(&t, &hellovm, egress.as_deref()) {
            log::warn!("template {}: {err}", t.config.name);
        }
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        // A template that ran for a while is restarted at once; one that
        // keeps failing, less and less often.
        if started.elapsed() > Duration::from_secs(60) {
            delay = Duration::from_millis(250);
        } else {
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_sockets_are_removed_and_live_ones_kept() {
        let dir = std::env::temp_dir().join(format!(
            "noded-clean-{}-{}",
            std::process::id(),
            hellovm_control::unix_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("old.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        let live_path = dir.join("live.sock");
        let _live = std::os::unix::net::UnixListener::bind(&live_path).unwrap();
        let other = dir.join("notes.sock");
        std::fs::write(&other, b"not a socket").unwrap();
        // Another test of this process may be starting a child right now:
        // between its fork and its exec the child holds a copy of the
        // listener just dropped, and the socket still answers. Only then.
        let start = Instant::now();
        let mut removed = clean_dir(&dir).unwrap();
        while stale.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
            removed += clean_dir(&dir).unwrap();
        }
        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(live_path.exists());
        assert!(other.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
