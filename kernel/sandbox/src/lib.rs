//! Least privilege for the kernel process (`hellovm`).
//!
//! The kernel process (K) parses guest-controlled bytes (ELF files,
//! syscall arguments, DNS queries, signal frames) and must assume one of
//! those parsers has a bug. Once start-up is done (image directory open,
//! egress socket path known, platform profile taken) and before it looks
//! at any guest input, [`apply`] takes away everything K does not need.
//! Each layer is used when the host allows it and skipped, with the
//! reason, when it does not, because hellovm must also run inside an
//! unprivileged container. In this order:
//!
//! 1. **Inherited fds** ([`close_inherited_fds`], at the very start of
//!    `main`): everything but stdin, stdout and stderr is closed.
//! 2. **Namespaces** (`ns`): user + mount + network + IPC; the root becomes
//!    an empty read-only tmpfs, the old one is detached, the egress socket
//!    is bind-mounted in, and every capability is dropped again.
//! 3. **Resource limits** (`limits`): no core dumps, at most 4096 fds,
//!    32 GiB of address space.
//! 4. **`PR_SET_NO_NEW_PRIVS`**.
//! 5. **Landlock** (`landlock`): reading the image directory is the only
//!    filesystem access; no TCP bind or connect; signals and abstract Unix
//!    sockets only within K's own domain (its app processes).
//! 6. **Not dumpable** (`PR_SET_DUMPABLE` 0): no ptrace attach to K and no
//!    `/proc/<pid>/mem` of K by other processes of the same user.
//! 7. **Seccomp** (`filter`, `allowlist`): an allowlist with argument
//!    checks for every syscall made from K's own code; anything else kills
//!    the process. `filter` explains how that coexists with the app
//!    processes' own filter.
//!
//! Required for `--sandbox=require`: 1, 3, 4, 6, 7, and filesystem
//! confinement by 2 or 5 (at least one). The network namespace, Landlock's
//! TCP and scope rights, and the IPC namespace are used when available.
//!
//! Without a network namespace or Landlock's TCP rights, the seccomp
//! rules are the network fence: `socket` is allowed for `AF_UNIX` stream
//! sockets only. Without the mount namespace, a pathname Unix socket other
//! than the egress socket is still reachable by `connect` (neither Landlock
//! nor seccomp can check a socket path).

#![cfg(target_os = "linux")]

mod allowlist;
mod bpf;
mod filter;
mod landlock;
#[cfg(feature = "insecure-test-hooks")]
mod learn;
mod limits;
mod ns;

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

pub use ns::EGRESS_INSIDE;

/// `--sandbox=require|best-effort|off`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Fail to start when a required layer is unavailable.
    Require,
    /// Use every layer the host allows.
    #[default]
    BestEffort,
    /// No hardening (debugging only).
    Off,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Mode, String> {
        match s {
            "require" => Ok(Mode::Require),
            "best-effort" => Ok(Mode::BestEffort),
            "off" => Ok(Mode::Off),
            _ => Err(format!(
                "--sandbox {s}: expected require, best-effort or off"
            )),
        }
    }
}

/// What [`apply`] needs.
pub struct Config<'a> {
    pub mode: Mode,
    /// The image directory, already open.
    pub image: BorrowedFd<'a>,
    /// The egress proxy's socket, absolute host path.
    pub egress: Option<PathBuf>,
    /// Test hook (`--splice-to`): one loopback TCP port K must reach.
    pub tcp_port: Option<u16>,
    /// Test hook: measure syscalls instead of enforcing the allowlist
    /// (see `learn`).
    pub learn: Option<PathBuf>,
    /// The outcome of [`close_inherited_fds`].
    pub fds: Result<usize, String>,
}

/// A hardening layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Fds,
    Namespaces,
    Limits,
    NoNewPrivs,
    Landlock,
    NotDumpable,
    Seccomp,
}

impl Layer {
    pub fn name(self) -> &'static str {
        match self {
            Layer::Fds => "inherited fds closed",
            Layer::Namespaces => "user/mount/network/IPC namespaces",
            Layer::Limits => "resource limits",
            Layer::NoNewPrivs => "no_new_privs",
            Layer::Landlock => "Landlock",
            Layer::NotDumpable => "not dumpable",
            Layer::Seccomp => "seccomp allowlist",
        }
    }
}

/// How one layer went: `Ok(detail)` when active, `Err(reason)` when
/// skipped.
#[derive(Clone, Debug)]
pub struct LayerReport {
    pub layer: Layer,
    pub outcome: Result<String, String>,
}

/// What [`apply`] did.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub layers: Vec<LayerReport>,
    /// Where K must now connect to reach the egress proxy.
    pub egress: Option<PathBuf>,
}

impl Report {
    pub fn active(&self, layer: Layer) -> bool {
        self.layers
            .iter()
            .any(|l| l.layer == layer && l.outcome.is_ok())
    }

    fn push(&mut self, layer: Layer, outcome: Result<String, String>) {
        self.layers.push(LayerReport { layer, outcome });
    }

    /// Logs every layer at debug level, skipped ones at info level too.
    pub fn log(&self) {
        for l in &self.layers {
            match &l.outcome {
                Ok(detail) => log::debug!("sandbox: {}: active ({detail})", l.layer.name()),
                Err(reason) => log::info!("sandbox: {}: skipped: {reason}", l.layer.name()),
            }
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in &self.layers {
            match &l.outcome {
                Ok(detail) => writeln!(f, "{}: active ({detail})", l.layer.name())?,
                Err(reason) => writeln!(f, "{}: skipped: {reason}", l.layer.name())?,
            }
        }
        Ok(())
    }
}

/// Closes every fd above 2. Call it first thing in `main`, before anything
/// opens an fd of its own; returns how many were open.
pub fn close_inherited_fds() -> Result<usize, String> {
    let open = std::fs::read_dir("/proc/self/fd")
        .map(|dir| {
            dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
                .filter(|&fd| fd > 2)
                .count()
                // read_dir's own fd.
                .saturating_sub(1)
        })
        .unwrap_or(0);
    // SAFETY: closes fds this process does not use; nothing else in the
    // process holds them yet.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if ret != 0 {
        return Err(format!("close_range: {}", io::Error::last_os_error()));
    }
    Ok(open)
}

/// Why `--sandbox=require` refused to start.
#[derive(Debug)]
pub struct Refused(pub Report);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot harden the kernel process (a required layer is unavailable, \
             or a layer failed half-way):\n{}",
            self.0
        )
    }
}

impl std::error::Error for Refused {}

fn prctl(option: libc::c_int, arg: libc::c_ulong) -> Result<String, String> {
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(option, arg, 0, 0, 0) } != 0 {
        return Err(format!("prctl: {}", io::Error::last_os_error()));
    }
    Ok(String::new())
}

/// Applies every layer the host allows; see the crate documentation.
pub fn apply(config: Config<'_>) -> Result<Report, Refused> {
    let mut report = Report {
        egress: config.egress.clone(),
        ..Report::default()
    };
    if config.mode == Mode::Off {
        for layer in [
            Layer::Fds,
            Layer::Namespaces,
            Layer::Limits,
            Layer::NoNewPrivs,
            Layer::Landlock,
            Layer::NotDumpable,
            Layer::Seccomp,
        ] {
            report.push(layer, Err("--sandbox=off".into()));
        }
        return Ok(report);
    }
    report.push(
        Layer::Fds,
        config.fds.clone().map(|n| format!("{n} closed")),
    );

    // Taken before the namespaces and Landlock hide /proc.
    let profile = hellovm_platform_seccomp::host_profile().map_err(|err| err.to_string());
    // The measurement file, if any, must be opened before Landlock.
    let learn = config.learn.as_ref().map(|path| {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|err| format!("{}: {err}", path.display()))
    });

    match ns::enter(config.egress.as_deref(), config.tcp_port.is_some()) {
        Ok(entered) => {
            report.push(
                Layer::Namespaces,
                Ok(if entered.net {
                    "user, mount, network, IPC".into()
                } else {
                    "user, mount, IPC; network kept for --splice-to".into()
                }),
            );
            if config.egress.is_some() {
                report.egress = entered.egress;
            }
        }
        Err(ns::NsError::Unavailable(reason)) => report.push(Layer::Namespaces, Err(reason)),
        Err(ns::NsError::Failed(reason)) => {
            // Half-built namespaces: never run guest code like this.
            report.push(
                Layer::Namespaces,
                Err(format!("FAILED after unshare: {reason}")),
            );
            report.log();
            return Err(Refused(report));
        }
    }

    report.push(
        Layer::Limits,
        limits::apply().map(|()| {
            format!(
                "core 0, nofile {}, as {} GiB",
                limits::NOFILE,
                limits::ADDRESS_SPACE >> 30
            )
        }),
    );
    report.push(Layer::NoNewPrivs, prctl(libc::PR_SET_NO_NEW_PRIVS, 1));
    report.push(
        Layer::Landlock,
        landlock::restrict(config.image, config.tcp_port).map(|a| {
            format!(
                "ABI {}: image read-only{}{}",
                a.abi,
                if a.net { ", no TCP" } else { "" },
                if a.scoped {
                    ", signals and abstract sockets scoped"
                } else {
                    ""
                }
            )
        }),
    );
    report.push(Layer::NotDumpable, prctl(libc::PR_SET_DUMPABLE, 0));
    report.push(
        Layer::Seccomp,
        profile.and_then(|profile| install_seccomp(profile, &config, learn)),
    );
    report.log();

    if config.mode == Mode::Require {
        let required = [
            Layer::Fds,
            Layer::Limits,
            Layer::NoNewPrivs,
            Layer::NotDumpable,
            Layer::Seccomp,
        ];
        let fs_confined = report.active(Layer::Namespaces) || report.active(Layer::Landlock);
        if !fs_confined || required.iter().any(|&l| !report.active(l)) {
            return Err(Refused(report));
        }
    }
    Ok(report)
}

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

fn audit_arch() -> u32 {
    if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    }
}

fn install_seccomp(
    profile: &hellovm_platform_seccomp::HostProfile,
    config: &Config<'_>,
    learn: Option<Result<std::fs::File, String>>,
) -> Result<String, String> {
    let code = profile.code_ranges();
    #[cfg(feature = "insecure-test-hooks")]
    if let Some(out) = learn {
        let mut prog = filter::build(
            audit_arch(),
            code,
            filter::Judge::Learn {
                execveat: libc::SYS_execveat as u32,
            },
        )?;
        learn::install(&mut prog, out?.into()).map_err(|err| format!("learning filter: {err}"))?;
        return Ok("LEARNING, nothing enforced".into());
    }
    #[cfg(not(feature = "insecure-test-hooks"))]
    if learn.is_some() {
        return Err("HELLOVM_SECCOMP_LEARN needs the insecure-test-hooks feature".into());
    }
    let entries = allowlist::entries(profile.stub_fd(), config.tcp_port.is_some());
    let mut prog = filter::build(audit_arch(), code, filter::Judge::Allowlist(&entries))?;
    let fprog = libc::sock_fprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: a valid program; NO_NEW_PRIVS is set.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const libc::sock_fprog,
        )
    };
    if ret != 0 {
        return Err(format!("seccomp: {}", io::Error::last_os_error()));
    }
    Ok(format!(
        "{} syscalls, {} instructions, {} code ranges",
        entries.len(),
        prog.len(),
        code.len()
    ))
}
