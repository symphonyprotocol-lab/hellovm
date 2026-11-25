//! [`apply`]: the layers in order, and the report of how each went.

use std::fmt;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

#[cfg(feature = "insecure-test-hooks")]
use crate::learn;
use crate::{allowlist, filter, landlock, limits, ns, Mode};

/// What [`apply`] needs.
pub struct Config<'a> {
    pub mode: Mode,
    /// The image directory, already open.
    pub image: BorrowedFd<'a>,
    /// Its absolute host path (the namespaces bind-mount it).
    pub image_path: &'a Path,
    /// The egress proxy's socket, absolute host path.
    pub egress: Option<PathBuf>,
    /// Test hook (`--splice-to`): one loopback TCP port K must reach.
    pub tcp_port: Option<u16>,
    /// Test hook: measure syscalls instead of enforcing the allowlist
    /// (see `learn`).
    pub learn: Option<PathBuf>,
    /// Test hook: leave Landlock out, to test the other fences alone.
    pub skip_landlock: bool,
    /// The process becomes a warm-clone template: it also needs the
    /// syscalls that serve clone requests and that make a clone's own
    /// Landlock domain (`allowlist`).
    pub warm: bool,
    /// The outcome of [`close_inherited_fds`].
    pub fds: Result<usize, String>,
    /// What runs the guest.
    pub platform: Platform,
}

/// The platform the kernel process runs its guest on, which decides its
/// seccomp filter.
#[derive(Clone, Debug, Default)]
pub enum Platform {
    /// `hellovm-platform-seccomp`: app processes forked from the kernel
    /// process and driven with `ptrace` (see `filter`).
    #[default]
    Seccomp,
    /// `hellovm-platform-kvm`: a KVM VM, made before the hardening, and
    /// its vCPUs' fds (see `allowlist::kvm_entries`). The process has no
    /// other thread yet.
    Kvm { vcpus: Vec<i32> },
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

    /// Whether the kernel process is fenced off from the host's files.
    pub fn filesystem_confined(&self) -> bool {
        self.active(Layer::Namespaces) || self.active(Layer::Landlock)
    }

    /// Logs active layers at debug level and skipped ones at info level.
    /// What leaves the kernel process weaker than `--sandbox=require`
    /// would accept is a warning, which the default log level shows.
    pub fn log(&self) {
        let confined = self.filesystem_confined();
        for l in &self.layers {
            let name = l.layer.name();
            match &l.outcome {
                Ok(detail) => log::debug!("sandbox: {name}: active ({detail})"),
                Err(reason) => {
                    let either = matches!(l.layer, Layer::Namespaces | Layer::Landlock);
                    if either && confined {
                        log::info!("sandbox: {name}: skipped: {reason}");
                    } else {
                        log::warn!("sandbox: {name}: skipped: {reason}");
                    }
                }
            }
        }
        if !confined {
            log::warn!(
                "sandbox: neither namespaces nor Landlock are available: the kernel process \
                 is not confined to the image and could, if compromised, read this user's files"
            );
        }
    }
}

/// What [`apply`] returns.
#[derive(Debug)]
pub struct Hardened {
    pub report: Report,
    /// The image directory as the kernel process must use it from now on:
    /// `Some` when the namespaces moved it (the fd opened before then
    /// leads back into the old root and must be dropped).
    pub image: Option<OwnedFd>,
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
pub fn apply(config: Config<'_>) -> Result<Hardened, Refused> {
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
        return Ok(Hardened {
            report,
            image: None,
        });
    }
    report.push(
        Layer::Fds,
        config.fds.clone().map(|n| format!("{n} closed")),
    );

    // Taken before the namespaces and Landlock hide /proc (the seccomp
    // platform's only).
    let profile = match config.platform {
        Platform::Seccomp => hellovm_platform_seccomp::host_profile()
            .map(Some)
            .map_err(|err| err.to_string()),
        Platform::Kvm { .. } => Ok(None),
    };
    // The measurement file, if any, must be opened before Landlock.
    let learn = config.learn.as_ref().map(|path| {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|err| format!("{}: {err}", path.display()))
    });

    let mut image = None;
    match ns::enter(
        config.image_path,
        config.egress.as_deref(),
        config.tcp_port.is_some(),
    ) {
        Ok(entered) => {
            report.push(
                Layer::Namespaces,
                Ok(if entered.net {
                    "user, mount, network, IPC".into()
                } else {
                    "user, mount, IPC; network kept for --splice-to".into()
                }),
            );
            if config.egress.is_some() && entered.egress.is_none() {
                log::warn!(
                    "the directory of the egress socket does not exist: \
                     outbound flows will be refused"
                );
            }
            report.egress = entered.egress;
            image = Some(entered.image);
        }
        Err(ns::NsError::Unavailable(reason)) => report.push(Layer::Namespaces, Err(reason)),
        Err(ns::NsError::Failed(reason)) => {
            // Half-built namespaces: never run guest code like this.
            report.push(Layer::Namespaces, Err(format!("FAILED half-way: {reason}")));
            report.log();
            return Err(Refused(report));
        }
    }

    report.push(
        Layer::Limits,
        limits::apply().map(|()| format!("core 0, nofile {}", limits::NOFILE)),
    );
    report.push(Layer::NoNewPrivs, prctl(libc::PR_SET_NO_NEW_PRIVS, 1));
    let image_fd = image.as_ref().map_or(config.image, |fd| fd.as_fd());
    let landlock = if config.skip_landlock {
        Err("left out by a test hook".into())
    } else {
        landlock::restrict(image_fd, config.tcp_port)
    };
    report.push(
        Layer::Landlock,
        landlock.map(|a| {
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
        if !report.filesystem_confined() || required.iter().any(|&l| !report.active(l)) {
            return Err(Refused(report));
        }
    }
    Ok(Hardened { report, image })
}

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

pub(crate) fn audit_arch() -> u32 {
    if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    }
}

fn install_seccomp(
    profile: Option<&hellovm_platform_seccomp::HostProfile>,
    config: &Config<'_>,
    learn: Option<Result<std::fs::File, String>>,
) -> Result<String, String> {
    let code = match profile {
        Some(profile) => profile.code_ranges(),
        None => std::slice::from_ref(&filter::EVERY_ADDRESS),
    };
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
    let entries = match (&config.platform, profile) {
        (Platform::Kvm { vcpus }, _) => allowlist::kvm_entries(vcpus, config.tcp_port.is_some()),
        (Platform::Seccomp, Some(profile)) => {
            allowlist::entries(profile.stub_fd(), config.tcp_port.is_some(), config.warm)
        }
        (Platform::Seccomp, None) => return Err("no host profile".into()),
    };
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
