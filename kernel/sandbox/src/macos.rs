//! [`apply`] on macOS: the layers in order, and the report of how each
//! went. See the crate documentation and README, "Hardening".

use std::ffi::{c_char, c_int, CStr, CString};
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::Mode;

pub use crate::seatbelt::profile;

/// What [`apply`] needs.
pub struct Config<'a> {
    pub mode: Mode,
    /// The image directory's canonical host path: the only files the
    /// kernel process may read afterwards.
    pub image_path: &'a Path,
    /// `--egress`: the egress proxy's socket, the one place the kernel
    /// process may connect to (an absolute path without symlinks, as
    /// the kernel process connects to it). `None`: no network at all.
    pub egress: Option<&'a Path>,
    /// Test hook: measure what the profile lacks: denied system calls fail
    /// instead of killing the process (see `seatbelt::Kind::Learn`).
    pub learn: bool,
    /// Test hook: hand Seatbelt a profile it rejects, as if the sandbox
    /// could not be entered.
    pub broken: bool,
    /// The outcome of [`close_inherited_fds`].
    pub fds: Result<usize, String>,
}

/// A hardening layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Fds,
    Limits,
    Environment,
    NoDebugger,
    Seatbelt,
}

impl Layer {
    pub fn name(self) -> &'static str {
        match self {
            Layer::Fds => "inherited fds closed",
            Layer::Limits => "resource limits",
            Layer::Environment => "environment cleared",
            Layer::NoDebugger => "no debugger (PT_DENY_ATTACH)",
            Layer::Seatbelt => "Seatbelt profile",
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

    /// Logs active layers at debug level and skipped ones as warnings
    /// (every layer is required by `--sandbox require`).
    pub fn log(&self) {
        for l in &self.layers {
            let name = l.layer.name();
            match &l.outcome {
                Ok(detail) => log::debug!("sandbox: {name}: active ({detail})"),
                Err(reason) => log::warn!("sandbox: {name}: skipped: {reason}"),
            }
        }
        if !self.active(Layer::Seatbelt) {
            log::warn!(
                "sandbox: no Seatbelt profile: the kernel process is not confined and \
                 could, if compromised, read and write this user's files and use the network"
            );
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

/// Why `--sandbox=require` refused to start.
#[derive(Debug)]
pub struct Refused(pub Report);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot harden the kernel process (a required layer is unavailable):\n{}",
            self.0
        )
    }
}

impl std::error::Error for Refused {}

/// Closes every fd above 2. Call it first thing in `main`, before anything
/// opens an fd of its own; returns how many were open. macOS has no
/// `close_range`: the open fds are listed with `proc_pidinfo`.
pub fn close_inherited_fds() -> Result<usize, String> {
    let fds = open_fds()?;
    let mut closed = 0;
    for fd in fds.into_iter().filter(|&fd| fd > 2) {
        // SAFETY: closes an fd this process does not use; nothing else in
        // the process holds it yet.
        if unsafe { libc::close(fd) } == 0 {
            closed += 1;
        }
    }
    // Checked again: nothing above 2 may be left.
    match open_fds()?.into_iter().find(|&fd| fd > 2) {
        Some(fd) => Err(format!("fd {fd} is still open")),
        None => Ok(closed),
    }
}

/// This process's open fds.
pub fn open_fds() -> Result<Vec<c_int>, String> {
    let size = std::mem::size_of::<libc::proc_fdinfo>();
    let mut buf: Vec<libc::proc_fdinfo> = Vec::new();
    // The table can grow between the size query and the listing: retry
    // with more room (bounded).
    for _ in 0..4 {
        // SAFETY: a size query (null buffer).
        let need = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if need <= 0 {
            return Err(format!(
                "proc_pidinfo(PROC_PIDLISTFDS): {}",
                io::Error::last_os_error()
            ));
        }
        let room = need as usize / size + 16;
        buf.resize(
            room,
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            },
        );
        // SAFETY: the buffer holds `room` entries.
        let got = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                (room * size) as c_int,
            )
        };
        if got < 0 {
            return Err(format!(
                "proc_pidinfo(PROC_PIDLISTFDS): {}",
                io::Error::last_os_error()
            ));
        }
        let got = got as usize / size;
        if got < room {
            return Ok(buf[..got].iter().map(|f| f.proc_fd).collect());
        }
    }
    Err("proc_pidinfo(PROC_PIDLISTFDS): the fd table keeps growing".into())
}

/// Resource limits; see `apply_limits`.
pub const NOFILE: u64 = 256;

fn lower(resource: c_int, value: u64) -> Result<(), String> {
    // SAFETY: getrlimit/setrlimit with a valid struct.
    unsafe {
        let mut cur: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(resource, &mut cur) != 0 {
            return Err(format!("getrlimit: {}", io::Error::last_os_error()));
        }
        let value = value.min(cur.rlim_max);
        let new = libc::rlimit {
            rlim_cur: cur.rlim_cur.min(value),
            rlim_max: value,
        };
        if libc::setrlimit(resource, &new) != 0 {
            return Err(format!("setrlimit: {}", io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// | Limit | Value | Why |
/// |---|---|---|
/// | `RLIMIT_CORE` | 0 | no core dump of the kernel process (guest memory) |
/// | `RLIMIT_NOFILE` | 256 | the kernel process holds stdio, the image directory and at most 48 cached image fds |
/// | `RLIMIT_NPROC` | 1 | it never makes a process; on macOS the limit is checked against the user's whole process count, so `fork` and `posix_spawn` fail whatever the profile says |
///
/// Limits are only lowered, the soft one too.
fn apply_limits() -> Result<String, String> {
    lower(libc::RLIMIT_CORE, 0)?;
    lower(libc::RLIMIT_NOFILE, NOFILE)?;
    lower(libc::RLIMIT_NPROC, 1)?;
    Ok(format!("core 0, nofile {NOFILE}, nproc 1"))
}

/// Removes every environment variable: the kernel process reads none after
/// start-up, and an operator's environment (tokens, keys) is not for a
/// compromised kernel process to read. The program's own environment is
/// built from `--env`, never from this one. Must run while no other
/// thread may read the environment (see the caller).
fn clear_environment() -> Result<String, String> {
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    for name in &names {
        std::env::remove_var(name);
    }
    match std::env::vars_os().next() {
        Some((name, _)) => Err(format!("{} is still set", name.to_string_lossy())),
        None => Ok(format!("{} removed", names.len())),
    }
}

/// Whether a debugger traces this process (`PROC_FLAG_TRACED` of
/// `proc_bsdinfo`, `sys/proc_info.h`).
fn traced() -> Result<bool, String> {
    const PROC_FLAG_TRACED: u32 = 2;
    // SAFETY: zeroed plain-old-data struct.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: the buffer is one proc_bsdinfo.
    let got = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if got != size {
        return Err(format!(
            "proc_pidinfo(PROC_PIDTBSDINFO): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(info.pbi_flags & PROC_FLAG_TRACED != 0)
}

/// `PT_DENY_ATTACH`: no debugger can attach to the kernel process from now
/// on. A process that is already traced would be killed by it, so it is
/// skipped then.
fn deny_debugger() -> Result<String, String> {
    if traced()? {
        return Err("a debugger traces the kernel process".into());
    }
    // SAFETY: plain ptrace request with no pointers.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        return Err(format!("ptrace: {}", io::Error::last_os_error()));
    }
    Ok(String::new())
}

type SandboxInit = unsafe extern "C" fn(
    profile: *const c_char,
    flags: u64,
    parameters: *const *const c_char,
    errorbuf: *mut *mut c_char,
) -> c_int;
type SandboxFreeError = unsafe extern "C" fn(errorbuf: *mut c_char);

/// A function of libsystem_sandbox (part of libSystem), looked up when it
/// is needed: `sandbox_init_with_parameters` is not in the SDK's headers
/// (only the deprecated named-profile `sandbox_init` is, see README), and
/// a build that linked it directly would not even start on a macOS that
/// dropped it; this way `--sandbox require` refuses to start there instead.
fn lookup(name: &CStr) -> Result<*mut std::ffi::c_void, String> {
    // SAFETY: dlsym with a valid C string.
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if sym.is_null() {
        return Err(format!("{} is not in libSystem", name.to_string_lossy()));
    }
    Ok(sym)
}

/// Enters the Seatbelt sandbox `profile` with `params` (pairs of name and
/// value).
pub fn enter(profile: &str, params: &[(&str, &[u8])]) -> Result<(), String> {
    let profile = CString::new(profile).map_err(|_| "NUL in the profile".to_string())?;
    let mut owned = Vec::with_capacity(params.len() * 2);
    for (name, value) in params {
        owned.push(CString::new(*name).map_err(|_| "NUL in a parameter name".to_string())?);
        owned.push(
            CString::new(value.to_vec()).map_err(|_| "NUL in a parameter value".to_string())?,
        );
    }
    let mut ptrs: Vec<*const c_char> = owned.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: the symbols have these C signatures (libsystem_sandbox).
    let (init, free_error) = unsafe {
        (
            std::mem::transmute::<*mut std::ffi::c_void, SandboxInit>(lookup(
                c"sandbox_init_with_parameters",
            )?),
            std::mem::transmute::<*mut std::ffi::c_void, SandboxFreeError>(lookup(
                c"sandbox_free_error",
            )?),
        )
    };
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings and a NULL-terminated array that
    // outlive the call; `error` is freed with sandbox_free_error.
    let ret = unsafe { init(profile.as_ptr(), 0, ptrs.as_ptr(), &mut error) };
    if ret == 0 {
        return Ok(());
    }
    let message = if error.is_null() {
        io::Error::last_os_error().to_string()
    } else {
        // SAFETY: sandbox_init_with_parameters set it to a C string.
        let text = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .trim()
            .to_string();
        // SAFETY: allocated by sandbox_init_with_parameters.
        unsafe { free_error(error) };
        text
    };
    Err(format!("sandbox_init_with_parameters: {message}"))
}

/// Checks from inside that a profile is in force: `/` cannot be opened.
/// This shows that the sandbox was entered, no more: the profile denies
/// `/` with a rule of its own (so that the check is not reported), so it
/// does not show that everything else is denied by default. What the
/// profile allows is pinned by the tests of `seatbelt`, and what it
/// refuses in a running process by `hellovm/tests/hvf_hardening.rs`.
fn verify() -> Result<(), String> {
    // SAFETY: open with a valid C string.
    let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd >= 0 {
        // SAFETY: the fd just opened.
        unsafe { libc::close(fd) };
        return Err("the sandbox was entered but / can still be opened".into());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EPERM) {
        return Err(format!("opening / outside the image: {err}, not EPERM"));
    }
    Ok(())
}

fn seatbelt(config: &Config<'_>) -> Result<String, String> {
    let image = config.image_path.as_os_str().as_bytes();
    if image == b"/" {
        return Err("the image is the host's root directory".into());
    }
    if !config.image_path.is_absolute() {
        return Err("the image path is not absolute".into());
    }
    let kind = if config.learn {
        crate::seatbelt::Kind::Learn
    } else {
        crate::seatbelt::Kind::Enforce
    };
    let mut params: Vec<(&str, &[u8])> = vec![("IMAGE", image)];
    if let Some(egress) = config.egress {
        if !egress.is_absolute() {
            return Err("the egress socket path is not absolute".into());
        }
        params.push(("EGRESS", egress.as_os_str().as_bytes()));
    }
    let mut text = profile(kind, config.egress.is_some());
    if config.broken {
        text.push_str("(this-is-not-an-operation)");
    }
    enter(&text, &params)?;
    if config.learn {
        return Ok("LEARNING: denied system calls fail instead of killing".into());
    }
    verify()?;
    Ok(format!("{} rules", crate::seatbelt::rule_count(&text)))
}

/// Applies every layer; see the crate documentation. Call it once the
/// image directory, the VM and its vCPUs, stdio and the terminal are set
/// up and before the kernel reads any guest input, while the only other
/// threads are the HVF platform's vCPU threads and, with an egress
/// socket, the outbound streams' I/O thread, which wait and read no
/// environment.
pub fn apply(config: Config<'_>) -> Result<Report, Refused> {
    let mut report = Report::default();
    let layers = [
        Layer::Fds,
        Layer::Limits,
        Layer::Environment,
        Layer::NoDebugger,
        Layer::Seatbelt,
    ];
    if config.mode == Mode::Off {
        for layer in layers {
            report.push(layer, Err("--sandbox=off".into()));
        }
        return Ok(report);
    }
    report.push(
        Layer::Fds,
        config.fds.clone().map(|n| format!("{n} closed")),
    );
    report.push(Layer::Limits, apply_limits());
    report.push(Layer::Environment, clear_environment());
    report.push(Layer::NoDebugger, deny_debugger());
    report.push(Layer::Seatbelt, seatbelt(&config));
    report.log();
    if config.mode == Mode::Require && layers.iter().any(|&l| !report.active(l)) {
        return Err(Refused(report));
    }
    Ok(report)
}
