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
//!    an empty read-only tmpfs holding only the image directory and the
//!    egress socket's directory, the old one is detached, and every
//!    capability is dropped again.
//! 3. **Resource limits** (`limits`): no core dumps, at most 4096 fds.
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
//!
//! K drives its app processes with `ptrace`, `process_vm_readv`/`writev`
//! and signals, and seccomp cannot tell one process id from another. What
//! keeps a compromised K from doing the same to other processes of its
//! user: the user namespace and Landlock each refuse it any ptrace-level
//! access (attach, reading or writing memory) to a process outside, so
//! that holds wherever K is confined to the image at all. Signals are
//! different: only Landlock ABI 6 (Linux 6.12) scopes them. On an older
//! host a compromised K can still `SIGKILL` processes of its own user,
//! which is why the egress proxy should run as another user (see README).
//!
//! On macOS (`macos`, `seatbelt`) the layers are: inherited fds closed,
//! resource limits (including `RLIMIT_NPROC` 1), the environment cleared,
//! `PT_DENY_ATTACH`, and a Seatbelt profile the process enters itself:
//! reading the image is the only file access, no network, no processes,
//! no Mach IPC, and system call and Mach trap allowlists. All are required
//! for `--sandbox=require`. See README, "Hardening".

#[cfg(target_os = "linux")]
mod allowlist;
#[cfg(target_os = "linux")]
mod bpf;
#[cfg(target_os = "linux")]
mod filter;
#[cfg(target_os = "linux")]
mod harden;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(all(target_os = "linux", feature = "insecure-test-hooks"))]
mod learn;
#[cfg(target_os = "linux")]
mod limits;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod ns;
#[cfg(target_os = "macos")]
mod seatbelt;

#[cfg(target_os = "macos")]
pub use macos::{
    apply, close_inherited_fds, open_fds, profile, Config, Layer, LayerReport, Refused, Report,
};
#[cfg(target_os = "macos")]
pub use seatbelt::Kind as ProfileKind;

/// See `landlock::nest`: a nested Landlock domain for a warm clone's
/// kernel process.
#[cfg(target_os = "linux")]
pub use landlock::nest as nest_landlock_domain;

#[cfg(target_os = "linux")]
pub use harden::{
    apply, close_inherited_fds, Config, Hardened, Layer, LayerReport, Refused, Report,
};

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
