//! Landlock: the kernel process may read the image directory and nothing
//! else on the filesystem, may not use TCP, and may not signal or reach
//! (abstract Unix sockets) processes outside its own domain.
//!
//! Raw syscalls (no crate), negotiated down to the ABI the host kernel
//! has. Rights a newer ABI added are simply not handled on an older
//! kernel; a host without Landlock (or a container that refuses the
//! syscalls) skips the layer.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const SYS_CREATE_RULESET: libc::c_long = 444;
const SYS_ADD_RULE: libc::c_long = 445;
const SYS_RESTRICT_SELF: libc::c_long = 446;
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;
const RULE_NET_PORT: libc::c_int = 2;

// Filesystem rights by ABI.
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_ABI1: u64 = (1 << 13) - 1;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;

const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C, packed)]
struct NetPort {
    allowed_access: u64,
    port: u64,
}

/// What was restricted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub abi: i64,
    /// Filesystem: only the image, read-only.
    pub fs: bool,
    /// TCP bind and connect (except `tcp_port`).
    pub net: bool,
    /// Signals and abstract Unix sockets limited to the domain.
    pub scoped: bool,
}

/// The host's Landlock ABI version, or why there is none.
pub fn abi() -> Result<i64, String> {
    // SAFETY: the version query takes no pointers.
    let abi = unsafe {
        libc::syscall(
            SYS_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ENOSYS) => "the host kernel has no Landlock".into(),
            Some(libc::EOPNOTSUPP) => "Landlock is disabled on the host".into(),
            Some(libc::EPERM) => "Landlock syscalls are refused (container seccomp profile)".into(),
            _ => format!("Landlock unavailable: {err}"),
        });
    }
    Ok(abi)
}

/// Restricts the calling thread (and every thread and process it creates
/// later) to reading `image`. `tcp_port` keeps one TCP connect port open
/// (the `--splice-to` test hook). The caller has set `PR_SET_NO_NEW_PRIVS`.
pub fn restrict(image: BorrowedFd<'_>, tcp_port: Option<u16>) -> Result<Applied, String> {
    let abi = abi()?;
    let mut fs = FS_ABI1;
    if abi >= 2 {
        fs |= FS_REFER;
    }
    if abi >= 3 {
        fs |= FS_TRUNCATE;
    }
    if abi >= 5 {
        fs |= FS_IOCTL_DEV;
    }
    let net = if abi >= 4 {
        NET_BIND_TCP | NET_CONNECT_TCP
    } else {
        0
    };
    let scoped = if abi >= 6 {
        SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
    } else {
        0
    };
    let attr = RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: net,
        scoped,
    };
    let size = match abi {
        1..=3 => 8,
        4 | 5 => 16,
        _ => std::mem::size_of::<RulesetAttr>(),
    };
    // SAFETY: `attr` is valid for `size` bytes.
    let ruleset =
        unsafe { libc::syscall(SYS_CREATE_RULESET, &attr as *const RulesetAttr, size, 0u32) };
    if ruleset < 0 {
        return Err(format!(
            "creating a Landlock ruleset: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: a new fd we own.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset as i32) };
    let rule = PathBeneath {
        allowed_access: FS_READ_FILE | FS_READ_DIR,
        parent_fd: image.as_raw_fd(),
    };
    // SAFETY: valid rule for the duration of the call.
    if unsafe {
        libc::syscall(
            SYS_ADD_RULE,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &rule as *const PathBeneath,
            0u32,
        )
    } != 0
    {
        return Err(format!(
            "adding the image to the Landlock ruleset: {}",
            io::Error::last_os_error()
        ));
    }
    if let (Some(port), true) = (tcp_port, net != 0) {
        let rule = NetPort {
            allowed_access: NET_CONNECT_TCP,
            port: port.into(),
        };
        // SAFETY: valid rule for the duration of the call.
        if unsafe {
            libc::syscall(
                SYS_ADD_RULE,
                ruleset.as_raw_fd(),
                RULE_NET_PORT,
                &rule as *const NetPort,
                0u32,
            )
        } != 0
        {
            return Err(format!(
                "adding a TCP port to the Landlock ruleset: {}",
                io::Error::last_os_error()
            ));
        }
    }
    // SAFETY: plain syscall on our ruleset fd.
    if unsafe { libc::syscall(SYS_RESTRICT_SELF, ruleset.as_raw_fd(), 0u32) } != 0 {
        return Err(format!(
            "enforcing the Landlock ruleset: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(Applied {
        abi,
        fs: true,
        net: net != 0,
        scoped: scoped != 0,
    })
}

/// Puts the calling process into a new Landlock domain nested in its
/// current one, restricting nothing more on the filesystem than the
/// current one does (no rule needs adding, so no path is named). What it
/// adds is the domain boundary itself: Landlock refuses ptrace-level
/// access (attach, `process_vm_*`) from a domain to a process that is not
/// in it or below it, and with ABI 6 also signals and abstract Unix
/// sockets. A warm clone's kernel process calls this right after the fork,
/// before it creates its app processes: the clone's processes are then in
/// a domain of their own, which neither the template nor any other clone
/// can reach, and the clone cannot reach theirs. Returns the ABI.
pub fn nest() -> Result<i64, String> {
    let abi = abi()?;
    // Rights the current domain already denies everywhere (only reading
    // the image is allowed): handling them again changes nothing, and a
    // ruleset must handle something.
    let mut fs = FS_ABI1 & !(FS_READ_FILE | FS_READ_DIR);
    if abi >= 2 {
        fs |= FS_REFER;
    }
    let scoped = if abi >= 6 {
        SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
    } else {
        0
    };
    let attr = RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: 0,
        scoped,
    };
    let size = match abi {
        1..=3 => 8,
        4 | 5 => 16,
        _ => std::mem::size_of::<RulesetAttr>(),
    };
    // SAFETY: `attr` is valid for `size` bytes.
    let ruleset =
        unsafe { libc::syscall(SYS_CREATE_RULESET, &attr as *const RulesetAttr, size, 0u32) };
    if ruleset < 0 {
        return Err(format!(
            "creating a Landlock ruleset: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: a new fd we own.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset as i32) };
    // SAFETY: plain syscall on our ruleset fd.
    if unsafe { libc::syscall(SYS_RESTRICT_SELF, ruleset.as_raw_fd(), 0u32) } != 0 {
        return Err(format!(
            "enforcing the Landlock ruleset: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(abi)
}
