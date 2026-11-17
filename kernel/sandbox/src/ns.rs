//! A user, mount, network and IPC namespace for the kernel process.
//!
//! * user: needed to create the others without privileges. The kernel
//!   process keeps its host uid and gid (mapped to themselves), and drops
//!   every capability it gets in the new namespace once the rest is set up.
//! * mount: the root becomes an empty, read-only tmpfs. The old root is
//!   detached, so no host path can be named any more. The image stays
//!   reachable through the directory fd opened before; the egress socket,
//!   if any, is bind-mounted into the new root as `/egress.sock`. The bind
//!   pins the socket that existed at start-up: a proxy restarted later
//!   (a new socket at the same path) is reached only by kernel processes
//!   started after it, and one that was not running at start-up not at
//!   all (flows are refused, as with no proxy).
//! * network: only a loopback interface, which is down. Pathname Unix
//!   sockets (the egress socket) still work across network namespaces;
//!   abstract Unix sockets of the host do not.
//! * IPC: no SysV IPC or POSIX message queues shared with the host.
//!
//! `unshare(CLONE_NEWUSER)` needs a single-threaded process, and it is
//! refused by Docker's default seccomp profile, by kernels with
//! unprivileged user namespaces disabled and by some AppArmor policies:
//! then this layer is skipped with the reason.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Where the egress socket appears inside the new root.
pub const EGRESS_INSIDE: &str = "/egress.sock";

fn c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("no NUL in a path")
}

fn check(what: &str, ret: libc::c_int) -> Result<(), String> {
    if ret != 0 {
        return Err(format!("{what}: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn write_file(path: &str, data: &str) -> Result<(), String> {
    std::fs::write(path, data).map_err(|err| format!("writing {path}: {err}"))
}

/// Why [`enter`] did not finish.
#[derive(Debug)]
pub enum NsError {
    /// The host refused the namespaces; nothing was changed.
    Unavailable(String),
    /// A step after `unshare` failed: the process is in half-built
    /// namespaces and must not go on.
    Failed(String),
}

/// What [`enter`] set up.
#[derive(Debug, Default)]
pub struct Entered {
    pub net: bool,
    /// The egress socket's path inside the new root.
    pub egress: Option<PathBuf>,
}

/// Enters the namespaces and switches to the empty root. `egress` is the
/// host path of the egress socket. With `keep_net`, the
/// network namespace is not created (the `--splice-to` test hook needs the
/// host's loopback).
pub fn enter(egress: Option<&Path>, keep_net: bool) -> Result<Entered, NsError> {
    // SAFETY: plain syscalls.
    let ids = unsafe { (libc::getuid(), libc::getgid()) };
    unshare(keep_net).map_err(NsError::Unavailable)?;
    build(egress, keep_net, ids).map_err(NsError::Failed)
}

fn unshare(keep_net: bool) -> Result<(), String> {
    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWIPC;
    if !keep_net {
        flags |= libc::CLONE_NEWNET;
    }
    // SAFETY: plain syscall.
    if unsafe { libc::unshare(flags) } != 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM) => format!(
                "unshare(CLONE_NEWUSER) is refused ({err}): container seccomp profile, \
                 AppArmor, or unprivileged user namespaces disabled"
            ),
            Some(libc::EINVAL) => format!("unshare: {err} (the process is multi-threaded)"),
            Some(libc::ENOSPC) => format!("unshare: {err} (user namespace limit reached)"),
            _ => format!("unshare: {err}"),
        });
    }
    Ok(())
}

fn build(
    egress: Option<&Path>,
    keep_net: bool,
    (uid, gid): (libc::uid_t, libc::gid_t),
) -> Result<Entered, String> {
    // Opened in the new mount namespace (a bind mount refuses a source
    // from another one) and before the new root is mounted, so that its
    // mount cannot hide the socket's path. A socket that does not exist
    // yet (no proxy running) is not bound: flows are then refused, as
    // without the namespace.
    let socket = egress.and_then(|path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| {
                log::info!(
                    "egress socket {}: {err}; flows will be refused",
                    path.display()
                )
            })
            .ok()
    });
    write_file("/proc/self/setgroups", "deny")?;
    write_file("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
    write_file("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;

    // SAFETY: the mount calls take valid C strings or null.
    unsafe {
        check(
            "making mounts private",
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ),
        )?;
    }
    // Any existing directory serves as the mount point of the new root.
    let mountpoint = ["/tmp", "/mnt", "/dev", "/proc", "/"]
        .iter()
        .map(Path::new)
        .find(|p| p.is_dir())
        .ok_or("no directory to mount the new root on")?;
    let root = c(mountpoint);
    // SAFETY: valid C strings.
    unsafe {
        check(
            "mounting the new root",
            libc::mount(
                c"hellovm".as_ptr(),
                root.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=64k,mode=0755".as_ptr().cast(),
            ),
        )?;
    }
    let old = mountpoint.join("old");
    std::fs::create_dir(&old).map_err(|err| format!("mkdir {}: {err}", old.display()))?;
    let mut entered = Entered {
        net: !keep_net,
        egress: None,
    };
    if egress.is_some() {
        entered.egress = Some(PathBuf::from(EGRESS_INSIDE));
    }
    if let Some(socket) = &socket {
        let target = mountpoint.join(EGRESS_INSIDE.trim_start_matches('/'));
        std::fs::File::create(&target)
            .map_err(|err| format!("creating {}: {err}", target.display()))?;
        let source = PathBuf::from(format!("/proc/self/fd/{}", socket.as_raw_fd()));
        // SAFETY: valid C strings.
        unsafe {
            check(
                "bind-mounting the egress socket",
                libc::mount(
                    c(&source).as_ptr(),
                    c(&target).as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ),
            )?;
        }
    }
    drop(socket);
    // SAFETY: valid C strings; pivot_root has no libc wrapper.
    unsafe {
        check("chdir to the new root", libc::chdir(root.as_ptr()))?;
        check(
            "pivot_root",
            libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"old".as_ptr()) as libc::c_int,
        )?;
        check("chdir /", libc::chdir(c"/".as_ptr()))?;
        check(
            "detaching the old root",
            libc::umount2(c"/old".as_ptr(), libc::MNT_DETACH),
        )?;
        check("rmdir /old", libc::rmdir(c"/old".as_ptr()))?;
        check(
            "making the new root read-only",
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT
                    | libc::MS_BIND
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                std::ptr::null(),
            ),
        )?;
    }
    drop_capabilities()?;
    Ok(entered)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drops every capability (bounding, ambient, effective, permitted,
/// inheritable). In the user namespace they only ever applied to the
/// namespace's own objects; without them the process cannot change its
/// mounts or namespaces again.
fn drop_capabilities() -> Result<(), String> {
    // SAFETY: prctl and capset with valid arguments.
    unsafe {
        for cap in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                // EINVAL: past the last capability this kernel knows.
                break;
            }
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        let mut header = CapHeader {
            version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
            pid: 0,
        };
        let data = [CapData::default(); 2];
        check(
            "dropping capabilities",
            libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) as libc::c_int,
        )
    }
}
