//! A user, mount, network and IPC namespace for the kernel process.
//!
//! * user: needed to create the others without privileges. The kernel
//!   process keeps its host uid and gid (mapped to themselves), and drops
//!   every capability it gets in the new namespace once the rest is set up.
//! * mount: the root becomes an empty, read-only tmpfs with two bind
//!   mounts in it: the image directory at `/image`, and the directory
//!   that holds the egress socket, if any, at `/egress`. The old root is
//!   detached and every fd into it is dropped, so no host path outside
//!   those two directories can be named any more, not even with `..` from
//!   a directory fd: the kernel process serves the image from an fd opened
//!   at `/image`, whose parent is the empty root.
//!   The socket's directory is bound, not the socket: a proxy that is
//!   restarted makes a new socket at the same path, and kernel processes
//!   already running must reach it. Everything else in that directory is
//!   visible to the kernel process too, so the socket belongs in a
//!   directory of its own (see README). A directory that does not exist at
//!   start-up is not bound: flows are refused, as with no proxy.
//! * network: only a loopback interface, which is down. Pathname Unix
//!   sockets (the egress socket) still work across network namespaces;
//!   abstract Unix sockets of the host do not.
//! * IPC: no SysV IPC or POSIX message queues shared with the host.
//!
//! Hosts refuse this in two ways. `unshare(CLONE_NEWUSER)` itself fails
//! under Docker's default seccomp profile and where unprivileged user
//! namespaces are disabled. Ubuntu 24.04 and later (AppArmor's
//! `restrict_unprivileged_userns`) let `unshare` succeed and then deny
//! every capability in the new namespace, so a later step fails. A
//! process cannot leave a user namespace again, so [`enter`] first runs
//! the whole sequence in a forked child: when the child cannot finish,
//! the layer is skipped with the child's reason and this process is
//! untouched. Only a failure after a successful rehearsal leaves the
//! process half-confined, and that one is fatal.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Where the image directory appears inside the new root.
const IMAGE_INSIDE: &str = "/image";
/// Where the egress socket's directory appears inside the new root.
const EGRESS_INSIDE: &str = "/egress";

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
    /// A step failed although the rehearsal went through: the process is
    /// in half-built namespaces and must not go on.
    Failed(String),
}

/// What [`enter`] set up.
#[derive(Debug)]
pub struct Entered {
    pub net: bool,
    /// The image directory, opened inside the new root.
    pub image: OwnedFd,
    /// The egress socket's path inside the new root; `None` when its
    /// directory did not exist.
    pub egress: Option<PathBuf>,
}

/// Enters the namespaces and switches to the new root. `image` and
/// `egress` are absolute host paths (the image directory and the egress
/// socket). With `keep_net`, the network namespace is not created (the
/// `--splice-to` test hook needs the host's loopback).
pub fn enter(image: &Path, egress: Option<&Path>, keep_net: bool) -> Result<Entered, NsError> {
    // SAFETY: plain syscalls.
    let ids = unsafe { (libc::getuid(), libc::getgid()) };
    rehearse(image, egress, keep_net, ids).map_err(NsError::Unavailable)?;
    unshare(keep_net).map_err(NsError::Unavailable)?;
    build(image, egress, keep_net, ids).map_err(NsError::Failed)
}

/// Runs [`unshare`] and [`build`] in a forked child and reports how it
/// went; see the module documentation.
fn rehearse(
    image: &Path,
    egress: Option<&Path>,
    keep_net: bool,
    ids: (libc::uid_t, libc::gid_t),
) -> Result<(), String> {
    let mut pipe = [0; 2];
    // SAFETY: valid array for two fds.
    check("pipe2", unsafe {
        libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC)
    })?;
    // SAFETY: new fds we own.
    let (reader, writer) = unsafe {
        (
            std::fs::File::from(OwnedFd::from_raw_fd(pipe[0])),
            std::fs::File::from(OwnedFd::from_raw_fd(pipe[1])),
        )
    };
    // SAFETY: the process is single-threaded (unshare(CLONE_NEWUSER)
    // needs that anyway), so the child may run ordinary code. It leaves
    // with _exit: no destructor or stdio buffer of the parent runs twice.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork: {}", io::Error::last_os_error())),
        0 => {
            drop(reader);
            let result = unshare(keep_net).and_then(|()| build(image, egress, keep_net, ids));
            if let Err(reason) = result {
                use std::io::Write;
                let _ = (&writer).write_all(reason.as_bytes());
                // SAFETY: see above.
                unsafe { libc::_exit(1) };
            }
            // SAFETY: see above.
            unsafe { libc::_exit(0) }
        }
        child => {
            drop(writer);
            let mut reason = String::new();
            let _ = io::Read::read_to_string(&mut &reader, &mut reason);
            let mut status = 0;
            // SAFETY: our own child; valid out pointer.
            while unsafe { libc::waitpid(child, &mut status, 0) } == -1
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
            match (status, reason.is_empty()) {
                (0, true) => Ok(()),
                (_, false) => Err(reason),
                (_, true) => Err(format!("the rehearsal ended with wait status {status:#x}")),
            }
        }
    }
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

fn open_dir(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map(OwnedFd::from)
}

/// Bind-mounts the directory behind `source` on `target`, with everything
/// mounted below it: a mount namespace owned by a new user namespace may
/// not separate a mount from the ones it inherited underneath. The source
/// is named as the working directory, not through `/proc/self/fd`, which
/// the new root's mount may already hide.
fn bind(what: &str, source: &OwnedFd, target: &Path) -> Result<(), String> {
    std::fs::create_dir(target).map_err(|err| format!("mkdir {}: {err}", target.display()))?;
    // SAFETY: a valid fd and valid C strings.
    unsafe {
        check(what, libc::fchdir(source.as_raw_fd()))?;
        check(
            what,
            libc::mount(
                c".".as_ptr(),
                c(target).as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            ),
        )
    }
}

fn build(
    image: &Path,
    egress: Option<&Path>,
    keep_net: bool,
    (uid, gid): (libc::uid_t, libc::gid_t),
) -> Result<Entered, String> {
    // Opened in the new mount namespace (a bind mount refuses a source
    // from another one) and before the new root is mounted, so that its
    // mount cannot hide these paths.
    let image_outside = open_dir(image, libc::O_PATH)
        .map_err(|err| format!("opening the image {}: {err}", image.display()))?;
    let egress_outside = egress.and_then(|path| {
        let name = path.file_name()?;
        let dir = open_dir(path.parent()?, libc::O_PATH).ok()?;
        Some((dir, name))
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
    // With the host's `/` as the image, the new root's mount shows up in
    // the image at that directory; `/proc`, `/sys` and `/dev` come first
    // because the sandbox never sees the image's (it has its own).
    let mountpoint = ["/proc", "/sys", "/dev", "/mnt", "/tmp", "/"]
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
    let inside = |path: &str| mountpoint.join(path.trim_start_matches('/'));
    let old = inside("old");
    std::fs::create_dir(&old).map_err(|err| format!("mkdir {}: {err}", old.display()))?;
    bind(
        "bind-mounting the image",
        &image_outside,
        &inside(IMAGE_INSIDE),
    )?;
    let mut egress_inside = None;
    if let Some((dir, name)) = &egress_outside {
        bind(
            "bind-mounting the egress socket's directory",
            dir,
            &inside(EGRESS_INSIDE),
        )?;
        egress_inside = Some(Path::new(EGRESS_INSIDE).join(name));
    }
    drop((image_outside, egress_outside));
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
    let image = open_dir(Path::new(IMAGE_INSIDE), libc::O_RDONLY)
        .map_err(|err| format!("opening the image in the new root: {err}"))?;
    drop_capabilities()?;
    Ok(Entered {
        net: !keep_net,
        image,
        egress: egress_inside,
    })
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
