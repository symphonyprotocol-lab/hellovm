//! What the proxy asks the host kernel directly: who is on the other end
//! of a flow's Unix socket, and that no other process may look into this
//! one. This is the crate's only `unsafe` code.
#![allow(unsafe_code)]

use std::os::unix::net::UnixStream;

/// The process id of the peer of `sock` (`SO_PEERCRED` on Linux,
/// `LOCAL_PEERPID` on macOS), or `None` where the host does not provide it.
pub fn peer_pid(sock: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: SO_PEERCRED writes one `ucred` of the size passed.
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ret = libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            );
            (ret == 0 && cred.pid > 0).then_some(cred.pid as u32)
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: LOCAL_PEERPID writes one pid_t of the size passed.
        let ret = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        (ret == 0 && pid > 0).then_some(pid as u32)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = sock;
        None
    }
}

/// Makes this process non-dumpable and its core dumps empty: no other
/// process of the same user can then attach to it with `ptrace` or read or
/// write its memory (`process_vm_writev`, `/proc/<pid>/mem`), and its
/// memory (the allowlist, tenants' bytes in transit) never lands in a core
/// file. A sandbox's kernel process runs as the same user by default, and
/// the allowlist it must not be able to change lives here. On macOS: no
/// core dumps and `PT_DENY_ATTACH` (no debugger can attach, and getting
/// the task port of another process takes root or a debugger entitlement
/// there anyway); a proxy already traced is left traceable.
pub fn seal_process() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: prctl with integer arguments; setrlimit with a valid struct.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::setrlimit(libc::RLIMIT_CORE, &none) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with a valid struct.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // A process that is already traced would be killed by it.
        if !traced()? {
            // SAFETY: plain ptrace request with no pointers.
            if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// When process `pid` started, in microseconds since the epoch (macOS:
/// `pbi_start_tvsec` and `pbi_start_tvusec` of `proc_bsdinfo`).
#[cfg(target_os = "macos")]
pub fn start_micros(pid: u32) -> Option<u64> {
    let info = bsdinfo(i32::try_from(pid).ok()?).ok()?;
    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

#[cfg(target_os = "macos")]
fn bsdinfo(pid: libc::pid_t) -> std::io::Result<libc::proc_bsdinfo> {
    // SAFETY: zeroed plain-old-data struct.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is one proc_bsdinfo.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if got != size {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info)
}

/// Whether a debugger traces this process (`PROC_FLAG_TRACED` of
/// `proc_bsdinfo`, `sys/proc_info.h`).
#[cfg(target_os = "macos")]
fn traced() -> std::io::Result<bool> {
    const PROC_FLAG_TRACED: u32 = 2;
    // SAFETY: getpid has no preconditions.
    let info = bsdinfo(unsafe { libc::getpid() })?;
    Ok(info.pbi_flags & PROC_FLAG_TRACED != 0)
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn the_peer_is_this_process() {
        let dir = std::env::temp_dir().join(format!("hellovm-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (conn, _) = listener.accept().unwrap();
        let pid = super::peer_pid(&conn).unwrap();
        assert_eq!(pid, std::process::id());
        // The usage key of a process: stable, and not that of another.
        let start = super::start_micros(pid).unwrap();
        assert_eq!(super::start_micros(pid), Some(start));
        assert_ne!(super::start_micros(1), Some(start));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn a_sealed_process_is_not_dumpable() {
        super::seal_process().unwrap();
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }
}
