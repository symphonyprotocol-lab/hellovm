//! What the proxy asks the host kernel directly: who is on the other end
//! of a flow's Unix socket, and that no other process may look into this
//! one. This is the crate's only `unsafe` code.
#![allow(unsafe_code)]

use std::os::unix::net::UnixStream;

/// The process id of the peer of `sock` (`SO_PEERCRED`), or `None` where
/// the host does not provide it.
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
    #[cfg(not(target_os = "linux"))]
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
/// the allowlist it must not be able to change lives here.
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
    Ok(())
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
