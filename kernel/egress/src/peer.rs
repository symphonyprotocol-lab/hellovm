//! Who is on the other end of a flow's Unix socket, as the host kernel
//! reports it. This is the crate's only `unsafe` code.
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
