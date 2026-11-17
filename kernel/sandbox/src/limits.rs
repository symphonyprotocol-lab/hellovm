//! Resource limits on the kernel process (inherited by its app processes,
//! which are forked from it).
//!
//! | Limit | Value | Why |
//! |---|---|---|
//! | `RLIMIT_CORE` | 0 | no core dump of kernel memory (other tenants' flows, guest data) |
//! | `RLIMIT_NOFILE` | 4096 | the kernel holds a pidfd per app process (at most 2048 tasks per sandbox), two fds per outbound stream (at most 512) and a few more; a bug cannot exhaust the host's file table through it |
//! | `RLIMIT_MEMLOCK` | 0 | nothing is locked into RAM |
//! | `RLIMIT_MSGQUEUE` | 0 | no POSIX message queues |
//!
//! A limit is only ever lowered, the soft one too: a host that already
//! set a tighter one keeps it. There is no `RLIMIT_AS`: the app processes
//! would inherit it, and programs that reserve address space they never
//! touch (the Go and GHC runtimes, sanitizer builds) would fail to start,
//! while it bounds virtual size, not memory in use. The kernel's in-memory
//! writable layer is bounded by the core's own limit
//! (`hellovm_core::vfs::DEFAULT_UPPER_LIMIT`), and a memory cgroup is the real
//! bound on resident memory per sandbox (an operator setting, see README).
//! `RLIMIT_NPROC` is per user across the whole host, so it is not set; the
//! core already caps a sandbox at 1024 threads and 2048 tasks.

use std::io;

pub const NOFILE: u64 = 4096;

fn lower(resource: libc::__rlimit_resource_t, value: u64) -> Result<(), String> {
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

pub fn apply() -> Result<(), String> {
    lower(libc::RLIMIT_CORE, 0)?;
    lower(libc::RLIMIT_NOFILE, NOFILE)?;
    lower(libc::RLIMIT_MEMLOCK, 0)?;
    lower(libc::RLIMIT_MSGQUEUE, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(resource: libc::__rlimit_resource_t) -> (u64, u64) {
        // SAFETY: getrlimit with a valid struct.
        unsafe {
            let mut cur: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(resource, &mut cur), 0);
            (cur.rlim_cur, cur.rlim_max)
        }
    }

    #[test]
    fn a_lower_soft_limit_is_kept() {
        // RLIMIT_MSGQUEUE: nothing in the test process depends on it.
        let (_, max) = get(libc::RLIMIT_MSGQUEUE);
        if max < 4096 {
            return;
        }
        let soft = libc::rlimit {
            rlim_cur: 1024,
            rlim_max: max,
        };
        // SAFETY: setrlimit with a valid struct.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MSGQUEUE, &soft) }, 0);
        lower(libc::RLIMIT_MSGQUEUE, 4096).unwrap();
        assert_eq!(get(libc::RLIMIT_MSGQUEUE), (1024, 4096));
        lower(libc::RLIMIT_MSGQUEUE, 512).unwrap();
        assert_eq!(get(libc::RLIMIT_MSGQUEUE), (512, 512));
    }
}
