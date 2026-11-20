//! The Seatbelt profile of the kernel process on macOS.

/// Enforce the profile, or (a test hook, to measure what it lacks) deny
/// without killing: a system call outside the allowlists fails with
/// `EPERM` instead, and every denial is reported, so one run shows more
/// than the first missing call. (`(allow default (with report))` does not
/// work for this: with it, the kernel does not check most system calls at
/// all, so they are never reported.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Enforce,
    Learn,
}

/// The rules. Each was measured (README, "Hardening", lists them with
/// the reason); everything else is denied, and a system call outside the
/// three allowlists kills the process.
const RULES: &str = r#"
;; The image: lookups walk it with openat/fstatat/readlinkat from the
;; directory fd; a missing name is a test for existence.
(allow file-read-data file-read-metadata file-test-existence
    (subpath (param "IMAGE")))
;; Listing an image directory: opendir checks the file system's flags.
(allow system-info (info-type "vfs.disk-space"))
;; fcntl(F_GETFD, F_SETFD): close-on-exec of the image fds.
(allow system-fcntl (fcntl-command F_GETFD F_SETFD))
;; Restoring the host terminal's settings at exit (tcsetattr; the window
;; size and the settings were read before the profile was entered).
(allow file-ioctl (ioctl-command TIOCSETA))
;; Naming its own threads (hellovm-stdin).
(allow process-info-setcontrol (target self))
(allow syscall-unix (syscall-number
    ;; stdio and the terminal (settings, window size)
    SYS_write SYS_ioctl
    ;; the image: reading files and directories, metadata, symlinks
    SYS_read SYS_pread SYS_fstat64 SYS_fstatat64 SYS_fstatfs64
    SYS_getdirentries64 SYS_readlinkat
    ;; memory (malloc, thread stacks)
    SYS_mmap SYS_munmap SYS_mprotect SYS_madvise
    ;; threads: the stdin reader and the --timeout watchdog
    SYS_bsdthread_create SYS_bsdthread_terminate SYS_thread_selfid
    SYS___disable_threadsignal SYS_sigaltstack
    ;; locks and condition variables between them
    SYS_psynch_cvbroad SYS_psynch_cvsignal SYS_psynch_cvwait
    SYS_ulock_wait SYS_ulock_wake))
(allow syscall-mach (machtrap-number
    ;; memory (malloc)
    MSC__kernelrpc_mach_vm_map_trap MSC__kernelrpc_mach_vm_deallocate_trap
    MSC__kernelrpc_mach_vm_protect_trap
    MSC_mach_vm_reclaim_update_kernel_accounting_trap))
"#;

/// `apply` checks that `/` cannot be opened: not worth a report.
const SELF_CHECK: &str = "(deny file-read* file-test-existence (literal \"/\") (with no-report))\n";

pub fn profile(kind: Kind) -> String {
    match kind {
        Kind::Enforce => format!(
            "(version 3)\n(deny default)\n{RULES}\n{SELF_CHECK}\
             (deny syscall-unix syscall-mach syscall-mig (with send-signal SIGKILL))\n"
        ),
        Kind::Learn => format!("(version 3)\n(deny default)\n{RULES}"),
    }
}

/// How many `allow` rules `text` has (for the log).
pub fn rule_count(text: &str) -> usize {
    text.matches("(allow ").count()
}
