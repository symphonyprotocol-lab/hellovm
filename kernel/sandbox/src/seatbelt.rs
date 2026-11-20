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
    ;; the wall clock: libc reads it from the commpage, and makes this
    ;; call when the kernel is updating it there
    SYS_gettimeofday
    ;; threads: the stdin reader and the --timeout watchdog
    SYS_bsdthread_create SYS_bsdthread_terminate SYS_thread_selfid
    SYS___disable_threadsignal SYS_sigaltstack
    ;; locks and condition variables between them
    SYS_psynch_cvbroad SYS_psynch_cvsignal SYS_psynch_cvwait
    SYS_ulock_wait SYS_ulock_wake
    ;; the platform's vCPU threads: its mutex contended, condition
    ;; variable waits that time out as another thread signals, and lock
    ;; waits with a 64-bit timeout
    SYS_psynch_mutexwait SYS_psynch_mutexdrop SYS_psynch_cvclrprepost
    SYS_ulock_wait2))
(allow syscall-mach (machtrap-number
    ;; memory (malloc)
    MSC__kernelrpc_mach_vm_map_trap MSC__kernelrpc_mach_vm_deallocate_trap
    MSC__kernelrpc_mach_vm_protect_trap
    MSC_mach_vm_reclaim_update_kernel_accounting_trap
    ;; a vCPU thread that ends (the platform's are joined when it goes):
    ;; libpthread lets go of the thread's own port rights
    MSC__kernelrpc_mach_port_mod_refs_trap MSC__kernelrpc_mach_port_destruct_trap))
"#;

/// `apply` checks that `/` cannot be opened: not worth a report. Because
/// of this rule the check passes whatever the rest of the profile says;
/// it shows that the profile was entered, not that it denies by default.
const SELF_CHECK: &str = "(deny file-read* file-test-existence (literal \"/\") (with no-report))\n";

/// A system call outside the three lists kills the process.
const KILL: &str = "(deny syscall-unix syscall-mach syscall-mig (with send-signal SIGKILL))\n";

pub fn profile(kind: Kind) -> String {
    match kind {
        Kind::Enforce => format!("(version 3)\n(deny default)\n{RULES}\n{SELF_CHECK}{KILL}"),
        Kind::Learn => format!("(version 3)\n(deny default)\n{RULES}"),
    }
}

/// How many `allow` rules `text` has (for the log).
pub fn rule_count(text: &str) -> usize {
    text.matches("(allow ").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operations of every `(allow ...)` form in `text`, in order.
    fn allowed(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        for line in text.lines() {
            let line = line.split(";;").next().unwrap_or_default();
            let Some(rest) = line.trim_start().strip_prefix("(allow ") else {
                assert!(
                    !line.contains("(allow"),
                    "an allow not at the start: {line}"
                );
                continue;
            };
            let operations = rest.split('(').next().unwrap_or_default();
            found.extend(operations.split_whitespace().map(str::to_string));
        }
        found
    }

    /// The self-check at start-up cannot tell a profile that denies by
    /// default from one that does not, so the profile is pinned here: a
    /// new rule has to be added to this list (and to the README) too.
    #[test]
    fn the_profile_allows_these_operations_and_no_others() {
        let expected = [
            "file-read-data",
            "file-read-metadata",
            "file-test-existence",
            "system-info",
            "system-fcntl",
            "file-ioctl",
            "process-info-setcontrol",
            "syscall-unix",
            "syscall-mach",
        ];
        for kind in [Kind::Enforce, Kind::Learn] {
            let text = profile(kind);
            assert_eq!(allowed(&text), expected, "{kind:?}");
            assert_eq!(rule_count(&text), 7, "{kind:?}");
            assert!(
                text.starts_with("(version 3)\n(deny default)\n"),
                "{kind:?}"
            );
            assert_eq!(text.matches("default").count(), 1, "{kind:?}");
            for never in [
                "file-write",
                "file-read*",
                "network",
                "process-fork",
                "process-exec",
                "mach-lookup",
                "mach-register",
                "iokit",
                "sysctl",
                "(allow signal",
                "syscall-mig",
                "(import",
                "(literal",
                "(regex",
            ] {
                let rules = text.replace(SELF_CHECK, "").replace(KILL, "");
                assert!(!rules.contains(never), "{kind:?}: {never}");
            }
        }
    }

    /// Files are allowed only under the image, and it is a parameter: no
    /// path is written into the profile.
    #[test]
    fn files_are_allowed_only_under_the_image() {
        let text = profile(Kind::Enforce);
        assert_eq!(text.matches("(subpath ").count(), 1);
        assert_eq!(text.matches("(subpath (param \"IMAGE\"))").count(), 1);
        assert_eq!(text.matches("(param ").count(), 1);
        let rules: String = RULES
            .lines()
            .map(|line| line.split(";;").next().unwrap_or_default())
            .collect();
        assert!(!rules.contains('/'));
    }

    /// Enforcing kills on a system call outside the lists, and the rule
    /// comes last; learning does not kill.
    #[test]
    fn only_enforcing_kills() {
        let enforce = profile(Kind::Enforce);
        assert!(enforce.ends_with(KILL));
        assert!(enforce.contains(SELF_CHECK));
        let learn = profile(Kind::Learn);
        assert!(!learn.contains("SIGKILL"));
        assert!(!learn.contains("(deny file-read*"));
    }
}
