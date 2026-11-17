//! The kernel process's own hardening (`hellovm-sandbox`), tested from
//! inside: `--insecure-fence-test` makes the hardened kernel process try
//! what a compromised one would, and each attempt must be refused or kill
//! it. `--sandbox off` runs the same attempts as a control, so a test
//! cannot pass because the attempt itself is broken.
//!
//! What every one of the other end-to-end tests shows is the other half:
//! they all run in hardened kernel processes (`common::Session`, or the
//! binary with its default `--sandbox best-effort`).

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Output};

    use super::common::{require_guest, TempDir};
    use hellovm_test_guest as guest;

    const SIGSYS: i32 = 31;

    fn hellovm(sandbox: &str, args: &[&str]) -> Output {
        let image = TempDir::new("fence");
        Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .env("HELLOVM_LOG", "debug")
            .arg("--sandbox")
            .arg(sandbox)
            .arg("--root")
            .arg(image.path())
            .args(args)
            .output()
            .expect("run hellovm")
    }

    fn fence(sandbox: &str, test: &str) -> Output {
        hellovm(sandbox, &["--insecure-fence-test", test])
    }

    /// The same with Landlock left out, at the default log level: what the
    /// other layers hold on their own, and what an operator would see.
    fn fence_without_landlock(test: &str) -> Output {
        let image = TempDir::new("fence");
        Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .env("HELLOVM_TEST_NO_LANDLOCK", "1")
            .env_remove("HELLOVM_LOG")
            .args(["--sandbox", "best-effort", "--root"])
            .arg(image.path())
            .args(["--insecure-fence-test", test])
            .output()
            .expect("run hellovm")
    }

    const UNCONFINED: &str = "neither namespaces nor Landlock are available";

    fn describe(out: &Output) -> String {
        format!(
            "status {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Refused (the hook reports it and exits 0) or killed by seccomp.
    fn assert_fenced(out: &Output, test: &str) {
        let refused = out.status.code() == Some(0)
            && String::from_utf8_lossy(&out.stdout).contains(&format!("fence: {test}: refused"));
        let killed = out.status.signal() == Some(SIGSYS);
        assert!(
            refused || killed,
            "{test} was not fenced: {}",
            describe(out)
        );
    }

    fn assert_allowed(out: &Output, test: &str) {
        assert!(
            out.status.code() == Some(1)
                && String::from_utf8_lossy(&out.stdout)
                    .contains(&format!("fence: {test}: allowed")),
            "control run of {test}: {}",
            describe(out)
        );
    }

    #[test]
    fn host_files_are_out_of_reach() {
        assert_allowed(&fence("off", "open-host-file"), "open-host-file");
        assert_fenced(&fence("best-effort", "open-host-file"), "open-host-file");
    }

    /// The kernel process holds a directory fd of the image. `..` from it
    /// must not lead to the host's files, whichever layer confines it.
    #[test]
    fn the_image_fd_does_not_lead_above_the_image() {
        assert_allowed(&fence("off", "open-above-image"), "open-above-image");
        assert_fenced(
            &fence("best-effort", "open-above-image"),
            "open-above-image",
        );
    }

    /// Without Landlock the namespaces are the only filesystem fence. Where
    /// the host has them they must hold alone; where it has neither, the
    /// run goes on (best effort) but says so at the default log level.
    #[test]
    fn namespaces_alone_confine_or_the_gap_is_announced() {
        for test in ["open-host-file", "open-above-image"] {
            let out = fence_without_landlock(test);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains(UNCONFINED) {
                assert!(
                    stderr.contains("warn: sandbox: Landlock: skipped")
                        && stderr.contains("warn: sandbox: user/mount/network/IPC namespaces"),
                    "{}",
                    describe(&out)
                );
                assert_allowed(&out, test);
            } else {
                assert_fenced(&out, test);
            }
        }
        // With both fences this host has, nothing is announced.
        let out = Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .env_remove("HELLOVM_LOG")
            .args(["--root", "/", "--insecure-fence-test", "open-host-file"])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains(UNCONFINED),
            "{}",
            describe(&out)
        );
    }

    /// A compromised kernel process must not read or write the memory of
    /// other processes of its user (here: this test process).
    #[test]
    fn other_processes_memory_is_out_of_reach() {
        // Let any process of this user attach to the test process, so that
        // the control run works under Yama's ptrace_scope=1 too.
        // SAFETY: prctl with integer arguments.
        unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) };
        assert_allowed(&fence("off", "read-parent-memory"), "read-parent-memory");
        assert_fenced(
            &fence("best-effort", "read-parent-memory"),
            "read-parent-memory",
        );
    }

    #[test]
    fn tcp_connect_is_out_of_reach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let test = format!("tcp-connect:{}", listener.local_addr().unwrap());
        assert_allowed(&fence("off", &test), &test);
        let out = fence("best-effort", &test);
        assert_fenced(&out, &test);
        // The seccomp rule is the one that holds everywhere: AF_INET
        // sockets kill the kernel process.
        assert_eq!(out.status.signal(), Some(SIGSYS), "{}", describe(&out));
    }

    #[test]
    fn host_abstract_unix_sockets_are_out_of_reach() {
        use std::os::linux::net::SocketAddrExt;
        let addr =
            std::os::unix::net::SocketAddr::from_abstract_name(b"hellovm-fence-test").unwrap();
        let _listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
        assert_allowed(
            &fence("off", "unix-connect-abstract"),
            "unix-connect-abstract",
        );
        assert_fenced(
            &fence("best-effort", "unix-connect-abstract"),
            "unix-connect-abstract",
        );
    }

    #[test]
    fn syscalls_outside_the_allowlist_kill_the_kernel_process() {
        // Control: without the filter, setns(-1) is just EBADF.
        assert_allowed(&fence("off", "forbidden-syscall"), "forbidden-syscall");
        let out = fence("best-effort", "forbidden-syscall");
        assert_eq!(out.status.signal(), Some(SIGSYS), "{}", describe(&out));
        // An allowed syscall with an argument outside its rule, too.
        let out = fence("best-effort", "ptrace-attach");
        assert_eq!(out.status.signal(), Some(SIGSYS), "{}", describe(&out));
    }

    #[test]
    fn the_active_layers_are_logged_and_require_starts_here() {
        if !require_guest(guest::HELLO, "hello") {
            return;
        }
        let image = TempDir::new("require");
        image.install(guest::HELLO, "hello");
        let out = Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .env("HELLOVM_LOG", "debug")
            .args(["--sandbox", "require", "--root"])
            .arg(image.path())
            .arg("/hello")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        // This host (or container) has Landlock or user namespaces, as
        // every supported CI host does; see the README.
        assert_eq!(
            out.status.code(),
            Some(guest::HELLO_EXIT_CODE),
            "{}",
            describe(&out)
        );
        for layer in [
            "inherited fds closed: active",
            "resource limits: active",
            "no_new_privs: active",
            "not dumpable: active",
            "seccomp allowlist: active",
        ] {
            assert!(stderr.contains(layer), "{layer}: {stderr}");
        }
        assert!(
            stderr.contains("Landlock: active") || stderr.contains("namespaces: active"),
            "{stderr}"
        );
    }

    #[test]
    fn bad_sandbox_values_are_rejected() {
        let out = hellovm("sometimes", &["/hello"]);
        assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("expected require, best-effort or off")
        );
    }

    #[test]
    fn inherited_fds_are_closed() {
        // An fd the parent leaks into hellovm (here: a pipe without
        // close-on-exec) is closed before the kernel runs anything.
        let mut fds = [0; 2];
        // SAFETY: plain syscall with a valid array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let out = fence("best-effort", "open-host-file");
        // SAFETY: closing the fds we just created.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("inherited fds closed: active (")
                && !stderr.contains("active (0 closed)"),
            "{stderr}"
        );
    }
}
