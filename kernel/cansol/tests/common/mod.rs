//! Helpers shared by the end-to-end tests: temporary image directories and
//! running a program from one under the seccomp platform.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use cansol_core::{ExitStatus, Kernel, KernelError};
use cansol_host::{CaptureHost, ImageDir};
use cansol_platform_seccomp::SeccompApp;

/// A directory under the system temp dir, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("cansol-test-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file (creating parent directories).
    pub fn write(&self, rel: &str, data: &[u8]) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    /// Copies a host executable into the image at `rel`.
    pub fn install(&self, host_path: &str, rel: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::copy(host_path, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    pub fn symlink(&self, target: &str, rel: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    pub fn mkdir(&self, rel: &str) {
        fs::create_dir_all(self.0.join(rel)).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The outcome of running a program.
pub struct Run {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub kernel: Kernel<CaptureHost>,
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Run")
            .field("status", &self.status)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

/// Runs `argv` (argv[0] is the path inside the sandbox) with `image` as the
/// root, `stdin` as console input and a trace.
pub fn try_run(image: &Path, argv: &[&str], stdin: &[u8]) -> Result<Run, KernelError> {
    let mut host = CaptureHost::new(Some(ImageDir::open(image).unwrap()));
    host.stdin.extend(stdin);
    let mut kernel = Kernel::new(host).with_trace();
    let mut app = SeccompApp::new().expect("start the app process");
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
    let envp = vec![b"PATH=/bin".to_vec(), b"HOME=/".to_vec()];
    kernel.exec(&mut app, &argv[0], &argv, &envp)?;
    let status = kernel.run(&mut app)?;
    let host = kernel.host();
    Ok(Run {
        status,
        stdout: String::from_utf8_lossy(&host.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&host.stderr).into_owned(),
        kernel,
    })
}

pub fn run(image: &Path, argv: &[&str]) -> Run {
    try_run(image, argv, b"").unwrap_or_else(|err| panic!("{argv:?}: {err}"))
}
