//! `hellovm --clone SOCKET`: the requester's side of a warm clone (Linux
//! and macOS alike).

use std::io;
use std::os::fd::AsFd;
use std::path::Path;

use hellovm::warm::{self, Status};

/// `hellovm --clone SOCKET`: asks the template for a clone with this
/// process's stdio as its console, waits for it and returns its exit code
/// (125 when it could not be made, 124 after `--timeout`).
pub fn client(
    socket: &Path,
    sandbox_id: Option<u64>,
    input: &[u8],
    ready: bool,
    timeout: Option<std::time::Duration>,
) -> u8 {
    if ready {
        return match warm::wait_ready(socket) {
            Ok((stored, areas)) => {
                eprintln!("hellovm: template ready: {stored} bytes in {areas} areas");
                0
            }
            Err(err) => {
                eprintln!("hellovm: {}: {err}", socket.display());
                125
            }
        };
    }
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    let stdio = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
    let result = warm::WarmClone::request(socket, sandbox_id, input, stdio).and_then(|mut c| {
        c.stream().set_read_timeout(timeout)?;
        let started = c.start()?;
        log::info!("clone {:016x} runs", started.sandbox_id);
        c.wait()
    });
    match result {
        Ok(status) => {
            if let Status::Signaled(sig) = status {
                eprintln!("hellovm: program killed by signal {sig}");
            }
            status.code()
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            eprintln!("hellovm: clone timed out after {timeout:?}");
            crate::EXIT_TIMEOUT
        }
        Err(err) => {
            eprintln!("hellovm: {}: {err}", socket.display());
            125
        }
    }
}
