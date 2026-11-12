//! Terminal syscalls: reads, writes and `ioctl`s on the sandbox terminal.

use crate::errno::{Errno, SysResult, EAGAIN, ENOTTY};
use crate::fd::FileId;
use crate::host::{ConsoleStream, Host};
use crate::platform::Platform;
use crate::task::Restart;
use crate::tty::InputState;

use super::Ctx;

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    pub(crate) fn tty_read(&mut self, id: FileId, len: usize) -> SysResult<Vec<u8>> {
        let nonblock = self.st.files.get(id).nonblock;
        match self.st.console.input_state(self.host) {
            InputState::Ready => Ok(self.st.console.take_input(len)),
            InputState::Eof => Ok(Vec::new()),
            InputState::Empty if nonblock => Err(Errno(EAGAIN)),
            InputState::Empty => Err(self.park_retry(None, Restart::IfSaRestart)),
        }
    }

    pub(crate) fn tty_write(&mut self, data: &[u8]) -> SysResult<usize> {
        self.console_write(ConsoleStream::Stdout, data)
    }

    /// Bytes a read would return now.
    pub(crate) fn tty_readable(&mut self) -> usize {
        self.st.console.fill(self.host);
        self.st.console.buffered()
    }

    /// Whether the terminal's input has ended.
    pub(crate) fn tty_hung_up(&mut self) -> bool {
        self.st.console.input_state(self.host) == InputState::Eof
    }

    pub(crate) fn tty_ioctl(&mut self, _request: u64, _arg: u64) -> SysResult<u64> {
        Err(Errno(ENOTTY))
    }
}
