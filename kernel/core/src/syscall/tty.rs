//! Terminal syscalls: reads, writes and `ioctl`s on the sandbox terminal
//! (see `crate::tty` for the line discipline).
//!
//! Job control follows Linux: a process in the terminal's session but not
//! in its foreground group that reads from it gets `SIGTTIN` for its group
//! (or `EIO` if it ignores or blocks that), and with `TOSTOP` writes get
//! `SIGTTOU`.

use std::time::Duration;

use crate::errno::{Errno, SysResult, EAGAIN, EINVAL, EIO, ENOTTY, EPERM};
use crate::fd::FileId;
use crate::host::{ConsoleStream, Host};
use crate::platform::{GuestAddr, Platform};
use crate::signal::{bit, SigInfo, SIGTTIN, SIGTTOU, SIGWINCH, SIG_IGN};
use crate::task::{Pid, Restart, State};
use crate::tty::{Termios, Tty, TOSTOP, VMIN, VTIME};

use super::Ctx;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TCXONC: u64 = 0x540a;
const TCFLSH: u64 = 0x540b;
const TIOCSCTTY: u64 = 0x540e;
const TIOCGPGRP: u64 = 0x540f;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCSTI: u64 = 0x5412;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;

/// Sends `sig` from the terminal to every process of group `pgid`.
pub(crate) fn signal_group(st: &mut State, pgid: Pid, sig: u32) {
    for pid in st.group(pgid) {
        st.post_signal(pid, None, SigInfo::kernel(sig));
    }
}

/// Pulls host input through the terminal and sends the signals it raised
/// to the foreground group.
pub(crate) fn pull_terminal_input<H: Host + ?Sized>(st: &mut State, host: &mut H) {
    let signals = st.console.fill(host);
    if signals.is_empty() {
        return;
    }
    if let Some(fg) = st.console.foreground() {
        for sig in signals {
            signal_group(st, fg, sig);
        }
    }
    st.changed = true;
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    fn tty(&mut self) -> SysResult<&mut Tty> {
        self.st.console.tty.as_mut().ok_or(Errno(ENOTTY))
    }

    /// Whether this process is a background job of the terminal's session.
    fn in_background(&self) -> bool {
        let proc = self.proc();
        let console = &self.st.console;
        console.session() == Some(proc.sid) && console.foreground() != Some(proc.pgid)
    }

    /// For a background job: `Err(EIO)` if `sig` is ignored or blocked,
    /// else sends it to the job and parks the thread (the stop takes
    /// effect; the syscall is restarted when the job continues).
    fn background_signal(&mut self, sig: u32) -> SysResult<()> {
        let ignored = self.proc().action(sig).handler == SIG_IGN
            || self.st.thread(self.tid).sigmask & bit(sig) != 0;
        if ignored {
            return Err(Errno(EIO));
        }
        let pgid = self.proc().pgid;
        signal_group(self.st, pgid, sig);
        Err(self.park_retry(None, Restart::IfSaRestart))
    }

    pub(crate) fn tty_read(&mut self, id: FileId, len: usize) -> SysResult<Vec<u8>> {
        pull_terminal_input(self.st, self.host);
        if self.in_background() {
            self.background_signal(SIGTTIN)?;
        }
        let nonblock = self.st.files.get(id).nonblock;
        let hung_up = self.st.console.hung_up();
        let tty = self.tty()?;
        let termios = tty.termios;
        match tty.take(len) {
            None => Ok(Vec::new()),
            Some(data) if !data.is_empty() => Ok(data),
            Some(_) if hung_up => Ok(Vec::new()),
            Some(_) if !termios.canonical() && termios.cc[VMIN] == 0 => {
                let vtime = termios.cc[VTIME];
                if vtime == 0 || self.timed_out() {
                    Ok(Vec::new())
                } else {
                    let timeout = Duration::from_millis(u64::from(vtime) * 100);
                    Err(self.park_retry(Some(timeout), Restart::IfSaRestart))
                }
            }
            Some(_) if nonblock => Err(Errno(EAGAIN)),
            Some(_) => Err(self.park_retry(None, Restart::IfSaRestart)),
        }
    }

    pub(crate) fn tty_write(&mut self, data: &[u8]) -> SysResult<usize> {
        let tostop = self.tty()?.termios.lflag & TOSTOP != 0;
        if tostop && self.in_background() {
            self.background_signal(SIGTTOU)?;
        }
        let out = self.tty()?.output(data);
        self.console_write(ConsoleStream::Stdout, &out)?;
        Ok(data.len())
    }

    /// Bytes a read would return now.
    pub(crate) fn tty_readable(&mut self) -> usize {
        pull_terminal_input(self.st, self.host);
        self.st.console.buffered()
    }

    /// Whether a read would return end of file now.
    pub(crate) fn tty_hung_up(&mut self) -> bool {
        self.st.console.hung_up() || self.st.console.tty.as_ref().is_some_and(Tty::has_eof)
    }

    /// The process group of this terminal's session that `pgid` names, if
    /// the caller may make it the foreground group.
    fn check_session(&self) -> SysResult<Pid> {
        let sid = self.proc().sid;
        if self.st.console.session() != Some(sid) {
            return Err(Errno(ENOTTY));
        }
        Ok(sid)
    }

    pub(crate) fn tty_ioctl(&mut self, request: u64, arg: GuestAddr) -> SysResult<u64> {
        match request {
            TCGETS => {
                let termios = self.tty()?.termios.encode();
                self.write_mem(arg, &termios)?;
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                let termios = Termios::decode(&self.read_array(arg)?);
                let tty = self.tty()?;
                if request == TCSETSF {
                    tty.flush_input();
                }
                tty.set_termios(termios);
                self.st.changed = true;
                Ok(0)
            }
            TIOCGWINSZ => {
                let tty = self.tty()?;
                let mut ws = [0u8; 8];
                ws[0..2].copy_from_slice(&tty.rows.to_le_bytes());
                ws[2..4].copy_from_slice(&tty.cols.to_le_bytes());
                self.write_mem(arg, &ws)?;
                Ok(0)
            }
            TIOCSWINSZ => {
                let ws: [u8; 8] = self.read_array(arg)?;
                let rows = u16::from_le_bytes([ws[0], ws[1]]);
                let cols = u16::from_le_bytes([ws[2], ws[3]]);
                set_window_size(self.st, rows, cols);
                Ok(0)
            }
            TIOCGPGRP => {
                self.check_session()?;
                let fg = self.st.console.foreground().unwrap_or(0);
                self.write_u32(arg, fg)?;
                Ok(0)
            }
            TIOCSPGRP => {
                let sid = self.check_session()?;
                let pgid = self.read_u32(arg)? as i32;
                if pgid < 0 {
                    return Err(Errno(EINVAL));
                }
                let pgid = pgid as Pid;
                let exists = self
                    .st
                    .procs
                    .values()
                    .any(|p| p.pgid == pgid && p.sid == sid && p.alive());
                if !exists {
                    return Err(Errno(EPERM));
                }
                self.tty()?.foreground = Some(pgid);
                self.st.changed = true;
                Ok(0)
            }
            TIOCGSID => {
                let sid = self.st.console.session().ok_or(Errno(ENOTTY))?;
                self.write_u32(arg, sid)?;
                Ok(0)
            }
            TIOCSCTTY => {
                let proc = self.proc();
                let (pid, sid, pgid) = (proc.pid, proc.sid, proc.pgid);
                let tty = self.tty()?;
                if tty.session == Some(sid) {
                    return Ok(0);
                }
                if pid != sid || tty.session.is_some() {
                    return Err(Errno(EPERM));
                }
                tty.session = Some(sid);
                tty.foreground = Some(pgid);
                Ok(0)
            }
            TIOCNOTTY => {
                let sid = self.check_session()?;
                if self.pid == sid {
                    self.st.console.session_left(sid);
                }
                Ok(0)
            }
            TCFLSH => {
                if arg == 0 || arg == 2 {
                    self.tty()?.flush_input();
                }
                Ok(0)
            }
            TIOCOUTQ => {
                self.write_u32(arg, 0)?;
                Ok(0)
            }
            TCSBRK | TCXONC => Ok(0),
            // Faking input on a terminal is refused, as Linux does without
            // CAP_SYS_ADMIN since 6.2.
            TIOCSTI => Err(Errno(EPERM)),
            other => {
                log::debug!("unimplemented terminal ioctl {other:#x}");
                Err(Errno(ENOTTY))
            }
        }
    }
}

/// Changes the terminal's window size and tells the foreground group.
pub(crate) fn set_window_size(st: &mut State, rows: u16, cols: u16) {
    let Some(tty) = st.console.tty.as_mut() else {
        return;
    };
    if (tty.rows, tty.cols) == (rows, cols) {
        return;
    }
    tty.rows = rows;
    tty.cols = cols;
    if let Some(fg) = tty.foreground {
        signal_group(st, fg, SIGWINCH);
    }
    st.changed = true;
}
