//! File, path and fd syscalls.

use std::time::Duration;

use super::procfs::{self, ProcNode};
use crate::abi;
use crate::errno::{
    Errno, SysResult, EACCES, EAGAIN, EBADF, EEXIST, EFAULT, EINVAL, EISDIR, ELOOP, ENOENT, ENOSPC,
    ENOTDIR, ENOTTY, ENXIO, EOPNOTSUPP, EPERM, EPIPE, ESPIPE,
};
use crate::fd::{Access, FileId, FileObject, OpenFile, MAX_FDS};
use crate::host::{ConsoleStream, Host};
use crate::mm::{MAP_PRIVATE, MAP_TYPE};
use crate::pipe::{ReadResult, WriteResult, PIPE_CAPACITY};
use crate::platform::{GuestAddr, Platform};
use crate::signal::{self, SigInfo};
use crate::task::Restart;
use crate::tty::InputState;
use crate::vfs::{
    CreateTarget, Device, DirEntry, FileType, Ino, NewNode, Stat, Timespec, S_IFCHR, S_IFDIR,
    S_IFMT, S_IFREG, S_IFSOCK,
};

/// `S_IFIFO`.
const S_IFIFO: u32 = 0o010_000;

use super::{int, Ctx, AT_FDCWD, MAX_IO};

pub(crate) const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub(crate) const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_EACCESS: u64 = 0x200;

const RENAME_NOREPLACE: u64 = 1;

const F_DUPFD: i64 = 0;
const F_GETFD: i64 = 1;
const F_SETFD: i64 = 2;
const F_GETFL: i64 = 3;
const F_SETFL: i64 = 4;
const F_GETLK: i64 = 5;
const F_SETLK: i64 = 6;
const F_SETLKW: i64 = 7;
const F_OFD_GETLK: i64 = 36;
const F_OFD_SETLK: i64 = 37;
const F_OFD_SETLKW: i64 = 38;
const F_DUPFD_CLOEXEC: i64 = 1030;
const FD_CLOEXEC: u64 = 1;
const F_UNLCK: u16 = 2;

const FIONCLEX: u64 = 0x5450;
const FIOCLEX: u64 = 0x5451;
const FIONREAD: u64 = 0x541b;

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;
const POLLRDNORM: u16 = 0x40;
const POLLWRNORM: u16 = 0x100;

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `f_type` reported by `statfs` (overlayfs's magic number).
const OVERLAYFS_MAGIC: u64 = 0x794c_7630;

/// Most iovecs per call (`UIO_MAXIOV`).
const IOV_MAX: u64 = 1024;

/// What a path or fd refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Node(Ino),
    /// An fd of something that is not a node (via `AT_EMPTY_PATH` or
    /// `fstat`).
    Object(FileObject, u64),
    /// A node of `/proc`, with its inode number.
    Proc(u64, ProcNode),
}

/// A `stat` for an open object that is not a filesystem node: the console
/// (a character device; the terminal is `/dev/console`, 5:1), a pipe (a
/// FIFO on its own device, like Linux's pipefs) or a `/proc` file.
fn object_stat(object: FileObject, size: u64, time: Timespec) -> Stat {
    let (dev, ino, mode, rdev) = match object {
        FileObject::ConsoleIn => (0x05, 0x10, S_IFCHR | 0o620, crate::vfs::makedev(136, 0)),
        FileObject::ConsoleOut(_) => (0x05, 0x11, S_IFCHR | 0o620, crate::vfs::makedev(136, 0)),
        FileObject::Tty => (0x05, 0x12, S_IFCHR | 0o620, crate::vfs::makedev(5, 1)),
        FileObject::PipeRead(id) | FileObject::PipeWrite(id) => {
            (0x0c, 0x1000 + id as u64, S_IFIFO | 0o600, 0)
        }
        FileObject::Proc { dir: true } => (0x16, 0x20, S_IFDIR | 0o555, 0),
        FileObject::Proc { dir: false } => (0x16, 0x21, S_IFREG | 0o444, 0),
        FileObject::Socket(id) => (0x1d, 0x10_0000 + id as u64, S_IFSOCK | 0o777, 0),
        FileObject::Node(_) => unreachable!("nodes have their own stat"),
    };
    Stat {
        dev,
        ino,
        mode,
        nlink: 1,
        rdev,
        size,
        blksize: 4096,
        atime: time,
        mtime: time,
        ctime: time,
        ..Stat::default()
    }
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    // ----- helpers -----

    /// The directory a relative path in an `*at` call starts from.
    pub(crate) fn start_dir_for(&mut self, dirfd: i64, path: &[u8]) -> SysResult<Ino> {
        self.start_dir(dirfd, path)
    }

    fn start_dir(&mut self, dirfd: i64, path: &[u8]) -> SysResult<Ino> {
        if path.first() == Some(&b'/') {
            return Ok(self.vfs.root());
        }
        if dirfd == AT_FDCWD {
            return Ok(self.proc().cwd);
        }
        let (_, file) = self.file(dirfd)?;
        match file.node() {
            Some(ino) if self.vfs.is_dir(ino) => Ok(ino),
            _ => Err(Errno(ENOTDIR)),
        }
    }

    /// Resolves `dirfd` + `path` (an `*at` call's target).
    fn lookup_at(
        &mut self,
        dirfd: i64,
        path: &[u8],
        follow: bool,
        empty_path: bool,
    ) -> SysResult<Target> {
        if path.is_empty() {
            if !empty_path {
                return Err(Errno(ENOENT));
            }
            if dirfd == AT_FDCWD {
                return Ok(Target::Node(self.proc().cwd));
            }
            let (_, file) = self.file(dirfd)?;
            return Ok(match file.object {
                FileObject::Node(ino) => Target::Node(ino),
                other => {
                    Target::Object(other, file.contents.as_ref().map_or(0, |c| c.len() as u64))
                }
            });
        }
        if let Some(comps) = self.proc_path(dirfd, path) {
            return self.lookup_proc(&comps, follow, 0);
        }
        let start = self.start_dir(dirfd, path)?;
        Ok(Target::Node(
            self.vfs.resolve(self.host, start, path, follow)?,
        ))
    }

    /// Resolves a path inside `/proc`; links are followed (when `follow`)
    /// into `/proc` again or into the VFS.
    fn lookup_proc(&mut self, comps: &[Vec<u8>], follow: bool, depth: u32) -> SysResult<Target> {
        let (path, node) = self.proc_lookup(comps)?;
        if let (ProcNode::Link(target), true) = (&node, follow) {
            if depth >= 8 {
                return Err(Errno(ELOOP));
            }
            let target = self.proc_follow(&path, target);
            if let Some(comps) = self.proc_path(AT_FDCWD, &target) {
                return self.lookup_proc(&comps, true, depth + 1);
            }
            if target.first() != Some(&b'/') {
                // pipe:[n] and the like: not a path.
                return Ok(Target::Proc(procfs::proc_ino(&path), node));
            }
            let root = self.vfs.root();
            return Ok(Target::Node(
                self.vfs.resolve(self.host, root, &target, true)?,
            ));
        }
        Ok(Target::Proc(procfs::proc_ino(&path), node))
    }

    fn node_at(&mut self, dirfd: i64, path_addr: GuestAddr, follow: bool) -> SysResult<Ino> {
        let path = self.read_path(path_addr)?;
        match self.lookup_at(dirfd, &path, follow, false)? {
            Target::Node(ino) => Ok(ino),
            Target::Object(..) => Err(Errno(EINVAL)),
            Target::Proc(..) => Err(Errno(EACCES)),
        }
    }

    fn parent_at(
        &mut self,
        dirfd: i64,
        path_addr: GuestAddr,
    ) -> SysResult<crate::vfs::ParentAndName> {
        let path = self.read_path(path_addr)?;
        let start = self.start_dir(dirfd, &path)?;
        self.vfs.resolve_parent(self.host, start, &path)
    }

    fn stat_of(&mut self, target: Target) -> Stat {
        match target {
            Target::Node(ino) => self.vfs.stat(ino),
            Target::Object(FileObject::Tty, _) => {
                // The terminal is /dev/console (ttyname compares the two).
                let root = self.vfs.root();
                match self.vfs.resolve(self.host, root, b"/dev/console", true) {
                    Ok(ino) => self.vfs.stat(ino),
                    Err(_) => {
                        let time = self.now();
                        object_stat(FileObject::Tty, 0, time)
                    }
                }
            }
            Target::Object(object, size) => {
                let time = self.now();
                object_stat(object, size, time)
            }
            Target::Proc(ino, node) => {
                let time = self.now();
                node.stat(ino, time)
            }
        }
    }

    /// The absolute path of `path` looked up from `start`, as recorded for
    /// `/proc/<pid>/fd` (not normalized beyond joining).
    fn absolute_path(&self, start: Ino, path: &[u8]) -> Option<Vec<u8>> {
        if path.first() == Some(&b'/') {
            return Some(path.to_vec());
        }
        let mut dir = self.vfs.dir_path(start)?;
        if dir != b"/" {
            dir.push(b'/');
        }
        dir.extend_from_slice(path);
        Some(dir)
    }

    // ----- data -----

    /// Reads up to `len` bytes from a description, at `offset` or at (and
    /// advancing) its file position. Parks the thread when a pipe or the
    /// console has nothing yet.
    fn read_file(&mut self, id: FileId, offset: Option<u64>, len: usize) -> SysResult<Vec<u8>> {
        let file = self.st.files.get(id);
        if !file.access.readable() {
            return Err(Errno(EBADF));
        }
        let len = len.min(MAX_IO);
        let nonblock = file.nonblock;
        let stream = !matches!(file.object, FileObject::Node(_) | FileObject::Proc { .. });
        if stream && offset.is_some() {
            return Err(Errno(ESPIPE));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        match file.object {
            FileObject::ConsoleIn => match self.st.console.input_state(self.host) {
                InputState::Ready => Ok(self.st.console.take_input(len)),
                InputState::Eof => Ok(Vec::new()),
                InputState::Empty if nonblock => Err(Errno(EAGAIN)),
                InputState::Empty => Err(self.park_retry(None, Restart::IfSaRestart)),
            },
            FileObject::Tty => self.tty_read(id, len),
            FileObject::ConsoleOut(_) | FileObject::PipeWrite(_) => Err(Errno(EBADF)),
            FileObject::Socket(sock) => self.socket_read(sock, len),
            FileObject::PipeRead(pipe) => {
                let mut buf = vec![0u8; len.min(PIPE_CAPACITY)];
                match self.st.pipes.get_mut(pipe).read(&mut buf) {
                    ReadResult::Data(n) => {
                        buf.truncate(n);
                        self.st.changed = true;
                        Ok(buf)
                    }
                    ReadResult::Eof => Ok(Vec::new()),
                    ReadResult::Empty if nonblock => Err(Errno(EAGAIN)),
                    ReadResult::Empty => Err(self.park_retry(None, Restart::IfSaRestart)),
                }
            }
            FileObject::Proc { .. } => {
                let file = self.st.files.get(id);
                let data = file.contents.as_deref().unwrap_or(&[]);
                let pos = offset.unwrap_or(file.offset).min(data.len() as u64) as usize;
                let n = len.min(data.len() - pos);
                let out = data[pos..pos + n].to_vec();
                if offset.is_none() {
                    self.st.files.get_mut(id).offset = (pos + n) as u64;
                }
                Ok(out)
            }
            FileObject::Node(ino) => {
                let mut buf = vec![0u8; len];
                let n = match self.vfs.device(ino) {
                    Some(Device::Null) => 0,
                    Some(Device::Zero | Device::Full) => len,
                    Some(Device::Random | Device::Urandom) => {
                        self.host
                            .random(&mut buf)
                            .map_err(|e| Errno::from_host(&e))?;
                        len
                    }
                    Some(Device::Fd(_) | Device::Unusable | Device::Tty { .. }) => {
                        return Err(Errno(ENXIO))
                    }
                    None => {
                        let pos = offset.unwrap_or(file.offset);
                        let n = self.vfs.read(self.host, ino, pos, &mut buf)?;
                        if offset.is_none() {
                            self.st.files.get_mut(id).offset = pos + n as u64;
                        }
                        n
                    }
                };
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    /// Gives back bytes a read took from a stream (pipe, console) but could
    /// not deliver to the guest.
    fn unread(&mut self, id: FileId, data: &[u8]) {
        match self.st.files.get(id).object {
            FileObject::PipeRead(pipe) => self.st.pipes.get_mut(pipe).unread(data),
            FileObject::ConsoleIn | FileObject::Tty => self.st.console.unread(data),
            FileObject::Socket(sock) => {
                for &byte in data.iter().rev() {
                    self.st.net.get_mut(sock).rx.push_front(byte);
                }
            }
            _ => {}
        }
    }

    /// Writes `data` to a description, at `offset` or at (and advancing) its
    /// file position. Parks the thread when a pipe is full.
    fn write_file(&mut self, id: FileId, offset: Option<u64>, data: &[u8]) -> SysResult<usize> {
        let file = self.st.files.get(id);
        if !file.access.writable() {
            return Err(Errno(EBADF));
        }
        let nonblock = file.nonblock;
        let stream = !matches!(file.object, FileObject::Node(_) | FileObject::Proc { .. });
        if stream && offset.is_some() {
            return Err(Errno(ESPIPE));
        }
        match file.object {
            FileObject::ConsoleIn | FileObject::PipeRead(_) | FileObject::Proc { .. } => {
                Err(Errno(EBADF))
            }
            FileObject::Socket(sock) => self.socket_write(sock, data),
            FileObject::ConsoleOut(stream) => self.console_write(stream, data),
            FileObject::Tty => self.tty_write(data),
            FileObject::PipeWrite(pipe) => {
                if data.is_empty() {
                    return Ok(0);
                }
                match self.st.pipes.get_mut(pipe).write(data) {
                    WriteResult::Written(n) => {
                        self.st.changed = true;
                        Ok(n)
                    }
                    WriteResult::Broken => {
                        let info = SigInfo::kernel(signal::SIGPIPE);
                        self.st.post_signal(self.pid, Some(self.tid), info);
                        Err(Errno(EPIPE))
                    }
                    WriteResult::Full if nonblock => Err(Errno(EAGAIN)),
                    WriteResult::Full => Err(self.park_retry(None, Restart::IfSaRestart)),
                }
            }
            FileObject::Node(ino) => match self.vfs.device(ino) {
                Some(Device::Full) => Err(Errno(ENOSPC)),
                Some(Device::Fd(_) | Device::Unusable | Device::Tty { .. }) => Err(Errno(ENXIO)),
                Some(_) => Ok(data.len()),
                None => {
                    let append = file.append;
                    let pos = match offset {
                        Some(pos) => pos,
                        None if append => self.vfs.size(ino),
                        None => file.offset,
                    };
                    let now = self.now();
                    let n = self.vfs.write(self.host, ino, pos, data, now)?;
                    if offset.is_none() {
                        self.st.files.get_mut(id).offset = pos + n as u64;
                    }
                    Ok(n)
                }
            },
        }
    }

    pub(crate) fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> SysResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.host.console_write(stream, data).map_err(|err| {
            // Host errno values are not guest errno values; do not pass
            // them through.
            log::warn!("console write failed on the host: {err}");
            Errno(crate::errno::EIO)
        })
    }

    pub fn sys_read(
        &mut self,
        fd: i64,
        buf: GuestAddr,
        len: u64,
        offset: Option<u64>,
    ) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        if let FileObject::Node(ino) = file.object {
            if self.vfs.is_dir(ino) {
                return Err(Errno(EISDIR));
            }
        }
        let stream = !matches!(file.object, FileObject::Node(_) | FileObject::Proc { .. });
        let before = file.offset;
        if stream && len > 0 {
            // Stream input cannot be put back once the guest saw part of
            // it: make sure the buffer can take at least a byte first.
            self.probe_writable(buf)?;
        }
        let data = self.read_file(id, offset, len as usize)?;
        let done = self.write_mem_prefix(buf, &data);
        if done < data.len() && stream {
            self.unread(id, &data[done..]);
        }
        self.finish_read(id, offset, before, data.len(), done)
    }

    /// Checks that the guest byte at `addr` is writable, leaving it as is.
    pub(crate) fn probe_writable(&mut self, addr: GuestAddr) -> SysResult<()> {
        let byte: [u8; 1] = self.read_array(addr)?;
        self.write_mem(addr, &byte)
    }

    /// Completes a read that got `got` bytes of which `done` reached the
    /// guest: a partial copy is a short read, as on Linux, and the file
    /// position only moves past what the guest received.
    fn finish_read(
        &mut self,
        id: FileId,
        offset: Option<u64>,
        before: u64,
        got: usize,
        done: usize,
    ) -> SysResult<u64> {
        if done < got {
            let file = self.st.files.get_mut(id);
            if offset.is_none() && file.offset == before + got as u64 {
                file.offset = before + done as u64;
            }
            if done == 0 {
                return Err(Errno(EFAULT));
            }
        }
        Ok(done as u64)
    }

    pub fn sys_write(
        &mut self,
        fd: i64,
        buf: GuestAddr,
        len: u64,
        offset: Option<u64>,
    ) -> SysResult<u64> {
        let (id, _) = self.file(fd)?;
        let len = (len as usize).min(MAX_IO);
        let data = self.read_mem(buf, len)?;
        self.write_fully(id, offset, &data).map(|n| n as u64)
    }

    /// `write`/`writev`: like [`Self::write_file`], except that a blocking
    /// write to a pipe goes on until all of `data` is in the pipe, as
    /// POSIX requires: when the pipe fills up, the thread parks and the
    /// retry continues where it stopped (`Thread::io_done`). Only a signal
    /// handler or a closed read end make it return a short count.
    fn write_fully(&mut self, id: FileId, offset: Option<u64>, data: &[u8]) -> SysResult<usize> {
        let file = self.st.files.get(id);
        let blocking_pipe = !file.nonblock
            && matches!(
                file.object,
                FileObject::PipeWrite(_) | FileObject::Socket(_)
            );
        if !blocking_pipe || data.is_empty() {
            return self.write_file(id, offset, data);
        }
        let tid = self.tid;
        let mut done = match self.parked {
            Some(_) => self.st.thread(tid).io_done.min(data.len()),
            None => 0,
        };
        while done < data.len() {
            match self.write_file(id, offset, &data[done..]) {
                Ok(n) => done += n,
                Err(err) if self.action.is_some() => {
                    // Parked: remember the progress for the retry.
                    self.st.thread_mut(tid).io_done = done;
                    return Err(err);
                }
                // The read end closed after some data went through.
                Err(_) if done > 0 => break,
                Err(err) => {
                    self.st.thread_mut(tid).io_done = 0;
                    return Err(err);
                }
            }
        }
        self.st.thread_mut(tid).io_done = 0;
        Ok(done)
    }

    fn seekable(&self, fd: i64) -> SysResult<()> {
        let (_, file) = self.file(fd)?;
        match file.object {
            FileObject::Node(_) | FileObject::Proc { .. } => Ok(()),
            _ => Err(Errno(ESPIPE)),
        }
    }

    pub fn sys_pread(&mut self, fd: i64, buf: GuestAddr, len: u64, offset: u64) -> SysResult<u64> {
        if (offset as i64) < 0 {
            return Err(Errno(EINVAL));
        }
        self.seekable(fd)?;
        self.sys_read(fd, buf, len, Some(offset))
    }

    pub fn sys_pwrite(&mut self, fd: i64, buf: GuestAddr, len: u64, offset: u64) -> SysResult<u64> {
        if (offset as i64) < 0 {
            return Err(Errno(EINVAL));
        }
        self.seekable(fd)?;
        self.sys_write(fd, buf, len, Some(offset))
    }

    fn read_iovecs(&mut self, iov: GuestAddr, count: u64) -> SysResult<Vec<(u64, u64)>> {
        if count > IOV_MAX {
            return Err(Errno(EINVAL));
        }
        let raw = self.read_mem(iov, count as usize * 16)?;
        Ok(raw
            .as_chunks::<16>()
            .0
            .iter()
            .map(|c| {
                (
                    u64::from_le_bytes(c[..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..].try_into().unwrap()),
                )
            })
            .collect())
    }

    pub fn sys_readv(
        &mut self,
        fd: i64,
        iov: GuestAddr,
        count: u64,
        offset: Option<u64>,
    ) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        let stream = !matches!(file.object, FileObject::Node(_) | FileObject::Proc { .. });
        if offset.is_some() {
            self.seekable(fd)?;
        }
        let iovecs = self.read_iovecs(iov, count)?;
        // Guest-chosen lengths: the sum must not overflow.
        let total = iovecs
            .iter()
            .fold(0u64, |sum, v| sum.saturating_add(v.1))
            .min(MAX_IO as u64);
        let before = self.st.files.get(id).offset;
        if stream {
            if let Some(&(base, _)) = iovecs.iter().find(|v| v.1 > 0) {
                self.probe_writable(base)?;
            }
        }
        let data = self.read_file(id, offset, total as usize)?;
        let mut done = 0;
        for (base, len) in iovecs {
            if done == data.len() {
                break;
            }
            let n = (len as usize).min(data.len() - done);
            let written = self.write_mem_prefix(base, &data[done..done + n]);
            done += written;
            if written < n {
                break;
            }
        }
        if done < data.len() && stream {
            self.unread(id, &data[done..]);
        }
        self.finish_read(id, offset, before, data.len(), done)
    }

    pub fn sys_writev(
        &mut self,
        fd: i64,
        iov: GuestAddr,
        count: u64,
        offset: Option<u64>,
    ) -> SysResult<u64> {
        let (id, _) = self.file(fd)?;
        if offset.is_some() {
            self.seekable(fd)?;
        }
        let iovecs = self.read_iovecs(iov, count)?;
        // Gather into one buffer so that a console write stays in one piece.
        let mut data = Vec::new();
        for (base, len) in iovecs {
            let n = (len as usize).min(MAX_IO - data.len());
            data.extend(self.read_mem(base, n)?);
            if data.len() == MAX_IO {
                break;
            }
        }
        self.write_fully(id, offset, &data).map(|n| n as u64)
    }

    pub fn sys_sendfile(
        &mut self,
        out_fd: i64,
        in_fd: i64,
        offset_ptr: GuestAddr,
        count: u64,
    ) -> SysResult<u64> {
        let (out_id, _) = self.file(out_fd)?;
        let (in_id, in_file) = self.file(in_fd)?;
        let before = in_file.offset;
        let offset = if offset_ptr != 0 {
            Some(self.read_u64(offset_ptr)?)
        } else {
            None
        };
        let count = (count as usize).min(PIPE_CAPACITY);
        let data = self.read_file(in_id, offset, count)?;
        let n = match self.write_file(out_id, None, &data) {
            Ok(n) => n,
            Err(err) => {
                // Nothing was transferred: give the input back.
                self.unread(in_id, &data);
                if offset.is_none() {
                    self.st.files.get_mut(in_id).offset = before;
                }
                return Err(err);
            }
        };
        if let Some(offset) = offset {
            self.write_u64(offset_ptr, offset + n as u64)?;
        } else if n < data.len() {
            // Give back what was read but not written.
            self.unread(in_id, &data[n..]);
            let file = self.st.files.get_mut(in_id);
            if matches!(file.object, FileObject::Node(_) | FileObject::Proc { .. }) {
                file.offset -= (data.len() - n) as u64;
            }
        }
        Ok(n as u64)
    }

    pub fn sys_lseek(&mut self, fd: i64, offset: i64, whence: i64) -> SysResult<u64> {
        const SEEK_SET: i64 = 0;
        const SEEK_CUR: i64 = 1;
        const SEEK_END: i64 = 2;
        let (id, file) = self.file(fd)?;
        let size = match file.object {
            FileObject::Node(ino) => {
                if self.vfs.device(ino).is_some() {
                    return Ok(0);
                }
                self.vfs.size(ino)
            }
            FileObject::Proc { .. } => file.contents.as_ref().map_or(0, |c| c.len() as u64),
            _ => return Err(Errno(ESPIPE)),
        };
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => file.offset as i64,
            SEEK_END => size as i64,
            _ => return Err(Errno(EINVAL)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(EINVAL))?;
        let is_dir = match file.object {
            FileObject::Node(ino) => self.vfs.is_dir(ino),
            _ => false,
        };
        let file = self.st.files.get_mut(id);
        file.offset = new as u64;
        if is_dir && new == 0 {
            // Rewinding a directory lists it afresh.
            file.listing = None;
        }
        Ok(new as u64)
    }

    // ----- open, close, dup -----

    pub fn sys_openat(
        &mut self,
        dirfd: i64,
        path_addr: GuestAddr,
        raw_flags: u64,
        mode: u64,
    ) -> SysResult<u64> {
        let path = self.read_path(path_addr)?;
        self.open_path(dirfd, &path, raw_flags, mode, 0)
    }

    /// Opens a file of `/proc`.
    fn open_proc(
        &mut self,
        comps: &[Vec<u8>],
        raw_flags: u64,
        mode: u64,
        depth: u32,
    ) -> SysResult<u64> {
        let flags = abi::decode_open_flags(self.arch, raw_flags);
        let (path, node) = self.proc_lookup(comps)?;
        if let ProcNode::Link(target) = &node {
            if flags.nofollow && !flags.path {
                return Err(Errno(ELOOP));
            }
            if depth >= 8 {
                return Err(Errno(ELOOP));
            }
            // /proc/<pid>/fd/<n> of this process reopens the fd (as a
            // duplicate, sharing its offset).
            if let [pid, fd_dir, fd] = path.as_slice() {
                if fd_dir == b"fd" && *pid == self.pid.to_string().into_bytes() {
                    let fd = std::str::from_utf8(fd)
                        .ok()
                        .and_then(|f| f.parse::<i64>().ok())
                        .ok_or(Errno(ENOENT))?;
                    return self
                        .dup_min(fd, 0, flags.cloexec)
                        .map(|fd| fd as u64)
                        .map_err(|e| if e == Errno(EBADF) { Errno(ENOENT) } else { e });
                }
            }
            let target = self.proc_follow(&path, target);
            if target.first() != Some(&b'/') {
                return Err(Errno(ENXIO));
            }
            return self.open_path(AT_FDCWD, &target, raw_flags, mode, depth + 1);
        }
        if flags.creat || flags.accmode != 0 || flags.trunc {
            return Err(procfs::PROC_WRITE);
        }
        if flags.directory && !matches!(node, ProcNode::Dir(_)) {
            return Err(Errno(ENOTDIR));
        }
        let mut file = OpenFile::new(node.object(), Access::Read);
        let mut abs = b"/proc".to_vec();
        for c in &path {
            abs.push(b'/');
            abs.extend_from_slice(c);
        }
        match node {
            // The listing is generated when it is first read.
            ProcNode::Dir(_) => {}
            ProcNode::File(contents) => {
                // Each open keeps its snapshot: bound what they hold.
                let held = self.st.proc_bytes + contents.len();
                if held > crate::task::MAX_PROC_BYTES {
                    return Err(Errno(crate::errno::ENOMEM));
                }
                self.st.proc_bytes = held;
                file.contents = Some(contents);
            }
            ProcNode::Link(_) => unreachable!("handled above"),
        }
        file.path = Some(abs);
        file.nonblock = flags.nonblock;
        self.install(file, 0, flags.cloexec).map(|fd| fd as u64)
    }

    /// The listing of a `/proc` directory, at its absolute path.
    fn proc_listing(&mut self, abs: Vec<u8>) -> SysResult<Vec<DirEntry>> {
        let comps = self.proc_path(AT_FDCWD, &abs).ok_or(Errno(ENOENT))?;
        let (path, node) = self.proc_lookup(&comps)?;
        let ProcNode::Dir(entries) = node else {
            return Err(Errno(ENOTDIR));
        };
        let mut listing = vec![
            DirEntry {
                name: b".".to_vec(),
                ino: procfs::proc_ino(&path),
                kind: FileType::Directory,
            },
            DirEntry {
                name: b"..".to_vec(),
                ino: procfs::proc_ino(&path[..path.len().saturating_sub(1)]),
                kind: FileType::Directory,
            },
        ];
        for mut e in entries {
            let mut child = path.clone();
            child.push(e.name.clone());
            e.ino = procfs::proc_ino(&child);
            listing.push(e);
        }
        Ok(listing)
    }

    fn open_path(
        &mut self,
        dirfd: i64,
        path: &[u8],
        raw_flags: u64,
        mode: u64,
        depth: u32,
    ) -> SysResult<u64> {
        let flags = abi::decode_open_flags(self.arch, raw_flags);
        let path = path.to_vec();
        if flags.tmpfile {
            return Err(Errno(EOPNOTSUPP));
        }
        if let Some(comps) = self.proc_path(dirfd, &path) {
            return self.open_proc(&comps, raw_flags, mode, depth);
        }
        let start = self.start_dir(dirfd, &path)?;
        let follow = !flags.nofollow;
        let ino = if flags.creat && !flags.path {
            // O_EXCL never follows a final symlink: the name itself must
            // be free.
            match self
                .vfs
                .resolve_for_create(self.host, start, &path, follow && !flags.excl)?
            {
                CreateTarget::Existing(_) if flags.excl => return Err(Errno(EEXIST)),
                CreateTarget::Existing(ino) => ino,
                CreateTarget::Missing(parent) => {
                    if parent.trailing_slash {
                        return Err(Errno(EISDIR));
                    }
                    let perm = (mode as u32) & 0o7777 & !self.proc().umask;
                    let now = self.now();
                    self.vfs.create(
                        self.host,
                        parent.dir,
                        &parent.name,
                        NewNode::File,
                        perm,
                        now,
                    )?
                }
            }
        } else {
            self.vfs.resolve(self.host, start, &path, follow)?
        };

        let kind = self.vfs.file_type(ino);
        let access = if flags.path {
            Access::Path
        } else {
            match flags.accmode {
                0 => Access::Read,
                1 => Access::Write,
                2 => Access::ReadWrite,
                _ => return Err(Errno(EINVAL)),
            }
        };
        if flags.directory && kind != FileType::Directory {
            return Err(Errno(ENOTDIR));
        }
        if !flags.path {
            if kind == FileType::Symlink {
                return Err(Errno(ELOOP));
            }
            if kind == FileType::Directory && (access.writable() || flags.creat) {
                return Err(Errno(EISDIR));
            }
            match self.vfs.device(ino) {
                Some(Device::Fd(target)) => {
                    // /dev/stdin and friends reopen the fd they name.
                    return self
                        .dup_min(i64::from(target), 0, flags.cloexec)
                        .map(|fd| fd as u64)
                        .map_err(|e| if e == Errno(EBADF) { Errno(ENXIO) } else { e });
                }
                Some(Device::Unusable) => return Err(Errno(ENXIO)),
                Some(Device::Tty { .. }) => {
                    // The controlling terminal, or the console.
                    if self.st.console.tty.is_none() {
                        return Err(Errno(ENXIO));
                    }
                    let mut file = OpenFile::new(FileObject::Tty, access);
                    file.nonblock = flags.nonblock;
                    file.path = self.absolute_path(start, &path);
                    return self.install(file, 0, flags.cloexec).map(|fd| fd as u64);
                }
                _ => {}
            }
            if flags.trunc && kind == FileType::Regular && access.writable() {
                let now = self.now();
                self.vfs.truncate(self.host, ino, 0, now)?;
            }
        }
        let mut file = OpenFile::new(FileObject::Node(ino), access);
        file.append = flags.append;
        file.nonblock = flags.nonblock;
        file.path = self.absolute_path(start, &path);
        self.vfs.opened(ino);
        self.install(file, 0, flags.cloexec).map(|fd| fd as u64)
    }

    pub fn sys_creat(&mut self, path: GuestAddr, mode: u64) -> SysResult<u64> {
        let flags = 1 | abi::O_CREAT | abi::O_TRUNC;
        self.sys_openat(AT_FDCWD, path, flags, mode)
    }

    pub fn sys_close(&mut self, fd: i64) -> SysResult<u64> {
        let st = &mut *self.st;
        let proc = st.procs.get_mut(&self.pid).expect("live process");
        let released = proc.fds.close(&mut st.files, fd)?;
        self.release(released);
        Ok(0)
    }

    pub fn sys_close_range(&mut self, first: u64, last: u64, flags: u64) -> SysResult<u64> {
        const CLOSE_RANGE_CLOEXEC: u64 = 4;
        if first > last || flags & !CLOSE_RANGE_CLOEXEC != 0 {
            return Err(Errno(EINVAL));
        }
        for fd in self.proc().fds.fds() {
            if (first..=last).contains(&(fd as u64)) {
                if flags & CLOSE_RANGE_CLOEXEC != 0 {
                    self.proc_mut().fds.set_cloexec(fd, true)?;
                } else {
                    self.sys_close(fd)?;
                }
            }
        }
        Ok(0)
    }

    fn dup_min(&mut self, fd: i64, min: usize, cloexec: bool) -> SysResult<i64> {
        let st = &mut *self.st;
        let proc = st.procs.get_mut(&self.pid).expect("live process");
        proc.fds.dup(&mut st.files, fd, min, cloexec)
    }

    pub fn sys_dup(&mut self, fd: i64) -> SysResult<u64> {
        self.dup_min(fd, 0, false).map(|fd| fd as u64)
    }

    pub fn sys_dup2(&mut self, old: i64, new: i64) -> SysResult<u64> {
        if old == new {
            self.proc().fds.get(old)?;
            return Ok(new as u64);
        }
        self.sys_dup3(old, new, 0)
    }

    pub fn sys_dup3(&mut self, old: i64, new: i64, flags: u64) -> SysResult<u64> {
        if old == new || flags & !abi::O_CLOEXEC != 0 {
            return Err(Errno(EINVAL));
        }
        let st = &mut *self.st;
        let proc = st.procs.get_mut(&self.pid).expect("live process");
        let released = proc.fds.dup_to(&mut st.files, old, new, flags != 0)?;
        self.release(released);
        Ok(new as u64)
    }

    pub fn sys_pipe2(&mut self, fds: GuestAddr, flags: u64) -> SysResult<u64> {
        const O_DIRECT: u64 = 0o40000;
        if flags & !(abi::O_CLOEXEC | abi::O_NONBLOCK | O_DIRECT) != 0 {
            return Err(Errno(EINVAL));
        }
        // Check the destination before creating anything.
        let probe: [u8; 8] = self.read_array(fds)?;
        self.write_mem(fds, &probe)?;
        let cloexec = flags & abi::O_CLOEXEC != 0;
        let nonblock = flags & abi::O_NONBLOCK != 0;
        let pipe = self.st.pipes.create().ok_or(Errno(crate::errno::ENFILE))?;
        let mut read = OpenFile::new(FileObject::PipeRead(pipe), Access::Read);
        read.nonblock = nonblock;
        let mut write = OpenFile::new(FileObject::PipeWrite(pipe), Access::Write);
        write.nonblock = nonblock;
        let r = match self.install(read, 0, cloexec) {
            Ok(fd) => fd,
            Err(err) => {
                self.st.pipes.close_end(pipe, true);
                return Err(err);
            }
        };
        let w = match self.install(write, 0, cloexec) {
            Ok(fd) => fd,
            Err(err) => {
                self.sys_close(r)?;
                return Err(err);
            }
        };
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&(r as i32).to_le_bytes());
        out[4..].copy_from_slice(&(w as i32).to_le_bytes());
        self.write_mem(fds, &out)?;
        Ok(0)
    }

    pub fn sys_fcntl(&mut self, fd: i64, cmd: i64, arg: u64) -> SysResult<u64> {
        const F_SETOWN: i64 = 8;
        const F_GETOWN: i64 = 9;
        const F_SETPIPE_SZ: i64 = 1031;
        const F_GETPIPE_SZ: i64 = 1032;
        const F_ADD_SEALS: i64 = 1033;
        const F_GET_SEALS: i64 = 1034;
        let (id, file) = self.file(fd)?;
        let is_pipe = matches!(
            file.object,
            FileObject::PipeRead(_) | FileObject::PipeWrite(_)
        );
        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let min = usize::try_from(int(arg)).map_err(|_| Errno(EINVAL))?;
                if min >= MAX_FDS {
                    return Err(Errno(EINVAL));
                }
                self.dup_min(fd, min, cmd == F_DUPFD_CLOEXEC)
                    .map(|fd| fd as u64)
            }
            F_GETFD => Ok(u64::from(self.proc().fds.cloexec(fd)?)),
            F_SETFD => self
                .proc_mut()
                .fds
                .set_cloexec(fd, arg & FD_CLOEXEC != 0)
                .map(|()| 0),
            F_GETFL => Ok(abi::encode_status_flags(
                self.arch,
                file.access,
                file.append,
                file.nonblock,
            )),
            F_SETFL => {
                let file = self.st.files.get_mut(id);
                file.append = arg & abi::O_APPEND != 0;
                file.nonblock = arg & abi::O_NONBLOCK != 0;
                self.st.changed = true;
                Ok(0)
            }
            F_GETLK | F_OFD_GETLK => {
                // Locks are never held against anyone: report l_type
                // F_UNLCK (the first field of struct flock).
                self.write_mem(arg, &F_UNLCK.to_le_bytes())?;
                Ok(0)
            }
            F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => Ok(0),
            F_GETOWN | F_SETOWN => Ok(0),
            F_GETPIPE_SZ | F_SETPIPE_SZ if is_pipe => Ok(PIPE_CAPACITY as u64),
            F_GETPIPE_SZ | F_SETPIPE_SZ => Err(Errno(EBADF)),
            F_ADD_SEALS | F_GET_SEALS => Err(Errno(EINVAL)),
            _ => {
                log::warn!("unimplemented fcntl command {cmd}");
                Err(Errno(EINVAL))
            }
        }
    }

    pub fn sys_ioctl(&mut self, fd: i64, request: u64, arg: u64) -> SysResult<u64> {
        const FIONBIO: u64 = 0x5421;
        let (id, file) = self.file(fd)?;
        let object = file.object;
        match request & 0xffff_ffff {
            FIOCLEX => self.proc_mut().fds.set_cloexec(fd, true).map(|()| 0),
            FIONCLEX => self.proc_mut().fds.set_cloexec(fd, false).map(|()| 0),
            FIONBIO => {
                let on = self.read_u32(arg)? != 0;
                self.st.files.get_mut(id).nonblock = on;
                Ok(0)
            }
            FIONREAD => {
                let n = match object {
                    FileObject::Node(ino) if self.vfs.file_type(ino) == FileType::Regular => self
                        .vfs
                        .size(ino)
                        .saturating_sub(self.st.files.get(id).offset),
                    FileObject::PipeRead(pipe) => self.st.pipes.get(pipe).len() as u64,
                    FileObject::ConsoleIn => {
                        self.st.console.fill(self.host);
                        self.st.console.buffered() as u64
                    }
                    FileObject::Tty => self.tty_readable() as u64,
                    FileObject::Socket(sock) => self.socket_readable_len(sock) as u64,
                    _ => return Err(Errno(ENOTTY)),
                };
                self.write_u32(arg, n.min(i32::MAX as u64) as u32)?;
                Ok(0)
            }
            request if matches!(object, FileObject::Socket(_)) => {
                match self.socket_ioctl(request, arg) {
                    Some(result) => result,
                    None => Err(Errno(ENOTTY)),
                }
            }
            request if object == FileObject::Tty => self.tty_ioctl(request, arg),
            // Not a terminal: every tty request (TCGETS, TIOCGWINSZ,
            // TIOCGPGRP, ...) fails as on a pipe or file.
            _ => Err(Errno(ENOTTY)),
        }
    }

    /// The `poll` events an fd has now (`POLLNVAL` for a bad fd).
    fn poll_events(&mut self, fd: i64) -> u16 {
        let Ok((_, file)) = self.file(fd) else {
            return POLLNVAL;
        };
        let any_in = POLLIN | POLLRDNORM;
        let any_out = POLLOUT | POLLWRNORM;
        match file.object {
            FileObject::Node(_) | FileObject::Proc { .. } => any_in | any_out,
            FileObject::ConsoleOut(_) => any_out,
            FileObject::ConsoleIn => match self.st.console.input_state(self.host) {
                InputState::Empty => 0,
                _ => any_in,
            },
            FileObject::Tty => {
                if self.tty_readable() > 0 || self.tty_hung_up() {
                    any_in | any_out
                } else {
                    any_out
                }
            }
            FileObject::PipeRead(pipe) => {
                let p = self.st.pipes.get(pipe);
                (if p.is_empty() { 0 } else { any_in }) | if p.writers == 0 { POLLHUP } else { 0 }
            }
            FileObject::PipeWrite(pipe) => {
                let p = self.st.pipes.get(pipe);
                (if p.space() > 0 { any_out } else { 0 }) | if p.readers == 0 { POLLERR } else { 0 }
            }
            FileObject::Socket(sock) => {
                let ev = self.socket_poll(sock);
                (if ev.readable { any_in } else { 0 })
                    | (if ev.writable { any_out } else { 0 })
                    | (if ev.err { POLLERR } else { 0 })
                    | (if ev.hup { POLLHUP } else { 0 })
            }
        }
    }

    /// Replaces the signal mask for the duration of a `ppoll`/`pselect6`.
    fn temporary_mask(&mut self, set: GuestAddr, size: u64) -> SysResult<()> {
        if set == 0 || self.parked.is_some() {
            return Ok(());
        }
        if size != 8 {
            return Err(Errno(EINVAL));
        }
        let mask = self.read_u64(set)?;
        let thread = self.st.thread_mut(self.tid);
        thread.saved_mask = Some(thread.sigmask);
        thread.sigmask = mask & !signal::UNBLOCKABLE;
        self.st.changed = true;
        Ok(())
    }

    pub fn sys_poll(
        &mut self,
        fds: GuestAddr,
        nfds: u64,
        timeout_ms: Option<i64>,
    ) -> SysResult<u64> {
        let timeout = match timeout_ms {
            Some(ms) if ms >= 0 => Some(Duration::from_millis(ms as u64)),
            _ => None,
        };
        self.poll_until(fds, nfds, timeout)
    }

    fn poll_until(
        &mut self,
        fds: GuestAddr,
        nfds: u64,
        timeout: Option<Duration>,
    ) -> SysResult<u64> {
        if nfds > MAX_FDS as u64 {
            return Err(Errno(EINVAL));
        }
        let mut raw = self.read_mem(fds, nfds as usize * 8)?;
        let mut ready = 0;
        for entry in raw.as_chunks_mut::<8>().0 {
            let fd = i32::from_le_bytes(entry[..4].try_into().unwrap());
            let events = u16::from_le_bytes([entry[4], entry[5]]);
            let revents = if fd < 0 {
                0
            } else {
                self.poll_events(i64::from(fd)) & (events | POLLERR | POLLHUP | POLLNVAL)
            };
            entry[6..8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready += 1;
            }
        }
        if ready == 0 && !self.timed_out() && timeout != Some(Duration::ZERO) {
            return Err(self.park_retry(timeout, Restart::Never));
        }
        self.write_mem(fds, &raw)?;
        Ok(ready)
    }

    pub fn sys_ppoll(
        &mut self,
        fds: GuestAddr,
        nfds: u64,
        timeout: GuestAddr,
        sigmask: GuestAddr,
        sigsetsize: u64,
    ) -> SysResult<u64> {
        let timeout = if timeout == 0 {
            None
        } else {
            Some(self.read_timespec(timeout)?)
        };
        self.temporary_mask(sigmask, sigsetsize)?;
        self.poll_until(fds, nfds, timeout)
    }

    /// `select`/`pselect6`. The timeout is a `timeval` (`select`) or a
    /// `timespec` (`pselect6`); `sigmask` is pselect6's `{ sigset *, size }`.
    pub fn sys_select(
        &mut self,
        nfds: i64,
        sets: [GuestAddr; 3],
        timeout: GuestAddr,
        timeout_is_timespec: bool,
        sigmask: GuestAddr,
    ) -> SysResult<u64> {
        let timeout = if timeout == 0 {
            None
        } else {
            let (sec, sub) = abi::decode_pair(&self.read_array(timeout)?);
            let (max, to_nanos) = if timeout_is_timespec {
                (1_000_000_000, 1)
            } else {
                (1_000_000, 1000)
            };
            if sec < 0 || !(0..max).contains(&sub) {
                return Err(Errno(EINVAL));
            }
            Some(Duration::new(sec as u64, (sub * to_nanos) as u32))
        };
        if !(0..=MAX_FDS as i64).contains(&nfds) {
            return Err(Errno(EINVAL));
        }
        if sigmask != 0 {
            let pair: [u8; 16] = self.read_array(sigmask)?;
            let (set, size) = abi::decode_pair(&pair);
            self.temporary_mask(set as u64, size as u64)?;
        }
        let bytes = (nfds as usize).div_ceil(64) * 8;
        let mut inputs = [None, None, None];
        for (i, &set) in sets.iter().enumerate() {
            if set != 0 {
                inputs[i] = Some(self.read_mem(set, bytes)?);
            }
        }
        let wanted = [
            POLLIN | POLLRDNORM | POLLHUP | POLLERR,
            POLLOUT | POLLWRNORM | POLLERR,
            0,
        ];
        let mut outputs = vec![vec![0u8; bytes]; 3];
        let mut ready = 0;
        for fd in 0..nfds as usize {
            let (byte, mask) = (fd / 8, 1u8 << (fd % 8));
            let asked: Vec<usize> = (0..3)
                .filter(|&i| inputs[i].as_ref().is_some_and(|b| b[byte] & mask != 0))
                .collect();
            if asked.is_empty() {
                continue;
            }
            let events = self.poll_events(fd as i64);
            if events & POLLNVAL != 0 {
                return Err(Errno(EBADF));
            }
            for i in asked {
                if events & wanted[i] != 0 {
                    outputs[i][byte] |= mask;
                    ready += 1;
                }
            }
        }
        if ready == 0 && !self.timed_out() && timeout != Some(Duration::ZERO) {
            return Err(self.park_retry(timeout, Restart::Never));
        }
        for (i, &set) in sets.iter().enumerate() {
            if set != 0 {
                self.write_mem(set, &outputs[i])?;
            }
        }
        Ok(ready)
    }

    pub fn sys_fsync(&mut self, fd: i64) -> SysResult<u64> {
        self.proc().fds.get(fd)?;
        Ok(0)
    }

    pub fn sys_ftruncate(&mut self, fd: i64, len: i64) -> SysResult<u64> {
        let (_, file) = self.file(fd)?;
        if len < 0 {
            return Err(Errno(EINVAL));
        }
        let ino = file.node().ok_or(Errno(EINVAL))?;
        if !file.access.writable() {
            return Err(Errno(EINVAL));
        }
        let now = self.now();
        self.vfs
            .truncate(self.host, ino, len as u64, now)
            .map(|()| 0)
    }

    pub fn sys_truncate(&mut self, path: GuestAddr, len: i64) -> SysResult<u64> {
        if len < 0 {
            return Err(Errno(EINVAL));
        }
        let ino = self.node_at(AT_FDCWD, path, true)?;
        let now = self.now();
        self.vfs
            .truncate(self.host, ino, len as u64, now)
            .map(|()| 0)
    }

    // ----- metadata -----

    pub fn sys_fstat(&mut self, fd: i64, buf: GuestAddr) -> SysResult<u64> {
        let (_, file) = self.file(fd)?;
        let target = match file.object {
            FileObject::Node(ino) => Target::Node(ino),
            other => Target::Object(other, file.contents.as_ref().map_or(0, |c| c.len() as u64)),
        };
        let st = self.stat_of(target);
        self.write_mem(buf, &abi::encode_stat(self.arch, &st))?;
        Ok(0)
    }

    pub fn sys_newfstatat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        buf: GuestAddr,
        flags: u64,
    ) -> SysResult<u64> {
        let path = self.read_path(path)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let target = self.lookup_at(dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?;
        let st = self.stat_of(target);
        self.write_mem(buf, &abi::encode_stat(self.arch, &st))?;
        Ok(0)
    }

    pub fn sys_statx(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        flags: u64,
        buf: GuestAddr,
    ) -> SysResult<u64> {
        let path = self.read_path(path)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let target = self.lookup_at(dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?;
        let st = self.stat_of(target);
        self.write_mem(buf, &abi::encode_statx(&st))?;
        Ok(0)
    }

    fn write_statfs(&mut self, buf: GuestAddr) -> SysResult<u64> {
        let data = abi::encode_statfs(OVERLAYFS_MAGIC, 4096, 1 << 20, 1 << 19, 1 << 20, 1 << 19);
        self.write_mem(buf, &data)?;
        Ok(0)
    }

    pub fn sys_statfs_path(&mut self, path: GuestAddr, buf: GuestAddr) -> SysResult<u64> {
        self.node_at(AT_FDCWD, path, true)?;
        self.write_statfs(buf)
    }

    pub fn sys_fstatfs(&mut self, fd: i64, buf: GuestAddr) -> SysResult<u64> {
        self.file(fd)?;
        self.write_statfs(buf)
    }

    pub fn sys_faccessat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        mode: u64,
        flags: u64,
    ) -> SysResult<u64> {
        const X_OK: u64 = 1;
        if mode & !7 != 0 || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0 {
            return Err(Errno(EINVAL));
        }
        let path = self.read_path(path)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let target = self.lookup_at(dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?;
        // The guest is root: reading and writing are always allowed;
        // executing needs an execute bit (or a directory).
        if mode & X_OK != 0 {
            if let Target::Node(ino) = target {
                if !self.vfs.is_dir(ino) && self.vfs.perm(ino) & 0o111 == 0 {
                    return Err(Errno(EACCES));
                }
            }
        }
        Ok(0)
    }

    pub fn sys_readlinkat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        buf: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        if (size as i64) <= 0 {
            return Err(Errno(EINVAL));
        }
        let path = self.read_path(path)?;
        let target = match self.lookup_at(dirfd, &path, false, true)? {
            Target::Node(ino) => self.vfs.read_link(ino)?,
            Target::Proc(_, ProcNode::Link(target)) => target,
            _ => return Err(Errno(EINVAL)),
        };
        let n = target.len().min(size as usize);
        self.write_mem(buf, &target[..n])?;
        Ok(n as u64)
    }

    pub fn sys_getdents64(&mut self, fd: i64, buf: GuestAddr, count: u64) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        let proc_dir = file.object == FileObject::Proc { dir: true };
        let ino = match file.node() {
            Some(ino) if self.vfs.is_dir(ino) => ino,
            _ if proc_dir => 0,
            _ => return Err(Errno(ENOTDIR)),
        };
        if file.listing.is_none() && proc_dir {
            let listing = self.proc_listing(file.path.clone().unwrap_or_default())?;
            self.st.files.get_mut(id).listing = Some(listing);
        }
        let file = self.st.files.get(id);
        if file.listing.is_none() {
            let parent = self.vfs.parent(ino)?;
            let mut listing = vec![
                DirEntry {
                    name: b".".to_vec(),
                    ino,
                    kind: FileType::Directory,
                },
                DirEntry {
                    name: b"..".to_vec(),
                    ino: parent,
                    kind: FileType::Directory,
                },
            ];
            listing.extend(self.vfs.list(self.host, ino)?);
            self.st.files.get_mut(id).listing = Some(listing);
        }
        let file = self.st.files.get(id);
        let listing = file.listing.as_ref().expect("set above");
        let mut out = Vec::new();
        let mut index = file.offset as usize;
        while let Some(entry) = listing.get(index) {
            if out.len() + abi::dirent64_len(&entry.name) > count as usize {
                break;
            }
            abi::push_dirent64(
                &mut out,
                entry.ino,
                index as i64 + 1,
                entry.kind.dirent_type(),
                &entry.name,
            );
            index += 1;
        }
        if out.is_empty() && index < listing.len() {
            return Err(Errno(EINVAL));
        }
        self.write_mem(buf, &out)?;
        self.st.files.get_mut(id).offset = index as u64;
        Ok(out.len() as u64)
    }

    // ----- namespace changes -----

    pub fn sys_mkdirat(&mut self, dirfd: i64, path: GuestAddr, mode: u64) -> SysResult<u64> {
        let parent = self.parent_at(dirfd, path)?;
        let perm = (mode as u32) & 0o7777 & !self.proc().umask;
        let now = self.now();
        self.vfs
            .create(self.host, parent.dir, &parent.name, NewNode::Dir, perm, now)
            .map(|_| 0)
    }

    pub fn sys_mknodat(&mut self, dirfd: i64, path: GuestAddr, mode: u64) -> SysResult<u64> {
        // Only regular files; devices and FIFOs cannot be created.
        let kind = mode as u32 & S_IFMT;
        if kind != 0 && kind != S_IFREG {
            return Err(Errno(EPERM));
        }
        let parent = self.parent_at(dirfd, path)?;
        let perm = (mode as u32) & 0o7777 & !self.proc().umask;
        let now = self.now();
        self.vfs
            .create(
                self.host,
                parent.dir,
                &parent.name,
                NewNode::File,
                perm,
                now,
            )
            .map(|_| 0)
    }

    pub fn sys_unlinkat(&mut self, dirfd: i64, path: GuestAddr, flags: u64) -> SysResult<u64> {
        if flags & !AT_REMOVEDIR != 0 {
            return Err(Errno(EINVAL));
        }
        let parent = self.parent_at(dirfd, path)?;
        let now = self.now();
        if flags & AT_REMOVEDIR != 0 {
            self.vfs.rmdir(self.host, parent.dir, &parent.name, now)?;
        } else {
            if parent.trailing_slash {
                let ino = self.vfs.lookup(self.host, parent.dir, &parent.name)?;
                return Err(Errno(if self.vfs.is_dir(ino) {
                    EISDIR
                } else {
                    ENOTDIR
                }));
            }
            self.vfs.unlink(self.host, parent.dir, &parent.name, now)?;
        }
        Ok(0)
    }

    pub fn sys_renameat(
        &mut self,
        old_dirfd: i64,
        old: GuestAddr,
        new_dirfd: i64,
        new: GuestAddr,
        flags: u64,
    ) -> SysResult<u64> {
        if flags & !RENAME_NOREPLACE != 0 {
            // RENAME_EXCHANGE and RENAME_WHITEOUT.
            return Err(Errno(EINVAL));
        }
        let from = self.parent_at(old_dirfd, old)?;
        let to = self.parent_at(new_dirfd, new)?;
        if from.trailing_slash || to.trailing_slash {
            let ino = self.vfs.lookup(self.host, from.dir, &from.name)?;
            if !self.vfs.is_dir(ino) {
                return Err(Errno(ENOTDIR));
            }
        }
        let now = self.now();
        self.vfs
            .rename(
                self.host,
                from.dir,
                &from.name,
                to.dir,
                &to.name,
                flags & RENAME_NOREPLACE != 0,
                now,
            )
            .map(|()| 0)
    }

    pub fn sys_symlinkat(
        &mut self,
        target: GuestAddr,
        dirfd: i64,
        path: GuestAddr,
    ) -> SysResult<u64> {
        let target = self.read_path(target)?;
        if target.is_empty() {
            return Err(Errno(ENOENT));
        }
        let parent = self.parent_at(dirfd, path)?;
        if parent.trailing_slash {
            return Err(Errno(EEXIST));
        }
        let now = self.now();
        self.vfs
            .create(
                self.host,
                parent.dir,
                &parent.name,
                NewNode::Symlink(target),
                0o777,
                now,
            )
            .map(|_| 0)
    }

    pub fn sys_linkat(
        &mut self,
        old_dirfd: i64,
        old: GuestAddr,
        new_dirfd: i64,
        new: GuestAddr,
        flags: u64,
    ) -> SysResult<u64> {
        if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno(EINVAL));
        }
        let old_path = self.read_path(old)?;
        let Target::Node(ino) = self.lookup_at(
            old_dirfd,
            &old_path,
            flags & AT_SYMLINK_FOLLOW != 0,
            flags & AT_EMPTY_PATH != 0,
        )?
        else {
            return Err(Errno(EPERM));
        };
        let parent = self.parent_at(new_dirfd, new)?;
        let now = self.now();
        self.vfs
            .link(self.host, ino, parent.dir, &parent.name, now)
            .map(|()| 0)
    }

    pub fn sys_fchmodat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        mode: u64,
        flags: u64,
    ) -> SysResult<u64> {
        let ino = self.node_at(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        if self.vfs.file_type(ino) == FileType::Symlink {
            return Err(Errno(EOPNOTSUPP));
        }
        let now = self.now();
        self.vfs.set_perm(ino, mode as u32, now);
        Ok(0)
    }

    pub fn sys_fchmod(&mut self, fd: i64, mode: u64) -> SysResult<u64> {
        let (_, file) = self.file(fd)?;
        let ino = file.node().ok_or(Errno(EINVAL))?;
        let now = self.now();
        self.vfs.set_perm(ino, mode as u32, now);
        Ok(0)
    }

    fn chown(&mut self, ino: Ino, uid: u64, gid: u64) {
        let id = |v: u64| (v as u32 != u32::MAX).then_some(v as u32);
        let now = self.now();
        self.vfs.set_owner(ino, id(uid), id(gid), now);
    }

    pub fn sys_fchownat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        uid: u64,
        gid: u64,
        flags: u64,
    ) -> SysResult<u64> {
        let path = self.read_path(path)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        if let Target::Node(ino) =
            self.lookup_at(dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?
        {
            self.chown(ino, uid, gid);
        }
        Ok(0)
    }

    pub fn sys_fchown(&mut self, fd: i64, uid: u64, gid: u64) -> SysResult<u64> {
        let (_, file) = self.file(fd)?;
        if let Some(ino) = file.node() {
            self.chown(ino, uid, gid);
        }
        Ok(0)
    }

    pub fn sys_utimensat(
        &mut self,
        dirfd: i64,
        path: GuestAddr,
        times: GuestAddr,
        flags: u64,
    ) -> SysResult<u64> {
        let target = if path == 0 {
            // futimens(fd, times).
            self.lookup_at(dirfd, b"", true, true)?
        } else {
            let path = self.read_path(path)?;
            self.lookup_at(
                dirfd,
                &path,
                flags & AT_SYMLINK_NOFOLLOW == 0,
                flags & AT_EMPTY_PATH != 0,
            )?
        };
        let now = self.now();
        let (atime, mtime) = if times == 0 {
            (Some(now), Some(now))
        } else {
            let raw: [u8; 32] = self.read_array(times)?;
            let mut out = [None, None];
            for (i, slot) in out.iter_mut().enumerate() {
                let (sec, nsec) = abi::decode_pair(raw[i * 16..i * 16 + 16].try_into().unwrap());
                *slot = match nsec {
                    UTIME_NOW => Some(now),
                    UTIME_OMIT => None,
                    0..=999_999_999 => Some(Timespec {
                        sec,
                        nsec: nsec as u32,
                    }),
                    _ => return Err(Errno(EINVAL)),
                };
            }
            (out[0], out[1])
        };
        if let Target::Node(ino) = target {
            self.vfs.set_times(ino, atime, mtime, now);
        }
        Ok(0)
    }

    pub fn sys_getcwd(&mut self, buf: GuestAddr, size: u64) -> SysResult<u64> {
        let mut path = self.vfs.dir_path(self.proc().cwd).ok_or(Errno(ENOENT))?;
        path.push(0);
        if path.len() as u64 > size {
            return Err(Errno(crate::errno::ERANGE));
        }
        self.write_mem(buf, &path)?;
        Ok(path.len() as u64)
    }

    fn set_cwd(&mut self, ino: Ino) -> SysResult<u64> {
        if !self.vfs.is_dir(ino) {
            return Err(Errno(ENOTDIR));
        }
        self.vfs.opened(ino);
        let old = std::mem::replace(&mut self.proc_mut().cwd, ino);
        self.vfs.closed(old);
        Ok(0)
    }

    pub fn sys_chdir(&mut self, path: GuestAddr) -> SysResult<u64> {
        let ino = self.node_at(AT_FDCWD, path, true)?;
        self.set_cwd(ino)
    }

    pub fn sys_fchdir(&mut self, fd: i64) -> SysResult<u64> {
        let (_, file) = self.file(fd)?;
        let ino = file.node().ok_or(Errno(ENOTDIR))?;
        self.set_cwd(ino)
    }

    pub fn sys_umask(&mut self, mask: u64) -> SysResult<u64> {
        let old = self.proc().umask;
        self.proc_mut().umask = mask as u32 & 0o777;
        Ok(u64::from(old))
    }

    /// The contents of a file for a file mapping (always a private copy;
    /// see `mm`).
    pub(crate) fn mapping_contents(
        &mut self,
        fd: i64,
        offset: u64,
        len: u64,
        flags: u64,
    ) -> SysResult<Vec<u8>> {
        let (_, file) = self.file(fd)?;
        if flags & MAP_TYPE != MAP_PRIVATE && file.access.writable() {
            log::info!(
                "a shared writable file mapping is a private copy: writes do not reach the file"
            );
        }
        let ino = file.node().ok_or(Errno(crate::errno::EACCES))?;
        if !file.access.readable() {
            return Err(Errno(crate::errno::EACCES));
        }
        match self.vfs.file_type(ino) {
            FileType::Regular => {}
            FileType::CharDevice if self.vfs.device(ino) == Some(Device::Zero) => {
                return Ok(Vec::new())
            }
            _ => return Err(Errno(crate::errno::ENODEV)),
        }
        let size = self.vfs.size(ino);
        let n = len.min(size.saturating_sub(offset)) as usize;
        let mut data = vec![0; n];
        let got = self.vfs.read(self.host, ino, offset, &mut data)?;
        data.truncate(got);
        if offset.checked_add(len).is_none() {
            return Err(Errno(EFAULT));
        }
        Ok(data)
    }
}
