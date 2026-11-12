//! File, path and fd syscalls.

use crate::abi;
use crate::errno::{
    Errno, SysResult, EACCES, EBADF, EEXIST, EFAULT, EINVAL, EISDIR, ELOOP, ENOENT, ENOSPC,
    ENOTDIR, ENOTTY, ENXIO, EOPNOTSUPP, EPERM, ESPIPE,
};
use crate::fd::{Access, FileId, FileObject, OpenFile, MAX_FDS};
use crate::host::Host;
use crate::platform::{GuestAddr, Platform};
use crate::vfs::{
    CreateTarget, Device, DirEntry, FileType, Ino, NewNode, Stat, Timespec, S_IFCHR, S_IFMT,
    S_IFREG,
};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Node(Ino),
    /// A console fd (via `AT_EMPTY_PATH` or `fstat`).
    Console(FileObject),
}

/// A `stat` for the console: a character device that is not a terminal.
fn console_stat(object: FileObject, time: Timespec) -> Stat {
    Stat {
        dev: 0x05,
        ino: match object {
            FileObject::ConsoleIn => 0x10,
            _ => 0x11,
        },
        mode: S_IFCHR | 0o620,
        nlink: 1,
        rdev: crate::vfs::makedev(5, 1),
        blksize: 1024,
        atime: time,
        mtime: time,
        ctime: time,
        ..Stat::default()
    }
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    // ----- helpers -----

    fn file(&self, fd: i64) -> SysResult<(FileId, &OpenFile)> {
        let id = self.proc.fds.get(fd)?;
        Ok((id, self.proc.fds.file(id)))
    }

    /// Releases a description that lost its last fd.
    pub(crate) fn release(&mut self, file: Option<OpenFile>) {
        if let Some(ino) = file.and_then(|f| f.node()) {
            self.vfs.closed(ino);
        }
    }

    /// The directory a relative path in an `*at` call starts from.
    fn start_dir(&mut self, dirfd: i64, path: &[u8]) -> SysResult<Ino> {
        if path.first() == Some(&b'/') {
            return Ok(self.vfs.root());
        }
        if dirfd == AT_FDCWD {
            return Ok(self.proc.cwd);
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
                return Ok(Target::Node(self.proc.cwd));
            }
            let (_, file) = self.file(dirfd)?;
            return Ok(match file.object {
                FileObject::Node(ino) => Target::Node(ino),
                other => Target::Console(other),
            });
        }
        let start = self.start_dir(dirfd, path)?;
        Ok(Target::Node(
            self.vfs.resolve(self.host, start, path, follow)?,
        ))
    }

    fn node_at(&mut self, dirfd: i64, path_addr: GuestAddr, follow: bool) -> SysResult<Ino> {
        let path = self.read_path(path_addr)?;
        match self.lookup_at(dirfd, &path, follow, false)? {
            Target::Node(ino) => Ok(ino),
            Target::Console(_) => Err(Errno(EINVAL)),
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
            Target::Console(object) => {
                let time = self.now();
                console_stat(object, time)
            }
        }
    }

    // ----- data -----

    /// Reads up to `len` bytes from a description, at `offset` or at (and
    /// advancing) its file position.
    fn read_file(&mut self, id: FileId, offset: Option<u64>, len: usize) -> SysResult<Vec<u8>> {
        let file = self.proc.fds.file(id);
        if !file.access.readable() {
            return Err(Errno(EBADF));
        }
        let len = len.min(MAX_IO);
        let mut buf = vec![0u8; len];
        let n = match file.object {
            FileObject::ConsoleIn => {
                if offset.is_some() {
                    return Err(Errno(ESPIPE));
                }
                self.host.console_read(&mut buf).map_err(|err| {
                    log::warn!("console read failed on the host: {err}");
                    Errno::from_host(&err)
                })?
            }
            FileObject::ConsoleOut(_) => return Err(Errno(EBADF)),
            FileObject::Node(ino) => match self.vfs.device(ino) {
                Some(Device::Null) => 0,
                Some(Device::Zero | Device::Full) => len,
                Some(Device::Random | Device::Urandom) => {
                    self.host
                        .random(&mut buf)
                        .map_err(|e| Errno::from_host(&e))?;
                    len
                }
                Some(Device::Fd(_) | Device::Unusable) => return Err(Errno(ENXIO)),
                None => {
                    let pos = offset.unwrap_or(file.offset);
                    let n = self.vfs.read(self.host, ino, pos, &mut buf)?;
                    if offset.is_none() {
                        self.proc.fds.file_mut(id).offset = pos + n as u64;
                    }
                    n
                }
            },
        };
        buf.truncate(n);
        Ok(buf)
    }

    /// Writes `data` to a description, at `offset` or at (and advancing) its
    /// file position.
    fn write_file(&mut self, id: FileId, offset: Option<u64>, data: &[u8]) -> SysResult<usize> {
        let file = self.proc.fds.file(id);
        if !file.access.writable() {
            return Err(Errno(EBADF));
        }
        match file.object {
            FileObject::ConsoleIn => Err(Errno(EBADF)),
            FileObject::ConsoleOut(stream) => {
                if offset.is_some() {
                    return Err(Errno(ESPIPE));
                }
                if data.is_empty() {
                    return Ok(0);
                }
                self.host.console_write(stream, data).map_err(|err| {
                    // Host errno values are not guest errno values; do not
                    // pass them through.
                    log::warn!("console write failed on the host: {err}");
                    Errno(crate::errno::EIO)
                })
            }
            FileObject::Node(ino) => match self.vfs.device(ino) {
                Some(Device::Full) => Err(Errno(ENOSPC)),
                Some(Device::Fd(_) | Device::Unusable) => Err(Errno(ENXIO)),
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
                        self.proc.fds.file_mut(id).offset = pos + n as u64;
                    }
                    Ok(n)
                }
            },
        }
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
        let console = file.object == FileObject::ConsoleIn;
        let before = file.offset;
        if console && len > 0 {
            // Console input cannot be put back: make sure the buffer can
            // take at least a byte before consuming any.
            self.probe_writable(buf)?;
        }
        let data = self.read_file(id, offset, len as usize)?;
        let done = self.write_mem_prefix(buf, &data);
        self.finish_read(id, offset, before, data.len(), done)
    }

    /// Checks that the guest byte at `addr` is writable, leaving it as is.
    fn probe_writable(&mut self, addr: GuestAddr) -> SysResult<()> {
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
            let file = self.proc.fds.file_mut(id);
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
        self.write_file(id, offset, &data).map(|n| n as u64)
    }

    fn seekable(&self, fd: i64) -> SysResult<()> {
        let (_, file) = self.file(fd)?;
        match file.object {
            FileObject::Node(ino) if self.vfs.file_type(ino) == FileType::Regular => Ok(()),
            FileObject::Node(_) => Ok(()),
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
        let (id, _) = self.file(fd)?;
        if offset.is_some() {
            self.seekable(fd)?;
        }
        let iovecs = self.read_iovecs(iov, count)?;
        // Guest-chosen lengths: the sum must not overflow.
        let total = iovecs
            .iter()
            .fold(0u64, |sum, v| sum.saturating_add(v.1))
            .min(MAX_IO as u64);
        let file = self.proc.fds.file(id);
        let before = file.offset;
        if file.object == FileObject::ConsoleIn {
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
        self.write_file(id, offset, &data).map(|n| n as u64)
    }

    pub fn sys_sendfile(
        &mut self,
        out_fd: i64,
        in_fd: i64,
        offset_ptr: GuestAddr,
        count: u64,
    ) -> SysResult<u64> {
        let (out_id, _) = self.file(out_fd)?;
        let (in_id, _) = self.file(in_fd)?;
        let offset = if offset_ptr != 0 {
            Some(self.read_u64(offset_ptr)?)
        } else {
            None
        };
        let data = self.read_file(in_id, offset, count as usize)?;
        let n = self.write_file(out_id, None, &data)?;
        if let Some(offset) = offset {
            self.write_u64(offset_ptr, offset + n as u64)?;
        } else if n < data.len() {
            // Give back what was read but not written.
            let file = self.proc.fds.file_mut(in_id);
            file.offset -= (data.len() - n) as u64;
        }
        Ok(n as u64)
    }

    pub fn sys_lseek(&mut self, fd: i64, offset: i64, whence: i64) -> SysResult<u64> {
        const SEEK_SET: i64 = 0;
        const SEEK_CUR: i64 = 1;
        const SEEK_END: i64 = 2;
        let (id, file) = self.file(fd)?;
        let Some(ino) = file.node() else {
            return Err(Errno(ESPIPE));
        };
        if self.vfs.device(ino).is_some() {
            return Ok(0);
        }
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => file.offset as i64,
            SEEK_END => self.vfs.size(ino) as i64,
            _ => return Err(Errno(EINVAL)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(EINVAL))?;
        let is_dir = self.vfs.is_dir(ino);
        let file = self.proc.fds.file_mut(id);
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
        let flags = abi::decode_open_flags(self.arch, raw_flags);
        let path = self.read_path(path_addr)?;
        if flags.tmpfile {
            return Err(Errno(EOPNOTSUPP));
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
                    let perm = (mode as u32) & 0o7777 & !self.proc.umask;
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
                        .proc
                        .fds
                        .dup(i64::from(target), 0, flags.cloexec)
                        .map(|fd| fd as u64)
                        .map_err(|e| if e == Errno(EBADF) { Errno(ENXIO) } else { e });
                }
                Some(Device::Unusable) => return Err(Errno(ENXIO)),
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
        self.vfs.opened(ino);
        match self.proc.fds.install(file, 0, flags.cloexec) {
            Ok(fd) => Ok(fd as u64),
            Err(err) => {
                self.vfs.closed(ino);
                Err(err)
            }
        }
    }

    pub fn sys_creat(&mut self, path: GuestAddr, mode: u64) -> SysResult<u64> {
        let flags = 1 | abi::O_CREAT | abi::O_TRUNC;
        self.sys_openat(AT_FDCWD, path, flags, mode)
    }

    pub fn sys_close(&mut self, fd: i64) -> SysResult<u64> {
        let released = self.proc.fds.close(fd)?;
        self.release(released);
        Ok(0)
    }

    pub fn sys_close_range(&mut self, first: u64, last: u64, flags: u64) -> SysResult<u64> {
        const CLOSE_RANGE_CLOEXEC: u64 = 4;
        if first > last || flags & !CLOSE_RANGE_CLOEXEC != 0 {
            return Err(Errno(EINVAL));
        }
        for fd in self.proc.fds.fds() {
            if (first..=last).contains(&(fd as u64)) {
                if flags & CLOSE_RANGE_CLOEXEC != 0 {
                    self.proc.fds.set_cloexec(fd, true)?;
                } else {
                    self.sys_close(fd)?;
                }
            }
        }
        Ok(0)
    }

    pub fn sys_dup(&mut self, fd: i64) -> SysResult<u64> {
        self.proc.fds.dup(fd, 0, false).map(|fd| fd as u64)
    }

    pub fn sys_dup2(&mut self, old: i64, new: i64) -> SysResult<u64> {
        if old == new {
            self.proc.fds.get(old)?;
            return Ok(new as u64);
        }
        self.sys_dup3(old, new, 0)
    }

    pub fn sys_dup3(&mut self, old: i64, new: i64, flags: u64) -> SysResult<u64> {
        if old == new || flags & !abi::O_CLOEXEC != 0 {
            return Err(Errno(EINVAL));
        }
        let released = self.proc.fds.dup_to(old, new, flags != 0)?;
        self.release(released);
        Ok(new as u64)
    }

    pub fn sys_fcntl(&mut self, fd: i64, cmd: i64, arg: u64) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let min = usize::try_from(int(arg)).map_err(|_| Errno(EINVAL))?;
                if min >= MAX_FDS {
                    return Err(Errno(EINVAL));
                }
                self.proc
                    .fds
                    .dup(fd, min, cmd == F_DUPFD_CLOEXEC)
                    .map(|fd| fd as u64)
            }
            F_GETFD => Ok(u64::from(self.proc.fds.cloexec(fd)?)),
            F_SETFD => self
                .proc
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
                let file = self.proc.fds.file_mut(id);
                file.append = arg & abi::O_APPEND != 0;
                file.nonblock = arg & abi::O_NONBLOCK != 0;
                Ok(0)
            }
            F_GETLK | F_OFD_GETLK => {
                // There is no other process to hold a lock: report l_type
                // F_UNLCK (the first field of struct flock).
                self.write_mem(arg, &F_UNLCK.to_le_bytes())?;
                Ok(0)
            }
            F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => Ok(0),
            _ => {
                log::warn!("unimplemented fcntl command {cmd}");
                Err(Errno(EINVAL))
            }
        }
    }

    pub fn sys_ioctl(&mut self, fd: i64, request: u64, arg: u64) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        match request & 0xffff_ffff {
            FIOCLEX => self.proc.fds.set_cloexec(fd, true).map(|()| 0),
            FIONCLEX => self.proc.fds.set_cloexec(fd, false).map(|()| 0),
            FIONREAD => match file.node() {
                Some(ino) if self.vfs.file_type(ino) == FileType::Regular => {
                    let left = self
                        .vfs
                        .size(ino)
                        .saturating_sub(self.proc.fds.file(id).offset);
                    self.write_u32(arg, left.min(i32::MAX as u64) as u32)?;
                    Ok(0)
                }
                _ => Err(Errno(ENOTTY)),
            },
            // Nothing is a terminal in U1: every tty request (TCGETS,
            // TIOCGWINSZ, TIOCGPGRP, ...) fails as on a pipe or file.
            _ => Err(Errno(ENOTTY)),
        }
    }

    fn poll_one(&self, fd: i64, events: u16) -> u16 {
        // Files, devices and the console never block for readiness.
        match self.proc.fds.get(fd) {
            Err(_) => POLLNVAL,
            Ok(_) => events & (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM),
        }
    }

    pub fn sys_poll(
        &mut self,
        fds: GuestAddr,
        nfds: u64,
        timeout_ms: Option<i64>,
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
                self.poll_one(i64::from(fd), events)
            };
            entry[6..8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready += 1;
            }
        }
        self.write_mem(fds, &raw)?;
        if ready == 0 {
            match timeout_ms {
                Some(ms) if ms >= 0 => self.host.sleep(std::time::Duration::from_millis(ms as u64)),
                _ => {
                    log::warn!("poll would block forever (nothing can become ready)");
                    return Err(Errno(crate::errno::EINTR));
                }
            }
        }
        Ok(ready)
    }

    pub fn sys_ppoll(&mut self, fds: GuestAddr, nfds: u64, timeout: GuestAddr) -> SysResult<u64> {
        let timeout_ms = if timeout == 0 {
            None
        } else {
            let (sec, nsec) = abi::decode_pair(&self.read_array(timeout)?);
            Some(sec.saturating_mul(1000).saturating_add(nsec / 1_000_000))
        };
        self.sys_poll(fds, nfds, timeout_ms)
    }

    /// `select`/`pselect6`: every valid fd is ready for reading and writing.
    /// With nothing to report, the call sleeps for its timeout, a `timeval`
    /// (`select`) or a `timespec` (`pselect6`) at `timeout`.
    pub fn sys_select(
        &mut self,
        nfds: i64,
        readfds: GuestAddr,
        writefds: GuestAddr,
        exceptfds: GuestAddr,
        timeout: GuestAddr,
        timeout_is_timespec: bool,
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
            Some(std::time::Duration::new(
                sec as u64,
                (sub * to_nanos) as u32,
            ))
        };
        if !(0..=MAX_FDS as i64).contains(&nfds) {
            return Err(Errno(EINVAL));
        }
        let bytes = (nfds as usize).div_ceil(64) * 8;
        let mut ready = 0;
        for set in [readfds, writefds] {
            if set == 0 {
                continue;
            }
            let bits = self.read_mem(set, bytes)?;
            for fd in 0..nfds as usize {
                if bits[fd / 8] & (1 << (fd % 8)) != 0 {
                    self.proc.fds.get(fd as i64)?;
                    ready += 1;
                }
            }
        }
        if exceptfds != 0 {
            self.write_mem(exceptfds, &vec![0; bytes])?;
        }
        if ready == 0 {
            match timeout {
                Some(duration) => self.host.sleep(duration),
                None => {
                    log::warn!("select would block forever (nothing can become ready)");
                    return Err(Errno(crate::errno::EINTR));
                }
            }
        }
        Ok(ready)
    }

    pub fn sys_fsync(&mut self, fd: i64) -> SysResult<u64> {
        self.proc.fds.get(fd)?;
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
            other => Target::Console(other),
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
        let Target::Node(ino) = self.lookup_at(dirfd, &path, false, true)? else {
            return Err(Errno(EINVAL));
        };
        let target = self.vfs.read_link(ino)?;
        let n = target.len().min(size as usize);
        self.write_mem(buf, &target[..n])?;
        Ok(n as u64)
    }

    pub fn sys_getdents64(&mut self, fd: i64, buf: GuestAddr, count: u64) -> SysResult<u64> {
        let (id, file) = self.file(fd)?;
        let ino = file.node().ok_or(Errno(ENOTDIR))?;
        if !self.vfs.is_dir(ino) {
            return Err(Errno(ENOTDIR));
        }
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
            self.proc.fds.file_mut(id).listing = Some(listing);
        }
        let file = self.proc.fds.file(id);
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
        self.proc.fds.file_mut(id).offset = index as u64;
        Ok(out.len() as u64)
    }

    // ----- namespace changes -----

    pub fn sys_mkdirat(&mut self, dirfd: i64, path: GuestAddr, mode: u64) -> SysResult<u64> {
        let parent = self.parent_at(dirfd, path)?;
        let perm = (mode as u32) & 0o7777 & !self.proc.umask;
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
        let perm = (mode as u32) & 0o7777 & !self.proc.umask;
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
        let mut path = self.vfs.dir_path(self.proc.cwd).ok_or(Errno(ENOENT))?;
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
        let old = std::mem::replace(&mut self.proc.cwd, ino);
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
        let old = self.proc.umask;
        self.proc.umask = mask as u32 & 0o777;
        Ok(u64::from(old))
    }

    /// The contents of a file for a private file mapping.
    pub(crate) fn mapping_contents(
        &mut self,
        fd: i64,
        offset: u64,
        len: u64,
    ) -> SysResult<Vec<u8>> {
        let (_, file) = self.file(fd)?;
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
