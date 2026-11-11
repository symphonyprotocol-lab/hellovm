//! The per-process file descriptor table and open file descriptions.
//!
//! Descriptions live in an arena with reference counts, so that `dup`ed
//! descriptors share one offset and status flags as on Linux, and the whole
//! table can be cloned (for `fork` in U2 and for snapshotting).

use crate::errno::{Errno, SysResult, EBADF, EINVAL, EMFILE};
use crate::host::ConsoleStream;
use crate::vfs::{DirEntry, Ino};

/// Default `RLIMIT_NOFILE`.
pub const MAX_FDS: usize = 1024;

/// What an open file description refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileObject {
    /// A filesystem node (file, directory, symlink with `O_PATH`, device).
    Node(Ino),
    /// The sandbox console's input.
    ConsoleIn,
    /// The sandbox console's output streams.
    ConsoleOut(ConsoleStream),
}

/// The access mode an open file allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    /// `O_PATH`: neither.
    Path,
}

impl Access {
    pub fn readable(self) -> bool {
        matches!(self, Access::Read | Access::ReadWrite)
    }

    pub fn writable(self) -> bool {
        matches!(self, Access::Write | Access::ReadWrite)
    }
}

/// An open file description.
#[derive(Clone, Debug)]
pub struct OpenFile {
    pub object: FileObject,
    pub access: Access,
    pub append: bool,
    pub nonblock: bool,
    pub offset: u64,
    /// A directory listing taken when reading the directory started, so
    /// that `getdents64` offsets stay stable.
    pub listing: Option<Vec<DirEntry>>,
    refs: u32,
}

impl OpenFile {
    pub fn new(object: FileObject, access: Access) -> OpenFile {
        OpenFile {
            object,
            access,
            append: false,
            nonblock: false,
            offset: 0,
            listing: None,
            refs: 0,
        }
    }

    pub fn node(&self) -> Option<Ino> {
        match self.object {
            FileObject::Node(ino) => Some(ino),
            _ => None,
        }
    }
}

/// An index into the description arena.
pub type FileId = usize;

#[derive(Clone, Copy, Debug)]
struct Slot {
    file: FileId,
    cloexec: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FdTable {
    fds: Vec<Option<Slot>>,
    files: Vec<Option<OpenFile>>,
}

impl FdTable {
    /// A table with the console on fds 0, 1 and 2.
    pub fn with_console() -> FdTable {
        let mut table = FdTable::default();
        for object in [
            FileObject::ConsoleIn,
            FileObject::ConsoleOut(ConsoleStream::Stdout),
            FileObject::ConsoleOut(ConsoleStream::Stderr),
        ] {
            let access = if object == FileObject::ConsoleIn {
                Access::Read
            } else {
                Access::Write
            };
            table
                .install(OpenFile::new(object, access), 0, false)
                .expect("empty table");
        }
        table
    }

    fn slot(&self, fd: i64) -> SysResult<Slot> {
        usize::try_from(fd)
            .ok()
            .and_then(|fd| self.fds.get(fd).copied().flatten())
            .ok_or(Errno(EBADF))
    }

    /// The description behind `fd`.
    pub fn get(&self, fd: i64) -> SysResult<FileId> {
        self.slot(fd).map(|slot| slot.file)
    }

    pub fn file(&self, id: FileId) -> &OpenFile {
        self.files[id].as_ref().expect("live description")
    }

    pub fn file_mut(&mut self, id: FileId) -> &mut OpenFile {
        self.files[id].as_mut().expect("live description")
    }

    fn lowest_free(&self, min: usize) -> SysResult<usize> {
        if min >= MAX_FDS {
            return Err(Errno(EINVAL));
        }
        (min..MAX_FDS)
            .find(|&fd| self.fds.get(fd).is_none_or(|slot| slot.is_none()))
            .ok_or(Errno(EMFILE))
    }

    fn set(&mut self, fd: usize, slot: Slot) {
        if self.fds.len() <= fd {
            self.fds.resize(fd + 1, None);
        }
        self.fds[fd] = Some(slot);
    }

    /// Adds a new description at the lowest free fd `>= min`.
    pub fn install(&mut self, file: OpenFile, min: usize, cloexec: bool) -> SysResult<i64> {
        let fd = self.lowest_free(min)?;
        let id = match self.files.iter().position(Option::is_none) {
            Some(id) => id,
            None => {
                self.files.push(None);
                self.files.len() - 1
            }
        };
        self.files[id] = Some(OpenFile { refs: 1, ..file });
        self.set(fd, Slot { file: id, cloexec });
        Ok(fd as i64)
    }

    /// `dup`/`F_DUPFD`: a new fd for the same description.
    pub fn dup(&mut self, fd: i64, min: usize, cloexec: bool) -> SysResult<i64> {
        let slot = self.slot(fd)?;
        let new = self.lowest_free(min)?;
        self.file_mut(slot.file).refs += 1;
        self.set(new, Slot {
            file: slot.file,
            cloexec,
        });
        Ok(new as i64)
    }

    /// `dup2`/`dup3`: makes `new` refer to `old`'s description, closing
    /// what `new` referred to. Returns that description if it is gone now.
    pub fn dup_to(&mut self, old: i64, new: i64, cloexec: bool) -> SysResult<Option<OpenFile>> {
        let slot = self.slot(old)?;
        let new = usize::try_from(new)
            .ok()
            .filter(|&fd| fd < MAX_FDS)
            .ok_or(Errno(EBADF))?;
        let released = match self.fds.get(new).copied().flatten() {
            Some(_) => self.close(new as i64)?,
            None => None,
        };
        self.file_mut(slot.file).refs += 1;
        self.set(new, Slot {
            file: slot.file,
            cloexec,
        });
        Ok(released)
    }

    /// Closes `fd`. Returns its description if this was the last reference.
    pub fn close(&mut self, fd: i64) -> SysResult<Option<OpenFile>> {
        let slot = self.slot(fd)?;
        self.fds[fd as usize] = None;
        let file = self.file_mut(slot.file);
        file.refs -= 1;
        if file.refs == 0 {
            return Ok(self.files[slot.file].take());
        }
        Ok(None)
    }

    pub fn cloexec(&self, fd: i64) -> SysResult<bool> {
        self.slot(fd).map(|slot| slot.cloexec)
    }

    pub fn set_cloexec(&mut self, fd: i64, cloexec: bool) -> SysResult<()> {
        let slot = self.slot(fd)?;
        self.fds[fd as usize] = Some(Slot { cloexec, ..slot });
        Ok(())
    }

    /// Every open fd.
    pub fn fds(&self) -> Vec<i64> {
        (0..self.fds.len())
            .filter(|&fd| self.fds[fd].is_some())
            .map(|fd| fd as i64)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dup_shares_the_description() {
        let mut t = FdTable::with_console();
        assert_eq!(t.fds(), vec![0, 1, 2]);
        let fd = t
            .install(OpenFile::new(FileObject::Node(7), Access::Read), 0, false)
            .unwrap();
        assert_eq!(fd, 3);
        let d = t.dup(fd, 10, true).unwrap();
        assert_eq!(d, 10);
        assert!(t.cloexec(d).unwrap());
        assert!(!t.cloexec(fd).unwrap());
        let id = t.get(fd).unwrap();
        t.file_mut(id).offset = 42;
        assert_eq!(t.file(t.get(d).unwrap()).offset, 42);
        assert!(t.close(fd).unwrap().is_none());
        let last = t.close(d).unwrap().unwrap();
        assert_eq!(last.object, FileObject::Node(7));
        assert_eq!(t.close(d).unwrap_err(), Errno(EBADF));
    }

    #[test]
    fn dup_to_replaces_and_reports_released() {
        let mut t = FdTable::with_console();
        let fd = t
            .install(OpenFile::new(FileObject::Node(9), Access::Write), 0, false)
            .unwrap();
        // fd 1 (console out) is replaced; its description is still shared
        // with nobody, so it is released.
        let released = t.dup_to(fd, 1, false).unwrap().unwrap();
        assert_eq!(released.object, FileObject::ConsoleOut(ConsoleStream::Stdout));
        assert_eq!(t.get(1).unwrap(), t.get(fd).unwrap());
        assert_eq!(t.dup_to(fd, MAX_FDS as i64, false).unwrap_err(), Errno(EBADF));
        assert_eq!(t.dup_to(50, 4, false).unwrap_err(), Errno(EBADF));
        // Lowest free fd after a close.
        t.close(0).unwrap();
        let fd = t.dup(2, 0, false).unwrap();
        assert_eq!(fd, 0);
    }
}
