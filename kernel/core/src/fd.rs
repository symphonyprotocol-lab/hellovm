//! File descriptor tables and open file descriptions.
//!
//! Open file descriptions live in one arena per sandbox ([`Files`]) with
//! reference counts, and each process has an [`FdTable`] mapping its fds to
//! them. So `dup`ed descriptors, and the descriptors a child inherits with
//! `fork`, share one offset and one set of status flags, as on Linux.

use crate::errno::{Errno, SysResult, EBADF, EINVAL, EMFILE};
use crate::host::ConsoleStream;
use crate::vfs::{DirEntry, Ino};

/// Default `RLIMIT_NOFILE`.
pub const MAX_FDS: usize = 1024;

/// An index into the pipe arena.
pub type PipeId = usize;

/// What an open file description refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileObject {
    /// A filesystem node (file, directory, symlink with `O_PATH`, device).
    Node(Ino),
    /// The sandbox console's input, when the console is plain streams.
    ConsoleIn,
    /// The sandbox console's output streams, when the console is plain
    /// streams.
    ConsoleOut(ConsoleStream),
    /// The sandbox terminal, when the console is a terminal.
    Tty,
    /// The read end of a pipe.
    PipeRead(PipeId),
    /// The write end of a pipe.
    PipeWrite(PipeId),
    /// A generated file of `/proc`; its contents are in
    /// [`OpenFile::contents`] (or, for a directory, its listing).
    Proc { dir: bool },
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
    /// The absolute path the file was opened with, for `/proc/<pid>/fd`.
    pub path: Option<Vec<u8>>,
    /// The contents of a generated (`/proc`) file.
    pub contents: Option<Vec<u8>>,
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
            path: None,
            contents: None,
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

/// Most open file descriptions in one sandbox.
pub const MAX_FILES: usize = 64 * 1024;

/// The sandbox's open file descriptions.
#[derive(Clone, Debug, Default)]
pub struct Files {
    slots: Vec<Option<OpenFile>>,
    free: Vec<FileId>,
}

impl Files {
    pub fn get(&self, id: FileId) -> &OpenFile {
        self.slots[id].as_ref().expect("live description")
    }

    pub fn get_mut(&mut self, id: FileId) -> &mut OpenFile {
        self.slots[id].as_mut().expect("live description")
    }

    fn add(&mut self, file: OpenFile) -> SysResult<FileId> {
        let file = OpenFile { refs: 1, ..file };
        if let Some(id) = self.free.pop() {
            self.slots[id] = Some(file);
            return Ok(id);
        }
        if self.slots.len() >= MAX_FILES {
            return Err(Errno(crate::errno::ENFILE));
        }
        self.slots.push(Some(file));
        Ok(self.slots.len() - 1)
    }

    fn add_ref(&mut self, id: FileId) {
        self.get_mut(id).refs += 1;
    }

    /// Drops one reference; returns the description if it was the last.
    fn drop_ref(&mut self, id: FileId) -> Option<OpenFile> {
        let file = self.get_mut(id);
        file.refs -= 1;
        if file.refs == 0 {
            self.free.push(id);
            return self.slots[id].take();
        }
        None
    }

    /// How many open file descriptions exist.
    pub fn len(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every live description.
    pub fn iter(&self) -> impl Iterator<Item = (FileId, &OpenFile)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(id, f)| f.as_ref().map(|f| (id, f)))
    }
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    file: FileId,
    cloexec: bool,
}

/// A process's file descriptors. Each one holds a reference to a
/// description in [`Files`]; the table must be emptied with
/// [`FdTable::close_all`] before it is dropped.
#[derive(Debug, Default)]
pub struct FdTable {
    fds: Vec<Option<Slot>>,
}

impl FdTable {
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
    pub fn install(
        &mut self,
        files: &mut Files,
        file: OpenFile,
        min: usize,
        cloexec: bool,
    ) -> SysResult<i64> {
        let fd = self.lowest_free(min)?;
        let id = files.add(file)?;
        self.set(fd, Slot { file: id, cloexec });
        Ok(fd as i64)
    }

    /// `dup`/`F_DUPFD`: a new fd for the same description.
    pub fn dup(&mut self, files: &mut Files, fd: i64, min: usize, cloexec: bool) -> SysResult<i64> {
        let slot = self.slot(fd)?;
        let new = self.lowest_free(min)?;
        files.add_ref(slot.file);
        self.set(
            new,
            Slot {
                file: slot.file,
                cloexec,
            },
        );
        Ok(new as i64)
    }

    /// `dup2`/`dup3`: makes `new` refer to `old`'s description, closing
    /// what `new` referred to. Returns that description if it is gone now.
    pub fn dup_to(
        &mut self,
        files: &mut Files,
        old: i64,
        new: i64,
        cloexec: bool,
    ) -> SysResult<Option<OpenFile>> {
        let slot = self.slot(old)?;
        let new = usize::try_from(new)
            .ok()
            .filter(|&fd| fd < MAX_FDS)
            .ok_or(Errno(EBADF))?;
        files.add_ref(slot.file);
        let released = match self.fds.get(new).copied().flatten() {
            Some(_) => self.close(files, new as i64)?,
            None => None,
        };
        self.set(
            new,
            Slot {
                file: slot.file,
                cloexec,
            },
        );
        Ok(released)
    }

    /// Closes `fd`. Returns its description if this was the last reference.
    pub fn close(&mut self, files: &mut Files, fd: i64) -> SysResult<Option<OpenFile>> {
        let slot = self.slot(fd)?;
        self.fds[fd as usize] = None;
        Ok(files.drop_ref(slot.file))
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

    /// A copy of the table for a `fork`ed child: the same fds, sharing the
    /// same descriptions.
    pub fn fork(&self, files: &mut Files) -> FdTable {
        for slot in self.fds.iter().flatten() {
            files.add_ref(slot.file);
        }
        FdTable {
            fds: self.fds.clone(),
        }
    }

    /// Closes the fds marked close-on-exec; returns the descriptions that
    /// are gone now.
    pub fn close_on_exec(&mut self, files: &mut Files) -> Vec<OpenFile> {
        let mut released = Vec::new();
        for fd in 0..self.fds.len() {
            if let Some(slot) = self.fds[fd] {
                if slot.cloexec {
                    self.fds[fd] = None;
                    released.extend(files.drop_ref(slot.file));
                }
            }
        }
        released
    }

    /// Closes every fd; returns the descriptions that are gone now.
    pub fn close_all(&mut self, files: &mut Files) -> Vec<OpenFile> {
        let mut released = Vec::new();
        for slot in std::mem::take(&mut self.fds).into_iter().flatten() {
            released.extend(files.drop_ref(slot.file));
        }
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(files: &mut Files) -> FdTable {
        let mut t = FdTable::default();
        for object in [
            FileObject::ConsoleIn,
            FileObject::ConsoleOut(ConsoleStream::Stdout),
            FileObject::ConsoleOut(ConsoleStream::Stderr),
        ] {
            t.install(files, OpenFile::new(object, Access::ReadWrite), 0, false)
                .unwrap();
        }
        t
    }

    #[test]
    fn dup_shares_the_description() {
        let mut files = Files::default();
        let mut t = console(&mut files);
        assert_eq!(t.fds(), vec![0, 1, 2]);
        let fd = t
            .install(
                &mut files,
                OpenFile::new(FileObject::Node(7), Access::Read),
                0,
                false,
            )
            .unwrap();
        assert_eq!(fd, 3);
        let d = t.dup(&mut files, fd, 10, true).unwrap();
        assert_eq!(d, 10);
        assert!(t.cloexec(d).unwrap());
        assert!(!t.cloexec(fd).unwrap());
        let id = t.get(fd).unwrap();
        files.get_mut(id).offset = 42;
        assert_eq!(files.get(t.get(d).unwrap()).offset, 42);
        assert!(t.close(&mut files, fd).unwrap().is_none());
        let last = t.close(&mut files, d).unwrap().unwrap();
        assert_eq!(last.object, FileObject::Node(7));
        assert_eq!(t.close(&mut files, d).unwrap_err(), Errno(EBADF));
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn dup_to_replaces_and_reports_released() {
        let mut files = Files::default();
        let mut t = console(&mut files);
        let fd = t
            .install(
                &mut files,
                OpenFile::new(FileObject::Node(9), Access::Write),
                0,
                false,
            )
            .unwrap();
        let released = t.dup_to(&mut files, fd, 1, false).unwrap().unwrap();
        assert_eq!(
            released.object,
            FileObject::ConsoleOut(ConsoleStream::Stdout)
        );
        assert_eq!(t.get(1).unwrap(), t.get(fd).unwrap());
        // dup2 of an fd onto itself keeps the description alive.
        assert!(t.dup_to(&mut files, 1, 1, false).unwrap().is_none());
        assert_eq!(files.get(t.get(1).unwrap()).object, FileObject::Node(9));
        assert_eq!(
            t.dup_to(&mut files, fd, MAX_FDS as i64, false).unwrap_err(),
            Errno(EBADF)
        );
        assert_eq!(
            t.dup_to(&mut files, 50, 4, false).unwrap_err(),
            Errno(EBADF)
        );
        t.close(&mut files, 0).unwrap();
        let fd = t.dup(&mut files, 2, 0, false).unwrap();
        assert_eq!(fd, 0);
    }

    #[test]
    fn fork_shares_descriptions_and_exec_closes_cloexec() {
        let mut files = Files::default();
        let mut parent = console(&mut files);
        let fd = parent
            .install(
                &mut files,
                OpenFile::new(FileObject::Node(5), Access::Read),
                0,
                true,
            )
            .unwrap();
        let mut child = parent.fork(&mut files);
        files.get_mut(child.get(fd).unwrap()).offset = 7;
        assert_eq!(files.get(parent.get(fd).unwrap()).offset, 7);
        assert!(
            child.close_on_exec(&mut files).is_empty(),
            "parent keeps it"
        );
        assert_eq!(child.fds(), vec![0, 1, 2]);
        let released = parent.close_all(&mut files);
        assert_eq!(released.len(), 1);
        assert_eq!(child.close_all(&mut files).len(), 3);
        assert!(files.is_empty());
    }
}
