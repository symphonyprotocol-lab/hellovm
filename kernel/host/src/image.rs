//! [`ImageDir`]: a host directory served as the read-only image layer.
//!
//! The core only ever asks about [`ImagePath`]s it built itself from plain
//! names, and it never asks to follow a symlink. This module still treats
//! every request as untrusted and checks it again:
//!
//! * every component must be a plain name (no `..`, `.`, `/` or NUL);
//! * the directory is opened once, by [`ImageDir::open`], and every lookup
//!   after that walks from that directory fd one component at a time with
//!   `openat(..., O_NOFOLLOW | O_DIRECTORY)`, so a symlink anywhere on the
//!   way (pointing inside or outside the image) is never followed and no
//!   host path is ever named;
//! * the last component is looked at with `fstatat(AT_SYMLINK_NOFOLLOW)` or
//!   `readlinkat`, and a file is read only if it is a regular file, checked
//!   before it is opened (`O_NOFOLLOW | O_NONBLOCK`, so a FIFO or device
//!   node in the image is never opened) and again on the open fd.
//!
//! This gives the guarantees of `openat2(RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS)` with plain POSIX calls (also on macOS) and without
//! the race of checking a path and then opening it again: a host-side
//! change to the image directory can at most make one lookup fail or see
//! the new entry, never leave the image. The kernel process can keep
//! serving the image after it confines itself (U4): it needs only the
//! directory fd, which works under Landlock and after `pivot_root`.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use hellovm_core::host::{HostFileKind, HostStat, ImagePath};

use crate::fsys;

/// How many image files are kept open between reads.
const OPEN_FILES: usize = 16;

#[derive(Debug)]
pub struct ImageDir {
    root: PathBuf,
    dir: OwnedFd,
    /// Recently read files, most recent last.
    open: Vec<(ImagePath, File)>,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

// `mode_t` is `u32` on Linux and `u16` on macOS.
#[allow(clippy::unnecessary_cast)]
fn kind(mode: u32) -> HostFileKind {
    match mode & libc::S_IFMT as u32 {
        m if m == libc::S_IFLNK as u32 => HostFileKind::Symlink,
        m if m == libc::S_IFDIR as u32 => HostFileKind::Directory,
        m if m == libc::S_IFREG as u32 => HostFileKind::File,
        _ => HostFileKind::Other,
    }
}

/// A lookup result: the directory holding the entry, and its name (`None`
/// for the image root itself).
struct Entry<'a> {
    parent: Option<OwnedFd>,
    root: BorrowedFd<'a>,
    name: Option<Vec<u8>>,
}

impl Entry<'_> {
    fn dir(&self) -> BorrowedFd<'_> {
        self.parent.as_ref().map_or(self.root, |fd| fd.as_fd())
    }
}

impl ImageDir {
    /// Serves `root`, which must be a directory.
    pub fn open(root: impl AsRef<Path>) -> io::Result<ImageDir> {
        let root = std::fs::canonicalize(root)?;
        let dir = File::open(&root)?;
        if !dir.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", root.display()),
            ));
        }
        Ok(ImageDir {
            root,
            dir: dir.into(),
            open: Vec::new(),
        })
    }

    /// The host path the image was opened from (for messages only: lookups
    /// never use it).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The image's directory fd.
    pub fn dir_fd(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// Walks to the directory holding `path`'s last component, checking
    /// that every component is a plain name and every directory on the way
    /// is a real directory, not a symlink.
    fn lookup(&self, path: &ImagePath) -> io::Result<Entry<'_>> {
        let names: Vec<&[u8]> = path.components().collect();
        for name in &names {
            if !ImagePath::valid_name(name) {
                return Err(invalid("invalid image path component"));
            }
        }
        let mut parent: Option<OwnedFd> = None;
        let Some((last, dirs)) = names.split_last() else {
            return Ok(Entry {
                parent: None,
                root: self.dir.as_fd(),
                name: None,
            });
        };
        for name in dirs {
            let at = parent.as_ref().map_or(self.dir.as_fd(), |fd| fd.as_fd());
            let next = fsys::open_at(at, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(
                |err| match err.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "image path goes through a non-directory",
                    ),
                    _ => err,
                },
            )?;
            parent = Some(next);
        }
        Ok(Entry {
            parent,
            root: self.dir.as_fd(),
            name: Some(last.to_vec()),
        })
    }

    pub fn stat(&mut self, path: &ImagePath) -> io::Result<HostStat> {
        let entry = self.lookup(path)?;
        let st = fsys::stat_at(entry.dir(), entry.name.as_deref())?;
        Ok(HostStat {
            kind: kind(st.mode),
            mode: st.mode & 0o7777,
            size: st.size,
            nlink: st.nlink,
            mtime: (st.mtime, st.mtime_nsec.clamp(0, 999_999_999) as u32),
        })
    }

    pub fn read_link(&mut self, path: &ImagePath) -> io::Result<Vec<u8>> {
        let entry = self.lookup(path)?;
        let name = entry
            .name
            .as_deref()
            .ok_or_else(|| invalid("not a symlink"))?;
        fsys::read_link_at(entry.dir(), name)
    }

    pub fn read_dir(&mut self, path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
        let entry = self.lookup(path)?;
        let name = entry.name.as_deref().unwrap_or(b".");
        let dir = fsys::open_at(entry.dir(), name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(
            |err| match err.raw_os_error() {
                Some(libc::ELOOP) => io::ErrorKind::NotADirectory.into(),
                _ => err,
            },
        )?;
        fsys::list(dir)
    }

    pub fn read(&mut self, path: &ImagePath, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let index = match self.open.iter().position(|(p, _)| p == path) {
            Some(index) => index,
            None => {
                let file = self.open_file(path)?;
                if self.open.len() == OPEN_FILES {
                    self.open.remove(0);
                }
                self.open.push((path.clone(), file));
                self.open.len() - 1
            }
        };
        let entry = self.open.remove(index);
        let result = entry.1.read_at(buf, offset);
        self.open.push(entry);
        result
    }

    fn open_file(&self, path: &ImagePath) -> io::Result<File> {
        let entry = self.lookup(path)?;
        let name = entry
            .name
            .as_deref()
            .ok_or_else(|| invalid("not a regular file"))?;
        if kind(fsys::stat_at(entry.dir(), Some(name))?.mode) != HostFileKind::File {
            return Err(invalid("not a regular file"));
        }
        let file = File::from(fsys::open_at(
            entry.dir(),
            name,
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?);
        if !file.metadata()?.is_file() {
            return Err(invalid("not a regular file"));
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hellovm-image-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn p(path: &str) -> ImagePath {
        path.split('/')
            .filter(|c| !c.is_empty())
            .fold(ImagePath::root(), |acc, c| acc.join(c.as_bytes()).unwrap())
    }

    #[test]
    fn serves_files_dirs_and_symlinks_without_following() {
        let dir = tempdir("serve");
        let outside = tempdir("serve-outside");
        fs::write(outside.join("secret"), b"secret").unwrap();
        fs::create_dir(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/passwd"), b"root:x:0:0\n").unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("abs")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("out")).unwrap();
        let mut image = ImageDir::open(&dir).unwrap();

        assert_eq!(image.stat(&p("")).unwrap().kind, HostFileKind::Directory);
        let st = image.stat(&p("etc/passwd")).unwrap();
        assert_eq!((st.kind, st.size), (HostFileKind::File, 11));
        let mut buf = [0; 4];
        assert_eq!(image.read(&p("etc/passwd"), 5, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"x:0:");
        assert_eq!(image.stat(&p("abs")).unwrap().kind, HostFileKind::Symlink);
        assert_eq!(image.read_link(&p("abs")).unwrap(), b"/etc");
        let mut names = image.read_dir(&p("")).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![b"abs".to_vec(), b"etc".to_vec(), b"out".to_vec()]
        );

        // Host symlinks are never followed, not even by a stray request.
        assert!(image.read(&p("out/secret"), 0, &mut buf).is_err());
        assert!(image.stat(&p("out/secret")).is_err());
        assert!(image.read_dir(&p("out")).is_err());
        assert!(image.read(&p("out"), 0, &mut buf).is_err());
        assert!(image.read(&p("etc"), 0, &mut buf).is_err());

        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn never_opens_fifos_and_never_follows_symlinked_directories() {
        let dir = tempdir("fifo");
        fs::create_dir(dir.join("d")).unwrap();
        fs::write(dir.join("d/f"), b"inside").unwrap();
        std::os::unix::fs::symlink("d", dir.join("link")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join("fifo"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let mut image = ImageDir::open(&dir).unwrap();
        let mut buf = [0; 8];
        assert_eq!(image.read(&p("d/f"), 0, &mut buf).unwrap(), 6);
        // A relative symlink to a directory inside the image is not
        // followed on the host either: the core resolves symlinks itself.
        assert!(image.read(&p("link/f"), 0, &mut buf).is_err());
        assert!(image.read_dir(&p("link")).is_err());
        if made {
            // Would block forever if it were opened.
            assert_eq!(image.stat(&p("fifo")).unwrap().kind, HostFileKind::Other);
            assert!(image.read(&p("fifo"), 0, &mut buf).is_err());
        }
        assert!(image.read(&p(""), 0, &mut buf).is_err());
        assert!(image.read_link(&p("")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
