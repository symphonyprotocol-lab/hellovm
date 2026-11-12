//! [`ImageDir`]: a host directory served as the read-only image layer.
//!
//! The core only ever asks about [`ImagePath`]s it built itself from plain
//! names, and it never asks to follow a symlink. This module still treats
//! every request as untrusted and checks it again:
//!
//! * every component must be a plain name (no `..`, `.`, `/` or NUL);
//! * every directory on the way must be a real directory, not a symlink
//!   (checked with `lstat` on each prefix);
//! * files are opened with `O_NOFOLLOW` and must be regular files.
//!
//! What remains is a race with a concurrent *host-side* modification of the
//! image directory between the checks and the use (replacing a checked
//! directory with a symlink). The image is operator-provided, read-only
//! content that the sandbox cannot modify, so this is outside the threat
//! model for now; the file proxy of milestone U4 will resolve with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` instead.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use cansol_core::host::{HostFileKind, HostStat, ImagePath};

/// How many image files are kept open between reads.
const OPEN_FILES: usize = 16;

#[derive(Debug)]
pub struct ImageDir {
    root: PathBuf,
    /// Recently read files, most recent last.
    open: Vec<(ImagePath, File)>,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

impl ImageDir {
    /// Serves `root`, which must be a directory.
    pub fn open(root: impl AsRef<Path>) -> io::Result<ImageDir> {
        let root = fs::canonicalize(root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", root.display()),
            ));
        }
        Ok(ImageDir {
            root,
            open: Vec::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The host path of `path`, after checking that it is made of plain
    /// names and that no directory on the way is a symlink.
    fn host_path(&self, path: &ImagePath) -> io::Result<PathBuf> {
        let mut host = self.root.clone();
        for (i, name) in path.components().enumerate() {
            if !ImagePath::valid_name(name) {
                return Err(invalid("invalid image path component"));
            }
            if i > 0 && !fs::symlink_metadata(&host)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "image path goes through a non-directory",
                ));
            }
            host.push(std::ffi::OsStr::from_bytes(name));
        }
        Ok(host)
    }

    pub fn stat(&mut self, path: &ImagePath) -> io::Result<HostStat> {
        let meta = fs::symlink_metadata(self.host_path(path)?)?;
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            HostFileKind::Symlink
        } else if file_type.is_dir() {
            HostFileKind::Directory
        } else if file_type.is_file() {
            HostFileKind::File
        } else {
            HostFileKind::Other
        };
        Ok(HostStat {
            kind,
            mode: meta.mode() & 0o7777,
            size: meta.len(),
            nlink: meta.nlink(),
            mtime: (meta.mtime(), meta.mtime_nsec().clamp(0, 999_999_999) as u32),
        })
    }

    pub fn read_link(&mut self, path: &ImagePath) -> io::Result<Vec<u8>> {
        Ok(fs::read_link(self.host_path(path)?)?
            .into_os_string()
            .into_vec())
    }

    pub fn read_dir(&mut self, path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
        let host = self.host_path(path)?;
        if !fs::symlink_metadata(&host)?.is_dir() {
            return Err(io::ErrorKind::NotADirectory.into());
        }
        fs::read_dir(host)?
            .map(|entry| entry.map(|e| e.file_name().into_vec()))
            .collect()
    }

    pub fn read(&mut self, path: &ImagePath, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let index = match self.open.iter().position(|(p, _)| p == path) {
            Some(index) => index,
            None => {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(self.host_path(path)?)?;
                if !file.metadata()?.is_file() {
                    return Err(invalid("not a regular file"));
                }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cansol-image-{name}-{}", std::process::id()));
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
}
