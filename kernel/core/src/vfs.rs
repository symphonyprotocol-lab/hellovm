//! The sandbox filesystem: a read-only image layer under a writable
//! in-memory layer, with path resolution done entirely in the core.
//!
//! # Model
//!
//! Every file the guest has looked at is a [`Node`] in an arena, with an
//! inode number that stays stable for the node's life. A directory node has
//! a map of the entries the core knows (`entries`: files created in the
//! sandbox and cached image entries alike), a set of image names that are
//! deleted in the sandbox (`hidden`, the whiteouts), and optionally the
//! image directory it merges with (`lower`). Looking up a name checks
//! `entries`, then `hidden`, then asks the host about `lower/name`.
//!
//! * Copy-up is per node and in place: an image file's contents are read
//!   into memory on its first modification. Metadata changes (mode, times)
//!   never touch the image; they live in the node.
//! * A directory created in the sandbox has no `lower`, so it is opaque: an
//!   image directory deleted and re-created does not reappear.
//! * A renamed image directory keeps its `lower` path, so its unmodified
//!   contents still come from the image (like overlayfs `redirect_dir`).
//!
//! # Confinement
//!
//! The host only ever sees [`ImagePath`]s that the core built from a node's
//! own `lower` path plus one validated name. Guest paths are never passed to
//! the host; `.`, `..` and symlinks are interpreted here, and `..` at the
//! root stays at the root. An image symlink's target is resolved inside the
//! sandbox like any other symlink, absolute targets from the sandbox root.
//!
//! # Simplifications (U1)
//!
//! The guest is root and permission bits are not enforced (except that
//! `execve` and `access(X_OK)` want an execute bit). Image ownership is
//! shown as root. Hard links in the image appear as separate files.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::errno::{
    Errno, SysResult, EBUSY, EEXIST, EFBIG, EINVAL, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOSPC,
    ENOTDIR, ENOTEMPTY, EPERM,
};
use crate::host::{Host, HostFileKind, HostStat, ImagePath};

pub type Ino = u64;

pub const S_IFMT: u32 = 0o170_000;
pub const S_IFSOCK: u32 = 0o140_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFCHR: u32 = 0o020_000;

/// Longest path a syscall accepts, including the terminating NUL.
pub const PATH_MAX: usize = 4096;
/// Longest file name.
pub const NAME_MAX: usize = 255;
/// Most symlinks followed in one resolution.
pub const MAX_SYMLINKS: u32 = 40;
/// Largest file the in-memory layer holds.
pub const MAX_FILE_SIZE: u64 = 1 << 30;
/// Default budget of the in-memory layer: file contents plus a fixed cost
/// per node created in the sandbox. See [`Vfs::set_upper_limit`].
pub const DEFAULT_UPPER_LIMIT: u64 = 2 << 30;
/// What a node created in the sandbox costs against the budget, besides its
/// name and contents.
const NODE_COST: u64 = 512;

/// The device numbers of the sandbox filesystem and of `/dev`.
const FS_DEV: u64 = 0x2a;
const DEV_DEV: u64 = 0x05;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
}

impl FileType {
    pub fn mode_bits(self) -> u32 {
        match self {
            FileType::Regular => S_IFREG,
            FileType::Directory => S_IFDIR,
            FileType::Symlink => S_IFLNK,
            FileType::CharDevice => S_IFCHR,
        }
    }

    /// The `d_type` of a `dirent64`.
    pub fn dirent_type(self) -> u8 {
        match self {
            FileType::Regular => 8,
            FileType::Directory => 4,
            FileType::Symlink => 10,
            FileType::CharDevice => 2,
        }
    }
}

/// Character devices of `/dev`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
    /// `/dev/stdin`, `/dev/stdout`, `/dev/stderr`: opening one duplicates
    /// this fd.
    Fd(u32),
    /// An image entry that is neither file, directory nor symlink.
    Unusable,
}

impl Device {
    /// Major and minor number, as Linux numbers these devices.
    fn rdev(self) -> u64 {
        let (major, minor) = match self {
            Device::Null => (1, 3),
            Device::Zero => (1, 5),
            Device::Full => (1, 7),
            Device::Random => (1, 8),
            Device::Urandom => (1, 9),
            Device::Fd(_) | Device::Unusable => (0, 0),
        };
        makedev(major, minor)
    }
}

/// Linux `makedev` (the encoding of `st_rdev` and `st_dev`).
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xfff) << 8) | ((major & !0xfff) << 32) | (minor & 0xff) | ((minor & !0xff) << 12)
}

/// A point in time: seconds and nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

#[derive(Clone, Debug)]
struct Dir {
    parent: Ino,
    /// Known entries: created in the sandbox or cached from the image.
    entries: BTreeMap<Vec<u8>, Ino>,
    /// Image names deleted in the sandbox.
    hidden: BTreeSet<Vec<u8>>,
    /// The image directory this one merges with.
    lower: Option<ImagePath>,
}

#[derive(Clone, Debug)]
enum FileData {
    /// Still the image's contents.
    Lower { path: ImagePath, size: u64 },
    /// Copied up or created in the sandbox.
    Upper(Vec<u8>),
}

#[derive(Clone, Debug)]
enum Content {
    Dir(Dir),
    File(FileData),
    Symlink(Vec<u8>),
    Device(Device),
}

#[derive(Clone, Debug)]
pub struct Node {
    /// Permission bits (`0o7777`).
    perm: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    content: Content,
    /// Open file descriptions referring to the node.
    open: u32,
    /// Budget cost that does not depend on the file size: 0 for image
    /// nodes, node + name (+ symlink target) for nodes created here.
    overhead: u64,
    /// What the node currently costs against the in-memory budget:
    /// `overhead` plus the length of its upper-layer data.
    charge: u64,
}

/// What `stat` reports, independent of the guest ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

/// A directory entry as `getdents64` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: Ino,
    pub kind: FileType,
}

/// What to create.
#[derive(Clone, Debug)]
pub enum NewNode {
    File,
    Dir,
    Symlink(Vec<u8>),
}

/// The parent directory and last component of a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentAndName {
    pub dir: Ino,
    /// The last component; `.` for the root itself.
    pub name: Vec<u8>,
    /// The path ended with `/`.
    pub trailing_slash: bool,
}

/// What `open(O_CREAT)` found at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateTarget {
    Existing(Ino),
    /// Nothing there: create this name in this directory.
    Missing(ParentAndName),
}

/// The sandbox filesystem.
#[derive(Clone, Debug)]
pub struct Vfs {
    nodes: HashMap<Ino, Node>,
    next_ino: Ino,
    root: Ino,
    /// Bytes charged against the in-memory budget, and the budget.
    upper_used: u64,
    upper_limit: u64,
}

fn host_errno(err: std::io::Error) -> Errno {
    Errno::from_host(&err)
}

impl Vfs {
    /// A filesystem over the host's image (if it has one), with `/dev` and
    /// `/tmp` added in the upper layer.
    pub fn new<H: Host + ?Sized>(host: &mut H, now: Timespec) -> Vfs {
        let mut vfs = Vfs {
            nodes: HashMap::new(),
            next_ino: 2,
            root: 2,
            upper_used: 0,
            upper_limit: DEFAULT_UPPER_LIMIT,
        };
        let root_stat = if host.has_image() {
            match host.image_stat(&ImagePath::root()) {
                Ok(stat) if stat.kind == HostFileKind::Directory => Some(stat),
                Ok(_) => {
                    log::warn!("the image root is not a directory; starting empty");
                    None
                }
                Err(err) => {
                    log::warn!("the image root cannot be read ({err}); starting empty");
                    None
                }
            }
        } else {
            None
        };
        let root = vfs.add_node(
            Content::Dir(Dir {
                parent: 2,
                entries: BTreeMap::new(),
                hidden: BTreeSet::new(),
                lower: root_stat.map(|_| ImagePath::root()),
            }),
            root_stat.map_or(0o755, |s| s.mode),
            root_stat.map_or(now, |s| host_time(s.mtime)),
        );
        vfs.root = root;
        // Like any image directory: the host's count covers the image's
        // subdirectories, which `rmdir` and `rename` subtract again.
        vfs.node_mut(root).nlink =
            root_stat.map_or(2, |s| s.nlink.clamp(2, u32::MAX as u64) as u32);

        let dev = vfs.ensure_dir(host, root, b"dev", 0o755, now);
        let devices: [(&[u8], Device, u32); 8] = [
            (b"null", Device::Null, 0o666),
            (b"zero", Device::Zero, 0o666),
            (b"full", Device::Full, 0o666),
            (b"random", Device::Random, 0o666),
            (b"urandom", Device::Urandom, 0o666),
            (b"stdin", Device::Fd(0), 0o620),
            (b"stdout", Device::Fd(1), 0o620),
            (b"stderr", Device::Fd(2), 0o620),
        ];
        for (name, device, perm) in devices {
            let ino = vfs.add_node(Content::Device(device), perm, now);
            vfs.dir_mut(dev).entries.insert(name.to_vec(), ino);
        }
        vfs.ensure_dir(host, root, b"tmp", 0o1777, now);
        // Where /proc appears in listings; its contents are generated by the
        // syscall layer.
        vfs.ensure_dir(host, root, b"proc", 0o555, now);
        vfs
    }

    /// `dir/name` as a directory, created in the upper layer if missing.
    fn ensure_dir<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        dir: Ino,
        name: &[u8],
        perm: u32,
        now: Timespec,
    ) -> Ino {
        if let Ok(ino) = self.lookup(host, dir, name) {
            if self.file_type(ino) == FileType::Directory {
                return ino;
            }
            self.remove_entry(dir, name);
        }
        self.create(host, dir, name, NewNode::Dir, perm, now)
            .expect("creating a directory in a fresh filesystem")
    }

    pub fn root(&self) -> Ino {
        self.root
    }

    fn add_node(&mut self, content: Content, perm: u32, time: Timespec) -> Ino {
        let ino = self.next_ino;
        self.next_ino += 1;
        let nlink = if matches!(content, Content::Dir(_)) {
            2
        } else {
            1
        };
        self.nodes.insert(
            ino,
            Node {
                perm: perm & 0o7777,
                uid: 0,
                gid: 0,
                nlink,
                atime: time,
                mtime: time,
                ctime: time,
                content,
                open: 0,
                overhead: 0,
                charge: 0,
            },
        );
        ino
    }

    /// Sets the budget of the in-memory layer in bytes. Lowering it below
    /// what is in use only stops further growth.
    pub fn set_upper_limit(&mut self, bytes: u64) {
        self.upper_limit = bytes;
    }

    /// Bytes currently charged against the in-memory budget.
    pub fn upper_used(&self) -> u64 {
        self.upper_used
    }

    /// Reserves `bytes` of the budget; `ENOSPC` if that exceeds it.
    fn reserve(&mut self, bytes: u64) -> SysResult<()> {
        let used = self.upper_used.checked_add(bytes).ok_or(Errno(ENOSPC))?;
        if used > self.upper_limit {
            return Err(Errno(ENOSPC));
        }
        self.upper_used = used;
        Ok(())
    }

    /// Charges `ino` for `len` bytes of upper-layer data (plus its fixed
    /// overhead), reserving or releasing the difference.
    fn charge_data(&mut self, ino: Ino, len: u64) -> SysResult<()> {
        let node = self.node(ino);
        let (old, new) = (node.charge, node.overhead.saturating_add(len));
        if new > old {
            self.reserve(new - old)?;
        } else {
            self.upper_used -= old - new;
        }
        self.node_mut(ino).charge = new;
        Ok(())
    }

    /// Takes one subdirectory off a live directory's link count. Hosts
    /// that do not count subdirectories (btrfs reports 1) make the count
    /// start too low, so it never goes below a directory's own two links:
    /// 0 is reserved for "removed".
    fn drop_subdir_link(&mut self, dir: Ino) {
        let node = self.node_mut(dir);
        node.nlink = node.nlink.saturating_sub(1).max(2);
    }

    fn node(&self, ino: Ino) -> &Node {
        self.nodes.get(&ino).expect("live inode")
    }

    fn node_mut(&mut self, ino: Ino) -> &mut Node {
        self.nodes.get_mut(&ino).expect("live inode")
    }

    fn dir(&self, ino: Ino) -> SysResult<&Dir> {
        match &self.node(ino).content {
            Content::Dir(dir) => Ok(dir),
            _ => Err(Errno(ENOTDIR)),
        }
    }

    fn dir_mut(&mut self, ino: Ino) -> &mut Dir {
        match &mut self.node_mut(ino).content {
            Content::Dir(dir) => dir,
            _ => panic!("inode {ino} is not a directory"),
        }
    }

    pub fn file_type(&self, ino: Ino) -> FileType {
        match &self.node(ino).content {
            Content::Dir(_) => FileType::Directory,
            Content::File(_) => FileType::Regular,
            Content::Symlink(_) => FileType::Symlink,
            Content::Device(_) => FileType::CharDevice,
        }
    }

    pub fn device(&self, ino: Ino) -> Option<Device> {
        match self.node(ino).content {
            Content::Device(device) => Some(device),
            _ => None,
        }
    }

    pub fn is_dir(&self, ino: Ino) -> bool {
        self.file_type(ino) == FileType::Directory
    }

    pub fn perm(&self, ino: Ino) -> u32 {
        self.node(ino).perm
    }

    fn node_from_image(
        &mut self,
        path: ImagePath,
        stat: HostStat,
        parent: Ino,
        host_link: Option<Vec<u8>>,
    ) -> Ino {
        let content = match stat.kind {
            HostFileKind::Directory => Content::Dir(Dir {
                parent,
                entries: BTreeMap::new(),
                hidden: BTreeSet::new(),
                lower: Some(path),
            }),
            HostFileKind::File => Content::File(FileData::Lower {
                path,
                size: stat.size,
            }),
            HostFileKind::Symlink => Content::Symlink(host_link.unwrap_or_default()),
            HostFileKind::Other => Content::Device(Device::Unusable),
        };
        let ino = self.add_node(content, stat.mode, host_time(stat.mtime));
        if stat.kind == HostFileKind::Directory {
            self.node_mut(ino).nlink = stat.nlink.clamp(2, u32::MAX as u64) as u32;
        }
        ino
    }

    /// Looks up one name in a directory.
    pub fn lookup<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        dir: Ino,
        name: &[u8],
    ) -> SysResult<Ino> {
        let d = self.dir(dir)?;
        if name == b"." {
            return Ok(dir);
        }
        if name == b".." {
            // A removed directory that is still open or current may have
            // outlived its parent.
            return if self.nodes.contains_key(&d.parent) {
                Ok(d.parent)
            } else {
                Err(Errno(ENOENT))
            };
        }
        if let Some(&ino) = d.entries.get(name) {
            return Ok(ino);
        }
        if d.hidden.contains(name) {
            return Err(Errno(ENOENT));
        }
        let Some(lower) = &d.lower else {
            return Err(Errno(ENOENT));
        };
        let path = lower.join(name).ok_or(Errno(ENOENT))?;
        let stat = match host.image_stat(&path) {
            Ok(stat) => stat,
            Err(err) if err.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(Errno(ENOENT))
            }
            Err(err) => return Err(host_errno(err)),
        };
        let link = if stat.kind == HostFileKind::Symlink {
            Some(host.image_read_link(&path).map_err(host_errno)?)
        } else {
            None
        };
        let ino = self.node_from_image(path, stat, dir, link);
        self.dir_mut(dir).entries.insert(name.to_vec(), ino);
        Ok(ino)
    }

    /// Resolves `path` starting at `start` (for relative paths). A final
    /// symlink is followed if `follow` is set or the path ends with `/`.
    pub fn resolve<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        start: Ino,
        path: &[u8],
        follow: bool,
    ) -> SysResult<Ino> {
        let mut links = 0;
        self.walk(host, start, path, follow, &mut links)
    }

    fn walk<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        start: Ino,
        path: &[u8],
        follow: bool,
        links: &mut u32,
    ) -> SysResult<Ino> {
        if path.is_empty() {
            return Err(Errno(ENOENT));
        }
        if path.len() >= PATH_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        let trailing_slash = path.ends_with(b"/");
        let mut cur = if path[0] == b'/' { self.root } else { start };
        let comps: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        for (i, comp) in comps.iter().enumerate() {
            if comp.len() > NAME_MAX {
                return Err(Errno(ENAMETOOLONG));
            }
            self.dir(cur)?;
            if *comp == b".." && cur == self.root {
                continue;
            }
            let mut next = self.lookup(host, cur, comp)?;
            let last = i + 1 == comps.len();
            if self.file_type(next) == FileType::Symlink && (!last || follow || trailing_slash) {
                *links += 1;
                if *links > MAX_SYMLINKS {
                    return Err(Errno(ELOOP));
                }
                let Content::Symlink(target) = &self.node(next).content else {
                    unreachable!()
                };
                let target = target.clone();
                next = self.walk(host, cur, &target, true, links)?;
            }
            cur = next;
        }
        if trailing_slash && !self.is_dir(cur) {
            return Err(Errno(ENOTDIR));
        }
        Ok(cur)
    }

    /// Resolves all but the last component of `path`.
    pub fn resolve_parent<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        start: Ino,
        path: &[u8],
    ) -> SysResult<ParentAndName> {
        if path.is_empty() {
            return Err(Errno(ENOENT));
        }
        if path.len() >= PATH_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        let trimmed_len = path.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
        let trailing_slash = trimmed_len < path.len();
        let trimmed = &path[..trimmed_len];
        if trimmed.is_empty() {
            // "/" (or "///"): the root itself.
            return Ok(ParentAndName {
                dir: self.root,
                name: b".".to_vec(),
                trailing_slash,
            });
        }
        let (dir_part, name) = match trimmed.iter().rposition(|&b| b == b'/') {
            Some(i) => (&trimmed[..=i], &trimmed[i + 1..]),
            None => (&b""[..], trimmed),
        };
        if name.len() > NAME_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        let dir = if dir_part.is_empty() {
            start
        } else {
            self.resolve(host, start, dir_part, true)?
        };
        self.dir(dir)?;
        Ok(ParentAndName {
            dir,
            name: name.to_vec(),
            trailing_slash,
        })
    }

    /// Resolves `path` for `open(O_CREAT)`: the existing node, or where to
    /// create it. With `follow`, a final symlink is followed even if its
    /// target does not exist yet, so that the file is created at the
    /// target, as on Linux.
    pub fn resolve_for_create<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        start: Ino,
        path: &[u8],
        follow: bool,
    ) -> SysResult<CreateTarget> {
        let mut start = start;
        let mut path = path.to_vec();
        let mut links = 0;
        loop {
            let parent = self.resolve_parent(host, start, &path)?;
            let ino = match self.lookup(host, parent.dir, &parent.name) {
                Ok(ino) => ino,
                Err(Errno(ENOENT)) => return Ok(CreateTarget::Missing(parent)),
                Err(err) => return Err(err),
            };
            if follow || parent.trailing_slash {
                if let Content::Symlink(target) = &self.node(ino).content {
                    links += 1;
                    if links > MAX_SYMLINKS {
                        return Err(Errno(ELOOP));
                    }
                    path = target.clone();
                    if parent.trailing_slash {
                        path.push(b'/');
                    }
                    start = parent.dir;
                    continue;
                }
            }
            if parent.trailing_slash && !self.is_dir(ino) {
                return Err(Errno(ENOTDIR));
            }
            return Ok(CreateTarget::Existing(ino));
        }
    }

    fn check_new_name(name: &[u8]) -> SysResult<()> {
        if name.len() > NAME_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        if name.is_empty() || name == b"." || name == b".." {
            return Err(Errno(EEXIST));
        }
        Ok(())
    }

    fn touch_dir(&mut self, dir: Ino, now: Timespec) {
        let node = self.node_mut(dir);
        node.mtime = now;
        node.ctime = now;
    }

    /// Creates `dir/name`, which must not exist.
    pub fn create<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        dir: Ino,
        name: &[u8],
        what: NewNode,
        perm: u32,
        now: Timespec,
    ) -> SysResult<Ino> {
        Self::check_new_name(name)?;
        match self.lookup(host, dir, name) {
            Ok(_) => return Err(Errno(EEXIST)),
            Err(Errno(ENOENT)) => {}
            Err(err) => return Err(err),
        }
        if self.node(dir).nlink == 0 {
            // The directory was removed while still in use.
            return Err(Errno(ENOENT));
        }
        let is_dir = matches!(what, NewNode::Dir);
        let overhead = NODE_COST
            + name.len() as u64
            + match &what {
                NewNode::Symlink(target) => target.len() as u64,
                _ => 0,
            };
        self.reserve(overhead)?;
        let content = match what {
            NewNode::File => Content::File(FileData::Upper(Vec::new())),
            NewNode::Dir => Content::Dir(Dir {
                parent: dir,
                entries: BTreeMap::new(),
                hidden: BTreeSet::new(),
                lower: None,
            }),
            NewNode::Symlink(target) => Content::Symlink(target),
        };
        let ino = self.add_node(content, perm, now);
        let node = self.node_mut(ino);
        node.overhead = overhead;
        node.charge = overhead;
        self.dir_mut(dir).entries.insert(name.to_vec(), ino);
        if is_dir {
            self.node_mut(dir).nlink += 1;
        }
        self.touch_dir(dir, now);
        Ok(ino)
    }

    /// Drops `name` from `dir`, hiding the image's entry of that name.
    fn remove_entry(&mut self, dir: Ino, name: &[u8]) {
        let d = self.dir_mut(dir);
        d.entries.remove(name);
        if d.lower.is_some() {
            d.hidden.insert(name.to_vec());
        }
    }

    /// Frees a node that has no names and no open files left.
    fn maybe_free(&mut self, ino: Ino) {
        let node = self.node(ino);
        if node.nlink == 0 && node.open == 0 && ino != self.root {
            self.upper_used -= node.charge;
            self.nodes.remove(&ino);
        }
    }

    /// `unlink`: removes a non-directory name.
    pub fn unlink<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        dir: Ino,
        name: &[u8],
        now: Timespec,
    ) -> SysResult<()> {
        if name == b"." || name == b".." {
            return Err(Errno(EISDIR));
        }
        let ino = self.lookup(host, dir, name)?;
        if self.is_dir(ino) {
            return Err(Errno(EISDIR));
        }
        self.remove_entry(dir, name);
        self.touch_dir(dir, now);
        let node = self.node_mut(ino);
        node.nlink -= 1;
        node.ctime = now;
        self.maybe_free(ino);
        Ok(())
    }

    /// `rmdir`: removes an empty directory.
    pub fn rmdir<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        dir: Ino,
        name: &[u8],
        now: Timespec,
    ) -> SysResult<()> {
        if name == b"." {
            return Err(Errno(EINVAL));
        }
        if name == b".." {
            return Err(Errno(ENOTEMPTY));
        }
        let ino = self.lookup(host, dir, name)?;
        if !self.is_dir(ino) {
            return Err(Errno(ENOTDIR));
        }
        if ino == self.root {
            return Err(Errno(EBUSY));
        }
        if !self.list(host, ino)?.is_empty() {
            return Err(Errno(ENOTEMPTY));
        }
        self.remove_entry(dir, name);
        self.touch_dir(dir, now);
        self.drop_subdir_link(dir);
        self.node_mut(ino).nlink = 0;
        self.maybe_free(ino);
        Ok(())
    }

    /// The entries of a directory in name order, without `.` and `..`.
    pub fn list<H: Host + ?Sized>(&mut self, host: &mut H, dir: Ino) -> SysResult<Vec<DirEntry>> {
        let d = self.dir(dir)?;
        if self.node(dir).nlink == 0 {
            return Ok(Vec::new());
        }
        let mut names: BTreeSet<Vec<u8>> = d.entries.keys().cloned().collect();
        if let Some(lower) = d.lower.clone() {
            let hidden = d.hidden.clone();
            match host.image_read_dir(&lower) {
                Ok(lower_names) => names.extend(
                    lower_names
                        .into_iter()
                        .filter(|n| ImagePath::valid_name(n) && !hidden.contains(n)),
                ),
                Err(err) => log::warn!("listing image directory {lower:?}: {err}"),
            }
        }
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            match self.lookup(host, dir, &name) {
                Ok(ino) => out.push(DirEntry {
                    kind: self.file_type(ino),
                    ino,
                    name,
                }),
                // Gone from the image meanwhile, or unreadable: skip.
                Err(_) => continue,
            }
        }
        Ok(out)
    }

    /// `rename`. With `noreplace`, an existing target is an error.
    #[allow(clippy::too_many_arguments)]
    pub fn rename<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        old_dir: Ino,
        old_name: &[u8],
        new_dir: Ino,
        new_name: &[u8],
        noreplace: bool,
        now: Timespec,
    ) -> SysResult<()> {
        for name in [old_name, new_name] {
            if name == b"." || name == b".." || name.is_empty() {
                return Err(Errno(EBUSY));
            }
        }
        if new_name.len() > NAME_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        let src = self.lookup(host, old_dir, old_name)?;
        let dst = match self.lookup(host, new_dir, new_name) {
            Ok(ino) => Some(ino),
            Err(Errno(ENOENT)) => None,
            Err(err) => return Err(err),
        };
        if dst == Some(src) {
            return Ok(());
        }
        if noreplace && dst.is_some() {
            return Err(Errno(EEXIST));
        }
        if self.node(new_dir).nlink == 0 {
            return Err(Errno(ENOENT));
        }
        let src_is_dir = self.is_dir(src);
        if src_is_dir {
            // A directory cannot move into its own subtree.
            let mut at = new_dir;
            loop {
                if at == src {
                    return Err(Errno(EINVAL));
                }
                if at == self.root {
                    break;
                }
                at = self.dir(at)?.parent;
            }
            if let Some(dst) = dst {
                if !self.is_dir(dst) {
                    return Err(Errno(ENOTDIR));
                }
                if !self.list(host, dst)?.is_empty() {
                    return Err(Errno(ENOTEMPTY));
                }
            }
        } else if dst.is_some_and(|dst| self.is_dir(dst)) {
            return Err(Errno(EISDIR));
        }

        self.remove_entry(old_dir, old_name);
        if let Some(dst) = dst {
            self.dir_mut(new_dir).entries.remove(new_name);
            if self.is_dir(dst) {
                self.node_mut(dst).nlink = 0;
                self.drop_subdir_link(new_dir);
            } else {
                self.node_mut(dst).nlink -= 1;
            }
            self.node_mut(dst).ctime = now;
            self.maybe_free(dst);
        }
        self.dir_mut(new_dir).entries.insert(new_name.to_vec(), src);
        if src_is_dir {
            self.drop_subdir_link(old_dir);
            self.node_mut(new_dir).nlink += 1;
            self.dir_mut(src).parent = new_dir;
        }
        self.node_mut(src).ctime = now;
        self.touch_dir(old_dir, now);
        self.touch_dir(new_dir, now);
        Ok(())
    }

    /// `link`: a new name for an existing non-directory.
    pub fn link<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        ino: Ino,
        dir: Ino,
        name: &[u8],
        now: Timespec,
    ) -> SysResult<()> {
        if self.is_dir(ino) {
            return Err(Errno(EPERM));
        }
        Self::check_new_name(name)?;
        match self.lookup(host, dir, name) {
            Ok(_) => return Err(Errno(EEXIST)),
            Err(Errno(ENOENT)) => {}
            Err(err) => return Err(err),
        }
        if self.node(dir).nlink == 0 || self.node(ino).nlink == 0 {
            return Err(Errno(ENOENT));
        }
        self.dir_mut(dir).entries.insert(name.to_vec(), ino);
        let node = self.node_mut(ino);
        node.nlink += 1;
        node.ctime = now;
        self.touch_dir(dir, now);
        Ok(())
    }

    pub fn read_link(&self, ino: Ino) -> SysResult<Vec<u8>> {
        match &self.node(ino).content {
            Content::Symlink(target) => Ok(target.clone()),
            _ => Err(Errno(EINVAL)),
        }
    }

    /// The parent of a directory (the root is its own parent).
    pub fn parent(&self, dir: Ino) -> SysResult<Ino> {
        Ok(self.dir(dir)?.parent)
    }

    /// The name of `ino` in directory `parent`.
    pub fn name_in(&self, parent: Ino, ino: Ino) -> Option<Vec<u8>> {
        let dir = self.dir(parent).ok()?;
        dir.entries
            .iter()
            .find(|(_, &i)| i == ino)
            .map(|(name, _)| name.clone())
    }

    /// The absolute path of a directory, for `getcwd`. `None` if the
    /// directory has been removed.
    pub fn dir_path(&self, mut dir: Ino) -> Option<Vec<u8>> {
        let mut parts = Vec::new();
        while dir != self.root {
            if self.node(dir).nlink == 0 {
                return None;
            }
            let parent = self.parent(dir).ok()?;
            parts.push(self.name_in(parent, dir)?);
            dir = parent;
        }
        let mut path = Vec::new();
        for part in parts.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(part);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        Some(path)
    }

    pub fn size(&self, ino: Ino) -> u64 {
        match &self.node(ino).content {
            Content::File(FileData::Lower { size, .. }) => *size,
            Content::File(FileData::Upper(data)) => data.len() as u64,
            Content::Symlink(target) => target.len() as u64,
            Content::Dir(_) => 4096,
            Content::Device(_) => 0,
        }
    }

    pub fn stat(&self, ino: Ino) -> Stat {
        let node = self.node(ino);
        let size = self.size(ino);
        let (dev, rdev) = match node.content {
            Content::Device(device) => (DEV_DEV, device.rdev()),
            _ => (FS_DEV, 0),
        };
        Stat {
            dev,
            ino,
            mode: self.file_type(ino).mode_bits() | node.perm,
            nlink: node.nlink,
            uid: node.uid,
            gid: node.gid,
            rdev,
            size,
            blksize: 4096,
            blocks: size.div_ceil(4096) * 8,
            atime: node.atime,
            mtime: node.mtime,
            ctime: node.ctime,
        }
    }

    /// Reads file data at `offset`. Returns the number of bytes read.
    pub fn read<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        ino: Ino,
        offset: u64,
        buf: &mut [u8],
    ) -> SysResult<usize> {
        match &self.node(ino).content {
            Content::File(FileData::Upper(data)) => {
                let start = offset.min(data.len() as u64) as usize;
                let n = buf.len().min(data.len() - start);
                buf[..n].copy_from_slice(&data[start..start + n]);
                Ok(n)
            }
            Content::File(FileData::Lower { path, size }) => {
                if offset >= *size {
                    return Ok(0);
                }
                let n = buf.len().min((size - offset) as usize);
                let path = path.clone();
                let mut done = 0;
                while done < n {
                    let got = host
                        .image_read(&path, offset + done as u64, &mut buf[done..n])
                        .map_err(host_errno)?;
                    if got == 0 {
                        break;
                    }
                    done += got;
                }
                Ok(done)
            }
            Content::Dir(_) => Err(Errno(EISDIR)),
            _ => Err(Errno(EINVAL)),
        }
    }

    /// The whole contents of a regular file.
    pub fn read_all<H: Host + ?Sized>(&mut self, host: &mut H, ino: Ino) -> SysResult<Vec<u8>> {
        let mut data = vec![0; self.size(ino) as usize];
        let n = self.read(host, ino, 0, &mut data)?;
        data.truncate(n);
        Ok(data)
    }

    /// Replaces an image file's contents with an in-memory copy of its
    /// first `len` bytes, within the per-file and total limits.
    fn copy_up<H: Host + ?Sized>(&mut self, host: &mut H, ino: Ino, len: u64) -> SysResult<()> {
        if len > MAX_FILE_SIZE {
            return Err(Errno(EFBIG));
        }
        self.charge_data(ino, len)?;
        let mut data = vec![0; len as usize];
        match self.read(host, ino, 0, &mut data) {
            // If the image file is shorter than its size said, the rest
            // reads as zeros.
            Ok(_) => {
                self.node_mut(ino).content = Content::File(FileData::Upper(data));
                Ok(())
            }
            Err(err) => {
                self.charge_data(ino, 0).expect("releasing never fails");
                Err(err)
            }
        }
    }

    /// The upper-layer data of a file, copying it up first.
    fn upper_data<H: Host + ?Sized>(&mut self, host: &mut H, ino: Ino) -> SysResult<&mut Vec<u8>> {
        if let Content::File(FileData::Lower { size, .. }) = self.node(ino).content {
            self.copy_up(host, ino, size)?;
        }
        match &mut self.node_mut(ino).content {
            Content::File(FileData::Upper(data)) => Ok(data),
            Content::Dir(_) => Err(Errno(EISDIR)),
            _ => Err(Errno(EINVAL)),
        }
    }

    /// Writes file data at `offset`, extending the file as needed.
    pub fn write<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        ino: Ino,
        offset: u64,
        data: &[u8],
        now: Timespec,
    ) -> SysResult<usize> {
        let end = offset.checked_add(data.len() as u64).ok_or(Errno(EFBIG))?;
        if end > MAX_FILE_SIZE {
            return Err(Errno(EFBIG));
        }
        let len = self.upper_data(host, ino)?.len() as u64;
        if len < end {
            self.charge_data(ino, end)?;
        }
        let file = self.upper_data(host, ino)?;
        if file.len() < end as usize {
            file.resize(end as usize, 0);
        }
        file[offset as usize..end as usize].copy_from_slice(data);
        let node = self.node_mut(ino);
        node.mtime = now;
        node.ctime = now;
        Ok(data.len())
    }

    /// Sets the size of a regular file.
    pub fn truncate<H: Host + ?Sized>(
        &mut self,
        host: &mut H,
        ino: Ino,
        len: u64,
        now: Timespec,
    ) -> SysResult<()> {
        if len > MAX_FILE_SIZE {
            return Err(Errno(EFBIG));
        }
        match self.file_type(ino) {
            FileType::Regular => {}
            FileType::Directory => return Err(Errno(EISDIR)),
            _ => return Err(Errno(EINVAL)),
        }
        match self.node(ino).content {
            // Copy up only what is kept.
            Content::File(FileData::Lower { size, .. }) if len <= size => {
                self.copy_up(host, ino, len)?;
            }
            _ => {
                let old = self.upper_data(host, ino)?.len() as u64;
                if len > old {
                    self.charge_data(ino, len)?;
                }
                self.upper_data(host, ino)?.resize(len as usize, 0);
                if len < old {
                    self.charge_data(ino, len)?;
                }
            }
        }
        let node = self.node_mut(ino);
        node.mtime = now;
        node.ctime = now;
        Ok(())
    }

    pub fn set_perm(&mut self, ino: Ino, perm: u32, now: Timespec) {
        let node = self.node_mut(ino);
        node.perm = perm & 0o7777;
        node.ctime = now;
    }

    pub fn set_owner(&mut self, ino: Ino, uid: Option<u32>, gid: Option<u32>, now: Timespec) {
        let node = self.node_mut(ino);
        if let Some(uid) = uid {
            node.uid = uid;
        }
        if let Some(gid) = gid {
            node.gid = gid;
        }
        node.ctime = now;
    }

    pub fn set_times(
        &mut self,
        ino: Ino,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
        now: Timespec,
    ) {
        let node = self.node_mut(ino);
        if let Some(atime) = atime {
            node.atime = atime;
        }
        if let Some(mtime) = mtime {
            node.mtime = mtime;
        }
        node.ctime = now;
    }

    /// Records a new open file description for `ino`.
    pub fn opened(&mut self, ino: Ino) {
        self.node_mut(ino).open += 1;
    }

    /// Drops an open file description for `ino`, freeing an unlinked node.
    pub fn closed(&mut self, ino: Ino) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.open -= 1;
            self.maybe_free(ino);
        }
    }

    /// The number of live nodes (for tests).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

fn host_time((sec, nsec): (i64, u32)) -> Timespec {
    Timespec { sec, nsec }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockEntry, MockHost};

    const NOW: Timespec = Timespec { sec: 1000, nsec: 0 };

    fn image() -> MockHost {
        MockHost::with_image(&[
            ("etc", MockEntry::Dir),
            ("etc/passwd", MockEntry::File(b"root:x:0:0\n".to_vec())),
            (
                "etc/hosts",
                MockEntry::File(b"127.0.0.1 localhost\n".to_vec()),
            ),
            ("bin", MockEntry::Dir),
            ("bin/sh", MockEntry::Symlink(b"busybox".to_vec())),
            ("bin/busybox", MockEntry::File(b"\x7fELF".to_vec())),
            ("lib", MockEntry::Symlink(b"/usr/lib".to_vec())),
            ("usr", MockEntry::Dir),
            ("usr/lib", MockEntry::Dir),
            ("usr/lib/libc.so", MockEntry::File(b"libc".to_vec())),
            ("escape", MockEntry::Symlink(b"../../../../..".to_vec())),
            ("abs", MockEntry::Symlink(b"/../../etc".to_vec())),
            ("loop", MockEntry::Symlink(b"loop".to_vec())),
        ])
    }

    fn resolve(vfs: &mut Vfs, host: &mut MockHost, path: &str) -> SysResult<Ino> {
        let root = vfs.root();
        vfs.resolve(host, root, path.as_bytes(), true)
    }

    fn names(vfs: &mut Vfs, host: &mut MockHost, path: &str) -> Vec<String> {
        let dir = resolve(vfs, host, path).unwrap();
        vfs.list(host, dir)
            .unwrap()
            .into_iter()
            .map(|e| String::from_utf8(e.name).unwrap())
            .collect()
    }

    #[test]
    fn resolution_handles_dots_and_symlinks() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let passwd = resolve(&mut vfs, &mut host, "/etc/passwd").unwrap();
        assert_eq!(resolve(&mut vfs, &mut host, "/etc/./passwd"), Ok(passwd));
        assert_eq!(resolve(&mut vfs, &mut host, "//etc//passwd"), Ok(passwd));
        assert_eq!(
            resolve(&mut vfs, &mut host, "/bin/../etc/passwd"),
            Ok(passwd)
        );
        let busybox = resolve(&mut vfs, &mut host, "/bin/busybox").unwrap();
        assert_eq!(resolve(&mut vfs, &mut host, "/bin/sh"), Ok(busybox));
        let root = vfs.root();
        let sh = vfs.resolve(&mut host, root, b"/bin/sh", false).unwrap();
        assert_ne!(sh, busybox);
        assert_eq!(vfs.read_link(sh).unwrap(), b"busybox");
        let libc = resolve(&mut vfs, &mut host, "/lib/libc.so").unwrap();
        assert_eq!(vfs.read_all(&mut host, libc).unwrap(), b"libc");
        assert_eq!(resolve(&mut vfs, &mut host, "/nope"), Err(Errno(ENOENT)));
        assert_eq!(
            resolve(&mut vfs, &mut host, "/etc/passwd/x"),
            Err(Errno(ENOTDIR))
        );
        assert_eq!(
            resolve(&mut vfs, &mut host, "/etc/passwd/"),
            Err(Errno(ENOTDIR))
        );
        assert_eq!(resolve(&mut vfs, &mut host, "/loop"), Err(Errno(ELOOP)));
        assert_eq!(resolve(&mut vfs, &mut host, ""), Err(Errno(ENOENT)));
        let long = format!("/{}", "a".repeat(256));
        assert_eq!(
            resolve(&mut vfs, &mut host, &long),
            Err(Errno(ENAMETOOLONG))
        );
        // Relative to a start directory.
        let etc = resolve(&mut vfs, &mut host, "/etc").unwrap();
        assert_eq!(vfs.resolve(&mut host, etc, b"passwd", true), Ok(passwd));
        assert_eq!(vfs.resolve(&mut host, etc, b"../bin/sh", true), Ok(busybox));
    }

    #[test]
    fn dot_dot_and_symlinks_cannot_leave_the_root() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let root = vfs.root();
        assert_eq!(resolve(&mut vfs, &mut host, "/.."), Ok(root));
        assert_eq!(resolve(&mut vfs, &mut host, "/../../../.."), Ok(root));
        assert_eq!(resolve(&mut vfs, &mut host, "/escape"), Ok(root));
        let etc = resolve(&mut vfs, &mut host, "/etc").unwrap();
        assert_eq!(resolve(&mut vfs, &mut host, "/abs"), Ok(etc));
        assert_eq!(resolve(&mut vfs, &mut host, "/escape/etc"), Ok(etc));
        assert_eq!(vfs.resolve(&mut host, etc, b"../../../etc", true), Ok(etc));
        // The host was only ever asked about plain image paths.
        for path in &host.asked {
            assert!(
                !path
                    .split('/')
                    .any(|c| c == ".." || c == "." || c.is_empty())
                    || path.is_empty(),
                "{path}"
            );
        }
    }

    #[test]
    fn writes_copy_up_and_never_reach_the_image() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let passwd = resolve(&mut vfs, &mut host, "/etc/passwd").unwrap();
        vfs.write(&mut host, passwd, 0, b"ROOT", NOW).unwrap();
        assert_eq!(vfs.read_all(&mut host, passwd).unwrap(), b"ROOT:x:0:0\n");
        let MockEntry::File(original) = &host.image.as_ref().unwrap()["etc/passwd"] else {
            panic!()
        };
        assert_eq!(original, b"root:x:0:0\n");
        let hosts = resolve(&mut vfs, &mut host, "/etc/hosts").unwrap();
        host.asked.clear();
        vfs.truncate(&mut host, hosts, 0, NOW).unwrap();
        assert!(host.asked.is_empty(), "truncating to 0 needs no copy-up");
        assert_eq!(vfs.size(hosts), 0);
        vfs.write(&mut host, hosts, 5, b"x", NOW).unwrap();
        assert_eq!(vfs.read_all(&mut host, hosts).unwrap(), b"\0\0\0\0\0x");
    }

    #[test]
    fn whiteouts_and_opaque_directories() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let etc = resolve(&mut vfs, &mut host, "/etc").unwrap();
        assert_eq!(names(&mut vfs, &mut host, "/etc"), ["hosts", "passwd"]);
        vfs.unlink(&mut host, etc, b"passwd", NOW).unwrap();
        assert_eq!(names(&mut vfs, &mut host, "/etc"), ["hosts"]);
        assert_eq!(
            resolve(&mut vfs, &mut host, "/etc/passwd"),
            Err(Errno(ENOENT))
        );
        // Re-creating the name gives a new, empty file.
        let new = vfs
            .create(&mut host, etc, b"passwd", NewNode::File, 0o600, NOW)
            .unwrap();
        assert_eq!(vfs.size(new), 0);
        assert_eq!(names(&mut vfs, &mut host, "/etc"), ["hosts", "passwd"]);
        // Remove a whole image directory and re-create it: opaque.
        let root = vfs.root();
        let usr_lib = resolve(&mut vfs, &mut host, "/usr/lib").unwrap();
        vfs.unlink(&mut host, usr_lib, b"libc.so", NOW).unwrap();
        let usr = resolve(&mut vfs, &mut host, "/usr").unwrap();
        vfs.rmdir(&mut host, usr, b"lib", NOW).unwrap();
        assert_eq!(names(&mut vfs, &mut host, "/usr"), Vec::<String>::new());
        vfs.create(&mut host, usr, b"lib", NewNode::Dir, 0o755, NOW)
            .unwrap();
        assert_eq!(names(&mut vfs, &mut host, "/usr/lib"), Vec::<String>::new());
        assert_eq!(
            vfs.rmdir(&mut host, root, b"etc", NOW),
            Err(Errno(ENOTEMPTY))
        );
        assert_eq!(
            vfs.rmdir(&mut host, root, b"bin/sh", NOW),
            Err(Errno(ENOENT))
        );
        assert_eq!(vfs.unlink(&mut host, root, b"etc", NOW), Err(Errno(EISDIR)));
    }

    #[test]
    fn rename_and_link() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let root = vfs.root();
        let etc = resolve(&mut vfs, &mut host, "/etc").unwrap();
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        let passwd = resolve(&mut vfs, &mut host, "/etc/passwd").unwrap();
        vfs.rename(&mut host, etc, b"passwd", tmp, b"pw", false, NOW)
            .unwrap();
        assert_eq!(resolve(&mut vfs, &mut host, "/tmp/pw"), Ok(passwd));
        assert_eq!(
            resolve(&mut vfs, &mut host, "/etc/passwd"),
            Err(Errno(ENOENT))
        );
        assert_eq!(vfs.read_all(&mut host, passwd).unwrap(), b"root:x:0:0\n");
        // Renaming an image directory keeps its contents.
        vfs.rename(&mut host, root, b"usr", tmp, b"u", false, NOW)
            .unwrap();
        let libc = resolve(&mut vfs, &mut host, "/tmp/u/lib/libc.so").unwrap();
        assert_eq!(vfs.read_all(&mut host, libc).unwrap(), b"libc");
        let u_lib = resolve(&mut vfs, &mut host, "/tmp/u/lib").unwrap();
        assert_eq!(vfs.dir_path(u_lib), Some(b"/tmp/u/lib".to_vec()));
        // Into its own subtree.
        let u = resolve(&mut vfs, &mut host, "/tmp/u").unwrap();
        assert_eq!(
            vfs.rename(&mut host, tmp, b"u", u, b"x", false, NOW),
            Err(Errno(EINVAL))
        );
        // Replacing a file; noreplace.
        let hosts = resolve(&mut vfs, &mut host, "/etc/hosts").unwrap();
        assert_eq!(
            vfs.rename(&mut host, tmp, b"pw", etc, b"hosts", true, NOW),
            Err(Errno(EEXIST))
        );
        vfs.rename(&mut host, tmp, b"pw", etc, b"hosts", false, NOW)
            .unwrap();
        assert_eq!(resolve(&mut vfs, &mut host, "/etc/hosts"), Ok(passwd));
        assert!(!vfs.nodes.contains_key(&hosts), "replaced file is freed");
        // A file over a directory and the reverse.
        assert_eq!(
            vfs.rename(&mut host, etc, b"hosts", root, b"tmp", false, NOW),
            Err(Errno(EISDIR))
        );
        assert_eq!(
            vfs.rename(&mut host, root, b"tmp", etc, b"hosts", false, NOW),
            Err(Errno(ENOTDIR))
        );
        // Hard links share the node.
        vfs.link(&mut host, passwd, tmp, b"again", NOW).unwrap();
        assert_eq!(vfs.stat(passwd).nlink, 2);
        vfs.write(&mut host, passwd, 0, b"R", NOW).unwrap();
        let again = resolve(&mut vfs, &mut host, "/tmp/again").unwrap();
        assert_eq!(vfs.read_all(&mut host, again).unwrap()[0], b'R');
        assert_eq!(
            vfs.link(&mut host, tmp, root, b"t2", NOW),
            Err(Errno(EPERM))
        );
    }

    #[test]
    fn unlinked_open_files_live_until_closed() {
        let mut host = MockHost::default();
        let mut vfs = Vfs::new(&mut host, NOW);
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        let f = vfs
            .create(&mut host, tmp, b"f", NewNode::File, 0o644, NOW)
            .unwrap();
        vfs.write(&mut host, f, 0, b"data", NOW).unwrap();
        vfs.opened(f);
        vfs.unlink(&mut host, tmp, b"f", NOW).unwrap();
        assert_eq!(vfs.read_all(&mut host, f).unwrap(), b"data");
        let before = vfs.node_count();
        vfs.closed(f);
        assert_eq!(vfs.node_count(), before - 1);
    }

    #[test]
    fn devices_and_parents() {
        let mut host = MockHost::default();
        let mut vfs = Vfs::new(&mut host, NOW);
        let null = resolve(&mut vfs, &mut host, "/dev/null").unwrap();
        assert_eq!(vfs.device(null), Some(Device::Null));
        let st = vfs.stat(null);
        assert_eq!(st.mode, S_IFCHR | 0o666);
        assert_eq!(st.rdev, makedev(1, 3));
        let root = vfs.root();
        let p = vfs.resolve_parent(&mut host, root, b"/tmp/new/").unwrap();
        assert_eq!(p.name, b"new");
        assert!(p.trailing_slash);
        assert_eq!(p.dir, resolve(&mut vfs, &mut host, "/tmp").unwrap());
        let p = vfs.resolve_parent(&mut host, root, b"/").unwrap();
        assert_eq!((p.dir, p.name), (root, b".".to_vec()));
        let p = vfs.resolve_parent(&mut host, p.dir, b"x").unwrap();
        assert_eq!((p.dir, p.name), (root, b"x".to_vec()));
        assert_eq!(
            vfs.resolve_parent(&mut host, root, b"/dev/null/x")
                .map(|p| p.dir),
            Err(Errno(ENOTDIR))
        );
        assert_eq!(vfs.dir_path(root), Some(b"/".to_vec()));
        assert_eq!(makedev(1, 3), 0x103);
        assert_eq!(makedev(0x1000, 0x100), 0x1000_0010_0000);
    }

    #[test]
    fn removing_image_directories_keeps_the_parent_alive() {
        // The mock host reports a link count of 1 for directories, like
        // btrfs: nothing can be derived from it.
        let mut host = MockHost::with_image(&[
            ("a", MockEntry::Dir),
            ("b", MockEntry::Dir),
            ("c", MockEntry::Dir),
        ]);
        let mut vfs = Vfs::new(&mut host, NOW);
        let root = vfs.root();
        for name in ["a", "b", "c"] {
            vfs.rmdir(&mut host, root, name.as_bytes(), NOW).unwrap();
        }
        assert!(vfs.stat(root).nlink >= 2);
        assert_eq!(names(&mut vfs, &mut host, "/"), ["dev", "proc", "tmp"]);
        vfs.create(&mut host, root, b"f", NewNode::File, 0o644, NOW)
            .unwrap();
        // Renaming directories away does not underflow either.
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        vfs.rename(&mut host, root, b"dev", tmp, b"dev", false, NOW)
            .unwrap();
        assert!(vfs.stat(root).nlink >= 2);
    }

    #[test]
    fn dotdot_of_a_removed_directory_whose_parent_is_gone() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        let a = vfs
            .create(&mut host, tmp, b"a", NewNode::Dir, 0o755, NOW)
            .unwrap();
        let b = vfs
            .create(&mut host, a, b"b", NewNode::Dir, 0o755, NOW)
            .unwrap();
        vfs.opened(b); // the current directory, say
        vfs.rmdir(&mut host, a, b"b", NOW).unwrap();
        vfs.rmdir(&mut host, tmp, b"a", NOW).unwrap();
        assert_eq!(vfs.resolve(&mut host, b, b".", true), Ok(b));
        assert_eq!(vfs.resolve(&mut host, b, b"..", true), Err(Errno(ENOENT)));
        assert_eq!(vfs.resolve(&mut host, b, b"../x", true), Err(Errno(ENOENT)));
        vfs.closed(b);
    }

    #[test]
    fn in_memory_layer_has_a_budget() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let base = vfs.upper_used();
        vfs.set_upper_limit(base + 10_000);
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        let f = vfs
            .create(&mut host, tmp, b"f", NewNode::File, 0o644, NOW)
            .unwrap();
        assert_eq!(vfs.write(&mut host, f, 0, &[1; 4000], NOW), Ok(4000));
        assert_eq!(
            vfs.write(&mut host, f, 4000, &[1; 8000], NOW),
            Err(Errno(ENOSPC))
        );
        assert_eq!(vfs.truncate(&mut host, f, 100_000, NOW), Err(Errno(ENOSPC)));
        assert_eq!(vfs.size(f), 4000);
        // Copying an image file up is charged as well.
        let passwd = resolve(&mut vfs, &mut host, "/etc/passwd").unwrap();
        vfs.write(&mut host, passwd, 0, b"x", NOW).unwrap();
        assert!(vfs.upper_used() > base + 4000 + 11);
        // Many small files run into the budget, too.
        let mut created = 0;
        while vfs
            .create(
                &mut host,
                tmp,
                format!("n{created}").as_bytes(),
                NewNode::File,
                0o644,
                NOW,
            )
            .is_ok()
        {
            created += 1;
            assert!(created < 100, "node creation is not charged");
        }
        assert!(created > 0);
        // Everything is given back.
        for i in 0..created {
            vfs.unlink(&mut host, tmp, format!("n{i}").as_bytes(), NOW)
                .unwrap();
        }
        vfs.unlink(&mut host, tmp, b"f", NOW).unwrap();
        vfs.truncate(&mut host, passwd, 0, NOW).unwrap();
        assert_eq!(vfs.upper_used(), base);
    }

    #[test]
    fn truncating_an_image_file_copies_up_only_what_is_kept() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let base = vfs.upper_used();
        let passwd = resolve(&mut vfs, &mut host, "/etc/passwd").unwrap();
        vfs.truncate(&mut host, passwd, 4, NOW).unwrap();
        assert_eq!(vfs.read_all(&mut host, passwd).unwrap(), b"root");
        assert_eq!(vfs.upper_used(), base + 4);
        vfs.truncate(&mut host, passwd, 6, NOW).unwrap();
        assert_eq!(vfs.read_all(&mut host, passwd).unwrap(), b"root\0\0");
        assert_eq!(vfs.upper_used(), base + 6);
    }

    #[test]
    fn create_through_a_symlink_targets_what_it_points_to() {
        let mut host = image();
        let mut vfs = Vfs::new(&mut host, NOW);
        let root = vfs.root();
        let tmp = resolve(&mut vfs, &mut host, "/tmp").unwrap();
        let link = vfs
            .create(
                &mut host,
                tmp,
                b"link",
                NewNode::Symlink(b"target".to_vec()),
                0o777,
                NOW,
            )
            .unwrap();
        vfs.create(
            &mut host,
            tmp,
            b"abs",
            NewNode::Symlink(b"/tmp/link".to_vec()),
            0o777,
            NOW,
        )
        .unwrap();
        let missing = CreateTarget::Missing(ParentAndName {
            dir: tmp,
            name: b"target".to_vec(),
            trailing_slash: false,
        });
        // Followed, also through a second symlink, to the missing target.
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/tmp/link", true),
            Ok(missing.clone())
        );
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/tmp/abs", true),
            Ok(missing)
        );
        // Not followed (O_EXCL, O_NOFOLLOW): the link itself exists.
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/tmp/link", false),
            Ok(CreateTarget::Existing(link))
        );
        let etc = resolve(&mut vfs, &mut host, "/etc").unwrap();
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/abs", true),
            Ok(CreateTarget::Existing(etc))
        );
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/loop", true),
            Err(Errno(ELOOP))
        );
        assert_eq!(
            vfs.resolve_for_create(&mut host, root, b"/nodir/f", true),
            Err(Errno(ENOENT))
        );
    }
}
