//! A minimal `/proc`, generated from the kernel's own state.
//!
//! `/proc` is not a VFS directory: the path syscalls recognize a path that
//! lands in it (`Ctx::proc_path`) and resolve the rest here. Paths are
//! taken lexically (`.` and `..` are applied to the components, the start
//! directory is the caller's cwd or `dirfd`), so a symlink elsewhere that
//! points into `/proc` is not followed into it. Inside `/proc`, `self`,
//! `thread-self` and the per-process links (`exe`, `cwd`, `fd/<n>`) work
//! like symlinks. Files are generated when they are opened, and a read sees
//! that snapshot.
//!
//! What exists: `/proc/{self,thread-self,<pid>}` with `exe`, `cwd`, `fd/`,
//! `maps`, `stat`, `status`, `statm`, `cmdline`, `comm`, `environ` (empty),
//! `mounts` and `task/<tid>/`; and `/proc/{meminfo,cpuinfo,uptime,stat,
//! loadavg,version,mounts,filesystems}`. Only the processes of the sandbox
//! appear, with sandbox pids.

use crate::errno::{Errno, SysResult, EACCES, ENOENT};
use crate::fd::FileObject;
use crate::host::Host;
use crate::mm::VmaKind;
use crate::platform::Platform;
use crate::task::{Pid, Tid};
use crate::vfs::{DirEntry, FileType, Stat, S_IFDIR, S_IFREG};

use super::{Ctx, AT_FDCWD};

/// `S_IFLNK`.
const S_IFLNK: u32 = 0o120_000;
/// The device number of `/proc`.
const PROC_DEV: u64 = 0x16;
/// Total memory reported to the guest.
const MEM_TOTAL_KB: u64 = 1 << 20;

/// A node of `/proc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProcNode {
    Dir(Vec<DirEntry>),
    File(Vec<u8>),
    /// A symbolic link to this path.
    Link(Vec<u8>),
}

impl ProcNode {
    pub fn stat(&self, ino: u64, time: crate::vfs::Timespec) -> Stat {
        let (mode, size) = match self {
            ProcNode::Dir(_) => (S_IFDIR | 0o555, 0),
            ProcNode::File(_) => (S_IFREG | 0o444, 0),
            ProcNode::Link(target) => (S_IFLNK | 0o777, target.len() as u64),
        };
        Stat {
            dev: PROC_DEV,
            ino,
            mode,
            nlink: 1,
            size,
            blksize: 4096,
            atime: time,
            mtime: time,
            ctime: time,
            ..Stat::default()
        }
    }

    pub fn object(&self) -> FileObject {
        FileObject::Proc {
            dir: matches!(self, ProcNode::Dir(_)),
        }
    }
}

/// An inode number for a `/proc` path (stable for the path).
pub(crate) fn proc_ino(comps: &[Vec<u8>]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for c in comps {
        for &b in c.iter().chain(b"/") {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    0x1_0000_0000 | (h & 0xffff_ffff)
}

fn entry(name: &str, kind: FileType) -> DirEntry {
    DirEntry {
        name: name.as_bytes().to_vec(),
        ino: 0,
        kind,
    }
}

fn parse_id(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 9 || !name.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    /// If `dirfd` + `path` names something in `/proc`, the components after
    /// `/proc` (lexically normalized).
    pub(crate) fn proc_path(&self, dirfd: i64, path: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut comps: Vec<Vec<u8>> = Vec::new();
        if path.first() != Some(&b'/') {
            let base = if dirfd == AT_FDCWD {
                self.vfs.dir_path(self.proc().cwd)?
            } else {
                let (_, file) = self.file(dirfd).ok()?;
                match file.object {
                    FileObject::Node(ino) => self.vfs.dir_path(ino)?,
                    FileObject::Proc { dir: true } => file.path.clone()?,
                    _ => return None,
                }
            };
            comps = base
                .split(|&b| b == b'/')
                .filter(|c| !c.is_empty())
                .map(<[u8]>::to_vec)
                .collect();
        }
        for comp in path.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    comps.pop();
                }
                c => comps.push(c.to_vec()),
            }
        }
        if comps.first().map(Vec::as_slice) != Some(b"proc") {
            return None;
        }
        comps.remove(0);
        Some(comps)
    }

    /// Resolves the components after `/proc` to a node. `self` and
    /// `thread-self` are always followed; a final link only if `follow`
    /// (the caller then resolves its target).
    pub(crate) fn proc_lookup(&mut self, comps: &[Vec<u8>]) -> SysResult<(Vec<Vec<u8>>, ProcNode)> {
        let mut path: Vec<Vec<u8>> = Vec::new();
        for (i, comp) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            match (path.len(), comp.as_slice()) {
                (0, b"self") if !last => path.push(self.pid.to_string().into_bytes()),
                (0, b"thread-self") if !last => {
                    path.push(self.pid.to_string().into_bytes());
                    path.push(b"task".to_vec());
                    path.push(self.tid.to_string().into_bytes());
                }
                _ => path.push(comp.clone()),
            }
        }
        let node = self.proc_node(&path)?;
        Ok((path, node))
    }

    fn proc_node(&mut self, path: &[Vec<u8>]) -> SysResult<ProcNode> {
        let comps: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
        match comps.as_slice() {
            [] => Ok(self.proc_root()),
            [b"self"] => Ok(ProcNode::Link(self.pid.to_string().into_bytes())),
            [b"thread-self"] => Ok(ProcNode::Link(
                format!("{}/task/{}", self.pid, self.tid).into_bytes(),
            )),
            [b"net"] => Ok(ProcNode::Dir(vec![
                entry("tcp", FileType::Regular),
                entry("udp", FileType::Regular),
            ])),
            [b"net", b"tcp"] => Ok(ProcNode::File(self.st.net.proc_tcp())),
            [b"net", b"udp"] => Ok(ProcNode::File(self.st.net.proc_udp())),
            [name] if parse_id(name).is_none() => self.proc_global(name),
            [pid, rest @ ..] => {
                let pid = parse_id(pid).ok_or(Errno(ENOENT))?;
                if !self.st.procs.contains_key(&pid) {
                    return Err(Errno(ENOENT));
                }
                match rest {
                    [b"task", tid, rest @ ..] => {
                        let tid = parse_id(tid).ok_or(Errno(ENOENT))?;
                        match self.st.threads.get(&tid) {
                            Some(t) if t.pid == pid => self.proc_pid(pid, Some(tid), rest),
                            _ => Err(Errno(ENOENT)),
                        }
                    }
                    [b"task"] => {
                        let entries = self
                            .st
                            .proc(pid)
                            .threads
                            .iter()
                            .map(|t| entry(&t.to_string(), FileType::Directory))
                            .collect();
                        Ok(ProcNode::Dir(entries))
                    }
                    rest => self.proc_pid(pid, None, rest),
                }
            }
        }
    }

    fn proc_root(&self) -> ProcNode {
        let mut entries = vec![
            entry("self", FileType::Symlink),
            entry("thread-self", FileType::Symlink),
        ];
        for name in [
            "meminfo",
            "cpuinfo",
            "uptime",
            "stat",
            "loadavg",
            "version",
            "mounts",
            "filesystems",
        ] {
            entries.push(entry(name, FileType::Regular));
        }
        entries.push(entry("net", FileType::Directory));
        for pid in self.st.procs.keys() {
            entries.push(entry(&pid.to_string(), FileType::Directory));
        }
        ProcNode::Dir(entries)
    }

    fn proc_global(&mut self, name: &[u8]) -> SysResult<ProcNode> {
        let uptime = self.host.clock_monotonic();
        let text = match name {
            b"meminfo" => format!(
                "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
                 Buffers:               0 kB\nCached:                0 kB\nSwapCached:            0 kB\n\
                 SwapTotal:             0 kB\nSwapFree:              0 kB\nShmem:                 0 kB\n",
                total = MEM_TOTAL_KB,
                free = MEM_TOTAL_KB / 2
            ),
            b"cpuinfo" => format!(
                "processor\t: 0\nmodel name\t: hellovm {} CPU\nBogoMIPS\t: 100.00\n\n",
                self.arch.name()
            ),
            b"uptime" => format!(
                "{}.{:02} {}.{:02}\n",
                uptime.as_secs(),
                uptime.subsec_millis() / 10,
                uptime.as_secs(),
                uptime.subsec_millis() / 10
            ),
            b"stat" => {
                let ticks = uptime.as_millis() / 10;
                let boot = self.host.clock_realtime().saturating_sub(uptime).as_secs();
                format!(
                    "cpu  {ticks} 0 0 0 0 0 0 0 0 0\ncpu0 {ticks} 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\n\
                     btime {boot}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n",
                    self.st.procs.len()
                )
            }
            b"loadavg" => format!(
                "0.00 0.00 0.00 1/{} {}\n",
                self.st.threads.len(),
                self.st.procs.keys().last().copied().unwrap_or(1)
            ),
            b"version" => "Linux version 6.1.0-hellovm (hellovm) #1 SMP hellovm\n".to_string(),
            b"mounts" => MOUNTS.to_string(),
            b"filesystems" => "nodev\tproc\n\toverlay\n".to_string(),
            _ => return Err(Errno(ENOENT)),
        };
        Ok(ProcNode::File(text.into_bytes()))
    }

    fn proc_pid(&mut self, pid: Pid, tid: Option<Tid>, rest: &[&[u8]]) -> SysResult<ProcNode> {
        let proc = self.st.proc(pid);
        let alive = proc.alive();
        match rest {
            [] => {
                let mut entries: Vec<DirEntry> = [
                    "stat", "status", "statm", "cmdline", "comm", "environ", "maps", "mounts",
                ]
                .iter()
                .map(|n| entry(n, FileType::Regular))
                .collect();
                for link in ["exe", "cwd"] {
                    entries.push(entry(link, FileType::Symlink));
                }
                entries.push(entry("fd", FileType::Directory));
                if tid.is_none() {
                    entries.push(entry("task", FileType::Directory));
                }
                Ok(ProcNode::Dir(entries))
            }
            [b"exe"] if alive => Ok(ProcNode::Link(proc.exe.clone())),
            [b"cwd"] if alive => {
                let cwd = proc.cwd;
                Ok(ProcNode::Link(self.vfs.dir_path(cwd).ok_or(Errno(ENOENT))?))
            }
            [b"exe" | b"cwd"] => Err(Errno(ENOENT)),
            [b"fd"] => {
                let entries = proc
                    .fds
                    .fds()
                    .iter()
                    .map(|fd| entry(&fd.to_string(), FileType::Symlink))
                    .collect();
                Ok(ProcNode::Dir(entries))
            }
            [b"fd", fd] => {
                let fd = parse_id(fd).ok_or(Errno(ENOENT))?;
                let id = proc.fds.get(i64::from(fd)).map_err(|_| Errno(ENOENT))?;
                let file = self.st.files.get(id);
                let target = match (&file.path, file.object) {
                    (Some(path), _) => path.clone(),
                    (None, FileObject::PipeRead(p) | FileObject::PipeWrite(p)) => {
                        format!("pipe:[{}]", 0x1000 + p).into_bytes()
                    }
                    (None, FileObject::Socket(id)) => {
                        format!("socket:[{}]", 0x10_0000 + id).into_bytes()
                    }
                    (None, FileObject::Node(ino)) => {
                        self.vfs.dir_path(ino).unwrap_or_else(|| b"/".to_vec())
                    }
                    (None, _) => b"/dev/console".to_vec(),
                };
                Ok(ProcNode::Link(target))
            }
            [b"cmdline"] => Ok(ProcNode::File(proc.cmdline.clone())),
            [b"comm"] => {
                let mut name = proc.name.clone();
                name.push(b'\n');
                Ok(ProcNode::File(name))
            }
            [b"environ"] => Ok(ProcNode::File(Vec::new())),
            [b"mounts"] => Ok(ProcNode::File(MOUNTS.as_bytes().to_vec())),
            [b"maps"] => Ok(ProcNode::File(self.proc_maps(pid))),
            [b"stat"] => Ok(ProcNode::File(self.proc_stat(pid, tid))),
            [b"statm"] => {
                let pages = self.vm_size(pid) / 4096;
                Ok(ProcNode::File(
                    format!("{pages} {pages} 0 0 0 {pages} 0\n").into_bytes(),
                ))
            }
            [b"status"] => Ok(ProcNode::File(self.proc_status(pid, tid))),
            _ => Err(Errno(ENOENT)),
        }
    }

    fn vm_size(&self, pid: Pid) -> u64 {
        let Some(mm) = self.st.proc(pid).mm else {
            return 0;
        };
        self.st
            .mms
            .get(mm)
            .mm
            .vmas()
            .iter()
            .filter(|v| v.kind != VmaKind::Reserved)
            .map(|v| v.end - v.start)
            .sum()
    }

    /// The one-letter state of a process.
    fn state_letter(&self, pid: Pid) -> char {
        let proc = self.st.proc(pid);
        if !proc.alive() {
            'Z'
        } else if proc.stopped {
            'T'
        } else if proc
            .threads
            .iter()
            .all(|t| self.st.thread(*t).parked().is_some())
        {
            'S'
        } else {
            'R'
        }
    }

    fn proc_stat(&mut self, pid: Pid, tid: Option<Tid>) -> Vec<u8> {
        let state = self.state_letter(pid);
        let vsize = self.vm_size(pid);
        let fg = self.st.console.foreground().unwrap_or(0);
        let proc = self.st.proc(pid);
        let start_ticks = proc.start_time.as_millis() / 10;
        let tty = if proc.sid == self.st.console.session().unwrap_or(0) {
            (5 << 8) | 1
        } else {
            0
        };
        format!(
            "{} ({}) {state} {} {} {} {tty} {fg} 4194304 0 0 0 0 0 0 0 0 20 0 {} 0 {start_ticks} {vsize} {} \
             18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            tid.unwrap_or(pid),
            String::from_utf8_lossy(&proc.name),
            proc.ppid,
            proc.pgid,
            proc.sid,
            proc.threads.len(),
            vsize / 4096,
        )
        .into_bytes()
    }

    fn proc_status(&mut self, pid: Pid, tid: Option<Tid>) -> Vec<u8> {
        let state = match self.state_letter(pid) {
            'R' => "R (running)",
            'S' => "S (sleeping)",
            'T' => "T (stopped)",
            _ => "Z (zombie)",
        };
        let vsize_kb = self.vm_size(pid) / 1024;
        let proc = self.st.proc(pid);
        let sigmask = tid
            .or_else(|| proc.threads.first().copied())
            .and_then(|t| self.st.threads.get(&t))
            .map_or(0, |t| t.sigmask);
        let ignored = proc
            .actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.handler == crate::signal::SIG_IGN)
            .fold(0u64, |set, (i, _)| set | 1 << i);
        let caught = proc
            .actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.handler > crate::signal::SIG_IGN)
            .fold(0u64, |set, (i, _)| set | 1 << i);
        format!(
            "Name:\t{}\nUmask:\t{:04o}\nState:\t{state}\nTgid:\t{pid}\nPid:\t{}\nPPid:\t{}\n\
             TracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nVmSize:\t{vsize_kb} kB\n\
             VmRSS:\t{vsize_kb} kB\nThreads:\t{}\nSigPnd:\t{:016x}\nSigBlk:\t{sigmask:016x}\n\
             SigIgn:\t{ignored:016x}\nSigCgt:\t{caught:016x}\nCapEff:\t000001ffffffffff\n",
            String::from_utf8_lossy(&proc.name),
            proc.umask,
            tid.unwrap_or(pid),
            proc.ppid,
            proc.threads.len(),
            proc.pending.set(),
        )
        .into_bytes()
    }

    fn proc_maps(&self, pid: Pid) -> Vec<u8> {
        let proc = self.st.proc(pid);
        let Some(mm) = proc.mm else {
            return Vec::new();
        };
        let mut out = String::new();
        for vma in self.st.mms.get(mm).mm.vmas().iter() {
            let name = match vma.kind {
                VmaKind::Reserved => continue,
                VmaKind::Heap => "[heap]".to_string(),
                VmaKind::Stack => "[stack]".to_string(),
                VmaKind::Vdso => "[vdso]".to_string(),
                VmaKind::Image => String::from_utf8_lossy(&proc.exe).into_owned(),
                VmaKind::Shared => "/dev/zero (deleted)".to_string(),
                VmaKind::Anonymous | VmaKind::File => String::new(),
            };
            let p = vma.prot;
            let flag = |bit, c| if p.contains(bit) { c } else { '-' };
            let share = if vma.kind == VmaKind::Shared {
                's'
            } else {
                'p'
            };
            out.push_str(&format!(
                "{:08x}-{:08x} {}{}{}{share} 00000000 00:00 0{}{name}\n",
                vma.start,
                vma.end,
                flag(crate::platform::Prot::READ, 'r'),
                flag(crate::platform::Prot::WRITE, 'w'),
                flag(crate::platform::Prot::EXEC, 'x'),
                if name.is_empty() {
                    ""
                } else {
                    "                          "
                },
            ));
        }
        out.into_bytes()
    }

    /// Where a `/proc` link leads when followed: another `/proc` path, or
    /// a path for the VFS.
    pub(crate) fn proc_follow(&self, comps: &[Vec<u8>], target: &[u8]) -> Vec<u8> {
        if target.first() == Some(&b'/') || target.starts_with(b"pipe:") {
            return target.to_vec();
        }
        // Relative to the link's directory inside /proc.
        let mut path = b"/proc".to_vec();
        for c in &comps[..comps.len().saturating_sub(1)] {
            path.push(b'/');
            path.extend_from_slice(c);
        }
        path.push(b'/');
        path.extend_from_slice(target);
        path
    }
}

/// What `/proc/mounts` shows.
const MOUNTS: &str =
    "overlay / overlay rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n\
                      devtmpfs /dev devtmpfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n";

/// `/proc` is read-only.
pub(crate) const PROC_WRITE: Errno = Errno(EACCES);
