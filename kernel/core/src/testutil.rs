//! Test doubles: a scripted platform with page-granular memory and an
//! in-memory host with an image tree.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;

use crate::arch::{Arch, Sysno};
use crate::host::{ConsoleStream, Host, HostFileKind, HostStat, ImagePath};
use crate::platform::{
    AddressSpace, AddressSpaceInfo, AppMemory, CpuInfo, GuestAddr, Platform, PlatformError, Prot,
    Resume, SyscallTrap, Trap,
};

const PAGE: u64 = 0x1000;
const RESERVED: u64 = 0xf_fff0_0000;

/// A scripted app: a fixed list of traps, and memory that honours page
/// protections like `process_vm_readv`/`writev` do.
pub struct MockApp {
    pub arch: Arch,
    pub traps: VecDeque<Trap>,
    pub returns: Vec<i64>,
    pub started: Option<(GuestAddr, GuestAddr)>,
    pub terminated: bool,
    pub thread_pointer: Option<u64>,
    pages: HashMap<u64, (Prot, Box<[u8; PAGE as usize]>)>,
}

impl MockApp {
    pub fn new(arch: Arch) -> Self {
        MockApp {
            arch,
            traps: VecDeque::new(),
            returns: Vec::new(),
            started: None,
            terminated: false,
            thread_pointer: None,
            pages: HashMap::new(),
        }
    }

    pub fn with_traps(arch: Arch, traps: Vec<Trap>) -> Self {
        let mut app = MockApp::new(arch);
        app.traps = traps.into();
        app
    }

    pub fn syscall(arch: Arch, sysno: Sysno, args: &[u64]) -> Trap {
        let mut all = [0; 6];
        all[..args.len()].copy_from_slice(args);
        Trap::Syscall(SyscallTrap {
            nr: arch.syscall_nr(sysno).unwrap(),
            args: all,
        })
    }

    pub fn reserved(&self) -> GuestAddr {
        RESERVED
    }

    pub fn is_mapped(&self, addr: GuestAddr) -> bool {
        self.pages.contains_key(&(addr & !(PAGE - 1)))
    }

    pub fn prot(&self, addr: GuestAddr) -> Option<Prot> {
        self.pages.get(&(addr & !(PAGE - 1))).map(|(p, _)| *p)
    }

    /// Maps and fills memory directly (test setup).
    pub fn poke(&mut self, addr: GuestAddr, data: &[u8]) {
        let start = addr & !(PAGE - 1);
        let end = (addr + data.len() as u64 + PAGE - 1) & !(PAGE - 1);
        for page in (start..end).step_by(PAGE as usize) {
            self.pages
                .entry(page)
                .or_insert_with(|| (Prot::RW, Box::new([0; PAGE as usize])));
        }
        self.access(addr, data.len(), Prot::NONE, |buf, off| {
            buf.copy_from_slice(&data[off..off + buf.len()])
        })
        .unwrap();
    }

    /// Reads memory regardless of protection (test checks).
    pub fn peek(&mut self, addr: GuestAddr, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        self.access(addr, len, Prot::NONE, |buf, off| {
            out[off..off + buf.len()].copy_from_slice(buf)
        })
        .unwrap();
        out
    }

    fn access(
        &mut self,
        addr: GuestAddr,
        len: usize,
        need: Prot,
        mut f: impl FnMut(&mut [u8], usize),
    ) -> Result<(), PlatformError> {
        let bad = PlatformError::BadAddress { addr, len };
        let mut done = 0;
        while done < len {
            let at = addr + done as u64;
            let page = at & !(PAGE - 1);
            let off = (at - page) as usize;
            let n = (PAGE as usize - off).min(len - done);
            let Some((prot, data)) = self.pages.get_mut(&page) else {
                return Err(bad);
            };
            if !prot.contains(need) {
                return Err(bad);
            }
            f(&mut data[off..off + n], done);
            done += n;
        }
        Ok(())
    }

    fn pages_of(addr: GuestAddr, len: u64) -> impl Iterator<Item = u64> {
        assert_eq!(addr % PAGE, 0);
        assert_eq!(len % PAGE, 0);
        (addr..addr + len).step_by(PAGE as usize)
    }

    fn check(&self, addr: GuestAddr, len: u64) {
        assert!(
            addr + len <= RESERVED || addr >= RESERVED + 0x1_0000,
            "core touched the reserved range"
        );
    }
}

impl AppMemory for MockApp {
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        self.access(addr, buf.len(), Prot::READ, |src, off| {
            buf[off..off + src.len()].copy_from_slice(src)
        })
    }

    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        self.access(addr, data.len(), Prot::WRITE, |dst, off| {
            dst.copy_from_slice(&data[off..off + dst.len()])
        })
    }
}

impl AddressSpace for MockApp {
    fn map(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError> {
        self.check(addr, len);
        for page in Self::pages_of(addr, len) {
            self.pages
                .insert(page, (prot, Box::new([0; PAGE as usize])));
        }
        Ok(())
    }

    fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        self.check(addr, len);
        for page in Self::pages_of(addr, len) {
            self.pages.remove(&page);
        }
        Ok(())
    }

    fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError> {
        self.check(addr, len);
        for page in Self::pages_of(addr, len) {
            match self.pages.get_mut(&page) {
                Some(entry) => entry.0 = prot,
                None => return Err(PlatformError::BadAddress { addr, len: 0 }),
            }
        }
        Ok(())
    }
}

impl Platform for MockApp {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn address_space(&self) -> AddressSpaceInfo {
        let reserved = RESERVED..RESERVED + 0x1_0000;
        AddressSpaceInfo {
            page_size: PAGE,
            min_addr: 0x1_0000,
            max_addr: 1 << 39,
            reserved: vec![reserved],
        }
    }

    fn cpu_info(&self) -> CpuInfo {
        CpuInfo {
            hwcap: 0x1234,
            hwcap2: 0x5,
        }
    }

    fn set_thread_pointer(&mut self, value: u64) -> Result<(), PlatformError> {
        self.thread_pointer = Some(value);
        Ok(())
    }

    fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError> {
        assert!(!self.terminated);
        match resume {
            Resume::Start { entry, stack } => {
                assert!(self.started.is_none());
                self.started = Some((entry, stack));
            }
            Resume::Return(ret) => self.returns.push(ret),
        }
        self.traps
            .pop_front()
            .ok_or_else(|| PlatformError::AppGone("script ended".into()))
    }

    fn terminate(&mut self) -> Result<(), PlatformError> {
        self.terminated = true;
        Ok(())
    }
}

/// An entry of [`MockHost`]'s image.
#[derive(Clone, Debug)]
pub enum MockEntry {
    Dir,
    File(Vec<u8>),
    Symlink(Vec<u8>),
}

/// A host with console capture, deterministic random bytes and clock, and
/// an in-memory image tree. It records every image path it is asked about.
#[derive(Default)]
pub struct MockHost {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdin: VecDeque<u8>,
    pub image: Option<BTreeMap<String, MockEntry>>,
    pub asked: Vec<String>,
    /// Total time the kernel asked to sleep.
    pub slept: std::time::Duration,
}

impl MockHost {
    pub fn with_image(entries: &[(&str, MockEntry)]) -> Self {
        let mut image = BTreeMap::new();
        image.insert(String::new(), MockEntry::Dir);
        for (path, entry) in entries {
            image.insert(path.to_string(), entry.clone());
        }
        MockHost {
            image: Some(image),
            ..Default::default()
        }
    }

    fn entry(&mut self, path: &ImagePath) -> io::Result<MockEntry> {
        let path = path.to_string();
        assert!(!path.starts_with('/') && !path.split('/').any(|c| c == ".."));
        self.asked.push(path.clone());
        self.image
            .as_ref()
            .and_then(|image| image.get(&path).cloned())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

impl Host for MockHost {
    fn sleep(&mut self, duration: std::time::Duration) {
        self.slept += duration;
    }

    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match stream {
            ConsoleStream::Stdout => self.stdout.extend_from_slice(data),
            ConsoleStream::Stderr => self.stderr.extend_from_slice(data),
        }
        Ok(data.len())
    }

    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.stdin.len());
        for (dst, src) in buf.iter_mut().zip(self.stdin.drain(..n)) {
            *dst = src;
        }
        Ok(n)
    }

    fn has_image(&self) -> bool {
        self.image.is_some()
    }

    fn image_stat(&mut self, path: &ImagePath) -> io::Result<HostStat> {
        let entry = self.entry(path)?;
        let (kind, size, mode) = match &entry {
            MockEntry::Dir => (HostFileKind::Directory, 4096, 0o755),
            MockEntry::File(data) => (HostFileKind::File, data.len() as u64, 0o755),
            MockEntry::Symlink(target) => (HostFileKind::Symlink, target.len() as u64, 0o777),
        };
        Ok(HostStat {
            kind,
            mode,
            size,
            nlink: 1,
            mtime: (1_700_000_000, 0),
        })
    }

    fn image_read_link(&mut self, path: &ImagePath) -> io::Result<Vec<u8>> {
        match self.entry(path)? {
            MockEntry::Symlink(target) => Ok(target),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    fn image_read_dir(&mut self, path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
        let MockEntry::Dir = self.entry(path)? else {
            return Err(io::ErrorKind::NotADirectory.into());
        };
        let prefix = if path.is_root() {
            String::new()
        } else {
            format!("{path}/")
        };
        let image = self.image.as_ref().unwrap();
        Ok(image
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(|name| name.as_bytes().to_vec())
            .collect())
    }

    fn image_read(&mut self, path: &ImagePath, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let MockEntry::File(data) = self.entry(path)? else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    fn random(&mut self, buf: &mut [u8]) -> io::Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8 ^ 0x5a;
        }
        Ok(())
    }

    fn clock_realtime(&mut self) -> std::time::Duration {
        std::time::Duration::new(1_700_000_000, 500)
    }

    fn clock_monotonic(&mut self) -> std::time::Duration {
        std::time::Duration::new(100, 0)
    }
}
