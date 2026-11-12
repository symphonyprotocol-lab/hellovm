//! Test doubles: a scripted multi-task platform with page-granular memory,
//! a standalone memory ([`MockApp`]) for address-space tests, and an
//! in-memory host with an image tree and a clock the platform advances.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::rc::Rc;
use std::time::Duration;

use crate::arch::{Arch, Sysno};
use crate::host::{
    ConsoleStream, Host, HostFileKind, HostStat, HostStreamId, ImagePath, OutboundFlow,
    StreamStatus,
};
use crate::platform::{
    AddressSpace, AddressSpaceInfo, AppMemory, Context, CpuInfo, Event, GuestAddr, Platform,
    PlatformError, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap, Waker,
};

const PAGE: u64 = 0x1000;
const RESERVED: u64 = 0xf_fff0_0000;

type Pages = HashMap<u64, (Prot, Box<[u8; PAGE as usize]>)>;

/// An address space with memory that honours page protections like
/// `process_vm_readv`/`writev` do.
#[derive(Clone, Default)]
pub struct MockApp {
    pages: Pages,
}

impl MockApp {
    pub fn new(_arch: Arch) -> Self {
        MockApp::default()
    }

    pub fn reserved(&self) -> GuestAddr {
        RESERVED
    }

    pub fn address_space(&self) -> AddressSpaceInfo {
        AddressSpaceInfo {
            page_size: PAGE,
            min_addr: 0x1_0000,
            max_addr: 1 << 39,
            reserved: std::iter::once(RESERVED..RESERVED + 0x1_0000).collect(),
        }
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
    fn map(
        &mut self,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        _sharing: Sharing,
    ) -> Result<(), PlatformError> {
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

/// One scripted task of a [`MockPlatform`].
pub struct MockTask {
    /// The traps it will make, in order.
    pub traps: VecDeque<Trap>,
    /// The syscall results it received.
    pub returns: Vec<i64>,
    pub started: Option<(GuestAddr, GuestAddr)>,
    /// The contexts it was resumed with by `Resume::Continue`.
    pub continued: Vec<Context>,
    pub context: Context,
    pub running: bool,
    pub killed: bool,
    /// Index into the platform's address spaces.
    pub space: usize,
}

/// A platform whose tasks follow scripts. Each task created by `spawn` or
/// `clone_task` takes the next script from [`MockPlatform::scripts`]; tasks
/// run one trap at a time in FIFO order of resumption.
pub struct MockPlatform {
    pub arch: Arch,
    pub tasks: BTreeMap<TaskKey, MockTask>,
    pub scripts: VecDeque<Vec<Trap>>,
    pub spaces: Vec<MockApp>,
    next_key: TaskKey,
    queue: VecDeque<TaskKey>,
    clock: Rc<Cell<Duration>>,
}

impl MockPlatform {
    pub fn new(arch: Arch, host: &MockHost) -> Self {
        MockPlatform {
            arch,
            tasks: BTreeMap::new(),
            scripts: VecDeque::new(),
            spaces: Vec::new(),
            next_key: 1,
            queue: VecDeque::new(),
            clock: Rc::clone(&host.clock),
        }
    }

    pub fn with_scripts(arch: Arch, host: &MockHost, scripts: Vec<Vec<Trap>>) -> Self {
        let mut p = MockPlatform::new(arch, host);
        p.scripts = scripts.into();
        p
    }

    pub fn syscall(arch: Arch, sysno: Sysno, args: &[u64]) -> Trap {
        let mut all = [0; 6];
        all[..args.len()].copy_from_slice(args);
        Trap::Syscall(SyscallTrap {
            nr: arch.syscall_nr(sysno).unwrap(),
            args: all,
        })
    }

    pub fn task(&self, key: TaskKey) -> &MockTask {
        &self.tasks[&key]
    }

    /// The memory of a task's address space.
    pub fn mem(&mut self, key: TaskKey) -> &mut MockApp {
        let space = self.tasks[&key].space;
        &mut self.spaces[space]
    }

    fn add_task(&mut self, space: usize, context: Context) -> TaskKey {
        let key = self.next_key;
        self.next_key += 1;
        let traps = self.scripts.pop_front().unwrap_or_default();
        self.tasks.insert(
            key,
            MockTask {
                traps: traps.into(),
                returns: Vec::new(),
                started: None,
                continued: Vec::new(),
                context,
                running: false,
                killed: false,
                space,
            },
        );
        key
    }

    fn live(&mut self, key: TaskKey) -> Result<&mut MockTask, PlatformError> {
        match self.tasks.get_mut(&key) {
            Some(task) if !task.killed => Ok(task),
            _ => Err(PlatformError::AppGone(format!("no task {key}"))),
        }
    }
}

impl Platform for MockPlatform {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn address_space(&self) -> AddressSpaceInfo {
        MockApp::default().address_space()
    }

    fn cpu_info(&self) -> CpuInfo {
        CpuInfo {
            hwcap: 0x1234,
            hwcap2: 0x5,
        }
    }

    fn spawn(&mut self) -> Result<TaskKey, PlatformError> {
        self.spaces.push(MockApp::default());
        let space = self.spaces.len() - 1;
        Ok(self.add_task(space, Context::zeroed(self.arch)))
    }

    fn clone_task(
        &mut self,
        parent: TaskKey,
        share_memory: bool,
    ) -> Result<TaskKey, PlatformError> {
        let task = self.live(parent)?;
        assert!(!task.running);
        let context = task.context.clone();
        let mut space = task.space;
        if !share_memory {
            let copy = self.spaces[space].clone();
            self.spaces.push(copy);
            space = self.spaces.len() - 1;
        }
        Ok(self.add_task(space, context))
    }

    fn kill(&mut self, task: TaskKey) -> Result<(), PlatformError> {
        let task = self.live(task)?;
        task.killed = true;
        task.running = false;
        Ok(())
    }

    fn context(&mut self, task: TaskKey) -> Result<Context, PlatformError> {
        Ok(self.live(task)?.context.clone())
    }

    fn set_context(&mut self, task: TaskKey, context: &Context) -> Result<(), PlatformError> {
        self.live(task)?.context = context.clone();
        Ok(())
    }

    fn resume(&mut self, key: TaskKey, resume: Resume) -> Result<(), PlatformError> {
        let task = self.live(key)?;
        assert!(!task.running, "task {key} resumed twice");
        match resume {
            Resume::Start { entry, stack } => {
                assert!(task.started.is_none());
                task.started = Some((entry, stack));
                task.context.set_pc(entry);
                task.context.set_sp(stack);
            }
            Resume::Return(ret) => {
                task.returns.push(ret);
                task.context.set_ret(ret);
            }
            Resume::Continue => task.continued.push(task.context.clone()),
        }
        task.running = true;
        self.queue.push_back(key);
        Ok(())
    }

    fn interrupt(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        let task = self.live(key)?;
        if task.running {
            task.traps.push_front(Trap::Interrupted);
        }
        Ok(())
    }

    fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, PlatformError> {
        while let Some(key) = self.queue.pop_front() {
            let task = self.tasks.get_mut(&key).expect("queued task");
            if task.killed || !task.running {
                continue;
            }
            task.running = false;
            let trap = task
                .traps
                .pop_front()
                .ok_or_else(|| PlatformError::AppGone(format!("task {key}: script ended")))?;
            if let Trap::Syscall(s) = trap {
                // Like a real syscall stop: the arguments are in registers.
                if let Context::Aarch64(c) = &mut task.context {
                    c.x[..6].copy_from_slice(&s.args);
                    c.x[8] = s.nr;
                }
            }
            return Ok(Some(Event { task: key, trap }));
        }
        match timeout {
            Some(t) => {
                self.clock.set(self.clock.get() + t);
                Ok(None)
            }
            None => Err(PlatformError::AppGone(
                "deadlock: no task is running and there is no timeout".into(),
            )),
        }
    }

    fn waker(&self) -> Waker {
        Waker::noop()
    }

    fn read(
        &mut self,
        task: TaskKey,
        addr: GuestAddr,
        buf: &mut [u8],
    ) -> Result<(), PlatformError> {
        self.live(task)?;
        self.mem(task).read(addr, buf)
    }

    fn write(&mut self, task: TaskKey, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        self.live(task)?;
        self.mem(task).write(addr, data)
    }

    fn map(
        &mut self,
        task: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError> {
        self.live(task)?;
        self.mem(task).map(addr, len, prot, sharing)
    }

    fn unmap(&mut self, task: TaskKey, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        self.live(task)?;
        self.mem(task).unmap(addr, len)
    }

    fn protect(
        &mut self,
        task: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
    ) -> Result<(), PlatformError> {
        self.live(task)?;
        self.mem(task).protect(addr, len, prot)
    }
}

/// An entry of [`MockHost`]'s image.
#[derive(Clone, Debug)]
pub enum MockEntry {
    Dir,
    File(Vec<u8>),
    Symlink(Vec<u8>),
}

/// A host with console capture, deterministic random bytes, a clock that
/// only the [`MockPlatform`] advances (when it waits), and an in-memory
/// image tree. It records every image path it is asked about.
#[derive(Default)]
pub struct MockHost {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdin: VecDeque<u8>,
    /// When set, console input reports `WouldBlock` instead of EOF once
    /// `stdin` is empty.
    pub stdin_open: bool,
    pub image: Option<BTreeMap<String, MockEntry>>,
    pub asked: Vec<String>,
    pub clock: Rc<Cell<Duration>>,
    /// When set, issued-fake-IP connects splice to an in-memory peer.
    pub splice: bool,
    /// Echo guest writes back as peer data.
    pub splice_echo: bool,
    /// The peer is already gone: writes fail with `BrokenPipe`.
    pub splice_break_writes: bool,
    /// The connect itself fails.
    pub splice_fail_connect: bool,
    /// The peer half-closes (FIN) as soon as the stream is up. Writes still work.
    pub splice_peer_fin: bool,
    streams: Vec<MockStream>,
}

struct MockStream {
    flow: OutboundFlow,
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    shut_wr: bool,
    read_eof: bool,
    broken: bool,
    failed: bool,
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
            clock: Rc::new(Cell::new(Duration::from_secs(100))),
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
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match stream {
            ConsoleStream::Stdout => self.stdout.extend_from_slice(data),
            ConsoleStream::Stderr => self.stderr.extend_from_slice(data),
        }
        Ok(data.len())
    }

    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stdin.is_empty() && self.stdin_open {
            return Err(io::ErrorKind::WouldBlock.into());
        }
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

    fn clock_realtime(&mut self) -> Duration {
        Duration::new(1_699_999_900, 500) + self.clock.get()
    }

    fn clock_monotonic(&mut self) -> Duration {
        self.clock.get()
    }

    fn egress_configured(&self) -> bool {
        self.splice
    }

    fn open_stream(&mut self, flow: OutboundFlow, _waker: Waker) -> io::Result<HostStreamId> {
        if !self.splice {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no splice endpoint configured",
            ));
        }
        // The guest address is recorded and never dialed: there is no socket.
        let id = self.streams.len() as u64;
        self.streams.push(MockStream {
            flow,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            shut_wr: false,
            read_eof: self.splice_peer_fin,
            broken: self.splice_break_writes,
            failed: self.splice_fail_connect,
        });
        Ok(HostStreamId(id))
    }

    fn stream_connect_result(&mut self, id: HostStreamId) -> io::Result<()> {
        let stream = self.mock_stream(id)?;
        if stream.failed {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "mock splice refused",
            ))
        } else {
            Ok(())
        }
    }

    fn stream_status(&mut self, id: HostStreamId) -> io::Result<StreamStatus> {
        let stream = self.mock_stream(id)?;
        Ok(StreamStatus {
            established: true,
            failed: stream.failed,
            readable: !stream.inbound.is_empty() || stream.read_eof,
            writable: !stream.shut_wr && !stream.broken,
            broken: stream.broken,
            shut_write: stream.shut_wr,
        })
    }

    fn stream_read(&mut self, id: HostStreamId, buf: &mut [u8]) -> io::Result<usize> {
        let stream = self.mock_stream_mut(id)?;
        if stream.inbound.is_empty() {
            return if stream.broken {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "mock peer reset",
                ))
            } else if stream.read_eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let n = buf.len().min(stream.inbound.len());
        for (dst, src) in buf.iter_mut().zip(stream.inbound.drain(..n)) {
            *dst = src;
        }
        Ok(n)
    }

    fn stream_write(&mut self, id: HostStreamId, data: &[u8]) -> io::Result<usize> {
        let echo = self.splice_echo;
        let stream = self.mock_stream_mut(id)?;
        if stream.broken || stream.shut_wr {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mock peer closed",
            ));
        }
        stream.outbound.extend(data);
        if echo {
            stream.inbound.extend(data);
        }
        Ok(data.len())
    }

    fn stream_shutdown_write(&mut self, id: HostStreamId) -> io::Result<()> {
        self.mock_stream_mut(id)?.shut_wr = true;
        Ok(())
    }

    fn stream_close(&mut self, id: HostStreamId) {
        if let Ok(stream) = self.mock_stream_mut(id) {
            stream.broken = true;
            stream.read_eof = true;
        }
    }
}

impl MockHost {
    fn mock_stream(&self, id: HostStreamId) -> io::Result<&MockStream> {
        self.streams
            .get(id.0 as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "mock stream is closed"))
    }

    fn mock_stream_mut(&mut self, id: HostStreamId) -> io::Result<&mut MockStream> {
        self.streams
            .get_mut(id.0 as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "mock stream is closed"))
    }

    /// Guest bytes written to the spliced stream.
    pub fn splice_outbound(&self, id: HostStreamId) -> Vec<u8> {
        self.streams[id.0 as usize]
            .outbound
            .iter()
            .copied()
            .collect()
    }

    pub fn splice_flows(&self) -> impl Iterator<Item = &OutboundFlow> {
        self.streams.iter().map(|s| &s.flow)
    }
}
