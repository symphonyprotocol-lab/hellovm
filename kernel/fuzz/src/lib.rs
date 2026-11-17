//! Fuzz targets: one function per parser of guest- or network-controlled
//! bytes. Each must never panic and must stay within bounded time and
//! memory on any input; some also check a property of their result.
//!
//! The libFuzzer binaries in `fuzz_targets/` call these, and so does
//! `tests/corpus.rs`, which runs every target over its corpus
//! (`corpus/<target>/`) and seeded mutations of it on the stable
//! toolchain.

use std::io::Cursor;
use std::time::Duration;

use hellovm_core::elf::{self, Placement};
use hellovm_core::mm::Mm;
use hellovm_core::net::Net;
use hellovm_core::platform::{Context, Fault, SyscallTrap, Trap};
use hellovm_core::testutil::{MockApp, MockEntry, MockHost, MockPlatform};
use hellovm_core::vfs::{Timespec, Vfs};
use hellovm_core::{fuzzing, signal, Arch, Kernel};
use hellovm_egress::policy::{Policy, Rule};
use hellovm_egress::sniff::{self, Sniff};
use hellovm_egress::wire::{self, Request, Status};

/// A fuzz target.
pub type Target = fn(&[u8]);

/// Every target, by name.
pub const TARGETS: &[(&str, Target)] = &[
    ("elf", elf),
    ("dns", dns),
    ("wire", wire),
    ("sniff", sniff),
    ("policy", policy),
    ("vfs_path", vfs_path),
    ("shebang", shebang),
    ("sigreturn", sigreturn),
    ("syscalls", syscalls),
];

const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

/// The ELF parser and loader (`execve` of an image file).
pub fn elf(data: &[u8]) {
    for arch in ARCHES {
        let Ok(parsed) = elf::parse(data, arch) else {
            continue;
        };
        for placement in [Placement::Program, Placement::Interpreter] {
            let mut app = MockApp::new(arch);
            let mut mm = Mm::new(&app.address_space());
            let _ = elf::load(&mut mm, &mut app, data, &parsed, placement);
        }
    }
}

/// The virtual DNS responder: one query, with and without an egress
/// proxy. A reply is a DNS message for the same id.
pub fn dns(data: &[u8]) {
    let mut net = Net::default();
    let now = Duration::from_secs(1);
    for outbound in [true, false] {
        if let Some(reply) = fuzzing::dns_reply(&mut net, data, outbound, now) {
            assert!(reply.len() >= 12, "short reply");
            assert_eq!(reply[..2], data[..2], "reply id");
            assert!(
                reply.len() <= 12 + data.len() + 16,
                "reply grew: {}",
                reply.len()
            );
        }
    }
    // The same query again gets the same answer (bindings are stable),
    // also much later.
    let first = fuzzing::dns_reply(&mut net, data, true, now);
    assert_eq!(first, fuzzing::dns_reply(&mut net, data, true, now));
    let later = Duration::from_secs(1 << 20);
    let _ = fuzzing::dns_reply(&mut net, data, true, later);
}

/// The egress flow header (proxy side) and verdict (kernel side).
pub fn wire(data: &[u8]) {
    if let Ok(request) = Request::read_from(&mut Cursor::new(data)) {
        assert!(wire::valid_hostname(request.host.as_bytes()));
        let encoded = request.encode().expect("a parsed request encodes");
        let again = Request::read_from(&mut Cursor::new(&encoded)).expect("round trip");
        assert_eq!(
            (again.sandbox_id, again.port, &again.host),
            (request.sandbox_id, request.port, &request.host)
        );
    }
    if let Some(bytes) = data.get(..wire::REPLY) {
        let reply: [u8; wire::REPLY] = bytes.try_into().unwrap();
        if let Some(status) = Status::parse_reply(&reply) {
            assert_eq!(status.reply(), reply);
        }
    }
    if let Some(&b) = data.first() {
        let _ = Status::from_byte(b);
    }
    let _ = wire::normalize_hostname(&String::from_utf8_lossy(data));
}

fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The SNI and `Host` sniffer. A name is only ever returned if it appears
/// in the input, and it is a valid hostname.
pub fn sniff(data: &[u8]) {
    match sniff::sniff(data) {
        Sniff::Tls(name) => {
            assert!(
                contains_ignoring_case(data, name.as_bytes()),
                "sniffed {name:?}, which is not in the input"
            );
        }
        Sniff::Http(req) => {
            assert!(
                contains_ignoring_case(&data[..req.head_len.min(data.len())], req.host.as_bytes()),
                "sniffed {:?}, which is not in the request head",
                req.host
            );
            assert!(req.head_len <= data.len(), "head past the input");
            assert!(
                req.forward.len() <= req.head_len + 64,
                "forwarded head grew from {} to {}",
                req.head_len,
                req.forward.len()
            );
        }
        Sniff::NeedMore | Sniff::Invalid(_) => {}
    }
    // Every prefix is a state the proxy sees while bytes arrive.
    for cut in [1, data.len() / 2, data.len().saturating_sub(1)] {
        if cut < data.len() {
            let _ = sniff::sniff(&data[..cut]);
        }
    }
}

/// The egress policy file and rule parser, then lookups.
pub fn policy(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut policy = Policy::new();
    let _ = policy.add_file(&text);
    for line in text.lines() {
        if let Ok(rule) = Rule::parse(line.trim()) {
            policy.push(rule);
        }
    }
    for line in text.lines().take(16) {
        let host = line.trim().trim_start_matches("allow").trim();
        let host = host
            .split(':')
            .next()
            .unwrap_or("")
            .trim_start_matches("*.");
        for port in [80, 443, 8080] {
            let _ = policy.allows(host, port);
        }
    }
    let _ = policy.allows("pypi.org", 443);
}

/// An image with symlinks that loop, climb above the root, point at
/// absolute paths and chain deeply.
fn tricky_image() -> MockHost {
    MockHost::with_image(&[
        ("bin", MockEntry::Dir),
        ("bin/sh", MockEntry::File(b"#!/bin/sh\n".to_vec())),
        ("etc", MockEntry::Dir),
        (
            "etc/passwd",
            MockEntry::File(b"root:x:0:0::/:/bin/sh\n".to_vec()),
        ),
        ("loop", MockEntry::Symlink(b"loop".to_vec())),
        ("a", MockEntry::Symlink(b"b".to_vec())),
        ("b", MockEntry::Symlink(b"a".to_vec())),
        ("up", MockEntry::Symlink(b"../../../../etc".to_vec())),
        ("abs", MockEntry::Symlink(b"/etc/passwd".to_vec())),
        ("dir", MockEntry::Dir),
        ("dir/self", MockEntry::Symlink(b".".to_vec())),
        ("dir/parent", MockEntry::Symlink(b"..".to_vec())),
        (
            "dir/deep",
            MockEntry::Symlink(b"self/self/self/self/self/deep".to_vec()),
        ),
        ("empty", MockEntry::Symlink(Vec::new())),
        ("long", MockEntry::Symlink(vec![b'x'; 4096])),
    ])
}

/// VFS path resolution: every resolver on paths taken from the input
/// (split at NUL), from the root and from a directory.
pub fn vfs_path(data: &[u8]) {
    let mut host = tricky_image();
    let mut vfs = Vfs::new(&mut host, Timespec::default());
    let root = vfs.root();
    let dir = vfs.resolve(&mut host, root, b"/dir", true).ok();
    for path in data.split(|&b| b == 0).take(32) {
        for start in [Some(root), dir].into_iter().flatten() {
            for follow in [true, false] {
                let _ = vfs.resolve(&mut host, start, path, follow);
                let _ = vfs.resolve_for_create(&mut host, start, path, follow);
            }
            let _ = vfs.resolve_parent(&mut host, start, path);
            let _ = vfs.lookup(&mut host, start, path);
        }
    }
}

/// The `#!` line parser. What it returns comes from the first line.
pub fn shebang(data: &[u8]) {
    if let Some((interp, arg)) = fuzzing::shebang(data) {
        let line = data.split(|&b| b == b'\n').next().unwrap_or(data);
        assert!(!interp.is_empty(), "empty interpreter");
        assert!(interp.len() + arg.as_ref().map_or(0, Vec::len) < line.len());
    }
}

/// `rt_sigreturn`: restoring a context from a frame the guest controls,
/// for both architectures, starting from a zero and from a busy context.
pub fn sigreturn(data: &[u8]) {
    for arch in ARCHES {
        let mut busy = Context::zeroed(arch);
        busy.set_pc(0x40_1000);
        busy.set_sp(0x7fff_0000);
        for current in [Context::zeroed(arch), busy] {
            let (_, len) = signal::frame_location(&current);
            let mut frame = data.to_vec();
            frame.resize(len, 0);
            // The kernel always reads exactly the frame's length.
            let _ = signal::read_frame(&current, &frame);
            if arch == Arch::X86_64 {
                let _ = signal::x86_64_fpstate(&frame);
            }
        }
    }
}

/// A minimal static executable: one read-execute segment at 0x40_0000.
pub fn sample_elf(arch: Arch) -> Vec<u8> {
    let machine: u16 = match arch {
        Arch::X86_64 => 62,
        Arch::Aarch64 => 183,
    };
    let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    out.resize(16, 0);
    out.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    out.extend_from_slice(&machine.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0x40_0100u64.to_le_bytes()); // entry
    out.extend_from_slice(&64u64.to_le_bytes()); // phoff
    out.extend_from_slice(&0u64.to_le_bytes()); // shoff
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&56u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // phnum
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    out.extend_from_slice(&5u32.to_le_bytes()); // R | X
    out.extend_from_slice(&0u64.to_le_bytes()); // offset
    out.extend_from_slice(&0x40_0000u64.to_le_bytes()); // vaddr
    out.extend_from_slice(&0x40_0000u64.to_le_bytes()); // paddr
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // filesz
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // memsz
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // align
    out.resize(0x1000, 0xaa);
    out
}

/// Where the syscall target's guest memory lives.
pub const SCRATCH: u64 = 0x7000_0000;
const SCRATCH_LEN: usize = 0x4000;

/// Reads the input as a little program.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    fn u64(&mut self, n: usize) -> u64 {
        (0..n).fold(0, |acc, i| acc | u64::from(self.byte()) << (8 * i))
    }

    fn arg(&mut self) -> u64 {
        match self.byte() % 8 {
            0 => u64::from(self.byte()),
            1 => SCRATCH + self.u64(2) % SCRATCH_LEN as u64,
            2 => self.u64(8),
            3 => u64::from(self.byte() % 8),
            4 => u64::MAX,
            5 => self.u64(4),
            6 => 0x1000_0000 + (self.u64(2) << 12),
            _ => 0,
        }
    }

    fn trap(&mut self, known: &[u64]) -> Trap {
        match self.byte() % 16 {
            0 => Trap::Interrupted,
            // The signals the seccomp platform reports as faults: the
            // platform is trusted, the guest only picks which fault.
            1 => Trap::Fault(Fault {
                signal: [4, 5, 7, 8, 11, 31][usize::from(self.byte()) % 6],
                code: i32::from(self.byte() as i8),
                addr: Some(self.arg()),
            }),
            kind => {
                // Mostly syscalls the kernel implements; sometimes any
                // number at all.
                let pick = self.u64(2);
                let nr = if kind < 12 && !known.is_empty() {
                    known[pick as usize % known.len()]
                } else {
                    pick % 512
                };
                let mut args = [0; 6];
                for a in &mut args {
                    *a = self.arg();
                }
                Trap::Syscall(SyscallTrap { nr, args })
            }
        }
    }
}

/// Arbitrary syscalls with arbitrary arguments and guest memory, through
/// the dispatcher and the mock platform (`hellovm_core::testutil`): the
/// first byte picks the architecture, the next `SCRATCH_LEN` bytes (at
/// most) fill guest memory, and the rest is a script of traps for the
/// first task and the tasks it creates.
pub fn syscalls(data: &[u8]) {
    let mut input = Input(data);
    let arch = ARCHES[usize::from(input.byte() & 1)];
    let mem_len = usize::from(input.byte()) * 64;
    let memory: Vec<u8> = (0..mem_len.min(SCRATCH_LEN))
        .map(|_| input.byte())
        .collect();
    let known: Vec<u64> = (0..512).filter(|&nr| arch.sysno(nr).is_some()).collect();
    let mut scripts = Vec::new();
    for _ in 0..4 {
        let n = usize::from(input.byte() % 64);
        scripts.push((0..n).map(|_| input.trap(&known)).collect::<Vec<_>>());
    }
    if std::env::var_os("HELLOVM_FUZZ_DEBUG").is_some() {
        for (i, script) in scripts.iter().enumerate() {
            for trap in script {
                match trap {
                    Trap::Syscall(s) => eprintln!(
                        "script {i}: {} {:x?}",
                        arch.sysno(s.nr).map_or("?", |n| n.name()),
                        s.args
                    ),
                    other => eprintln!("script {i}: {other:?}"),
                }
            }
        }
    }
    let mut host = MockHost::with_image(&[
        ("bin", MockEntry::Dir),
        ("bin/prog", MockEntry::File(sample_elf(arch))),
        ("bin/script", MockEntry::File(b"#!/bin/prog -x\n".to_vec())),
        ("etc", MockEntry::Dir),
        ("etc/motd", MockEntry::File(b"hello image\n".to_vec())),
        ("etc/link", MockEntry::Symlink(b"motd".to_vec())),
        ("tmp", MockEntry::Dir),
    ]);
    host.stdin.extend(b"console input\n");
    let mut plat = MockPlatform::with_scripts(arch, &host, scripts);
    // The writable layer's limit bounds what file data can cost (one
    // truncate can grow a file to it); the default 2 GiB is beyond the
    // fuzzers' memory bound, so the target uses 64 MiB.
    let mut kernel = Kernel::new(host).with_fs_limit(64 << 20);
    if kernel
        .exec(
            &mut plat,
            b"/bin/prog",
            &[b"prog".to_vec()],
            &[b"PATH=/bin".to_vec()],
        )
        .is_err()
    {
        return;
    }
    let init = *plat.tasks.keys().next().expect("init task");
    let mem = plat.mem(init);
    mem.poke(SCRATCH, &[0; SCRATCH_LEN]);
    mem.poke(SCRATCH, &memory);
    let _ = kernel.issue_fake_ip();
    // Ends with the exit of init, or with an error once a script runs out.
    let _ = kernel.run(&mut plat);
}
