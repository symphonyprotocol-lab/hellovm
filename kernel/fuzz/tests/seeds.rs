//! Writes the seed inputs of every target into `corpus/<target>/seed-*`
//! (run with `cargo test --test seeds -- --ignored`; the result is
//! committed). Seeds are small valid inputs, so that mutation starts from
//! something each parser accepts.

use std::path::Path;

use hellovm_core::{Arch, Sysno};
use hellovm_egress::sniff;
use hellovm_egress::wire::Request;
use hellovm_fuzz::{sample_elf, SCRATCH};

fn dns_query(id: u16, name: &str, qtype: u16, extra: &[u8]) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(!extra.is_empty())]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(extra);
    q
}

/// Encodes one syscall the way `hellovm_fuzz::syscalls` decodes it.
fn call(out: &mut Vec<u8>, arch: Arch, sysno: Sysno, args: &[Arg]) {
    let nr = arch.syscall_nr(sysno).unwrap() as u16;
    out.push(2);
    out.extend_from_slice(&nr.to_le_bytes());
    for i in 0..6 {
        match args.get(i).copied().unwrap_or(Arg::Small(0)) {
            Arg::Small(v) => out.extend_from_slice(&[0, v]),
            Arg::Scratch(off) => {
                out.push(1);
                out.extend_from_slice(&off.to_le_bytes());
            }
            Arg::Raw(v) => {
                out.push(2);
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Arg {
    Small(u8),
    Scratch(u16),
    Raw(u64),
}

fn program(arch: Arch, memory: &[u8], calls: &[(Sysno, &[Arg])]) -> Vec<u8> {
    let mut out = vec![u8::from(arch == Arch::Aarch64)];
    let blocks = memory.len().div_ceil(64);
    out.push(blocks as u8);
    let mut mem = memory.to_vec();
    mem.resize(blocks * 64, 0);
    out.extend_from_slice(&mem);
    out.push(calls.len() as u8);
    for (sysno, args) in calls {
        call(&mut out, arch, *sysno, args);
    }
    // The other scripts are empty.
    out.extend_from_slice(&[0, 0, 0]);
    out
}

#[test]
#[ignore = "writes the committed seed corpus"]
fn write_seed_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let write = |target: &str, name: &str, data: &[u8]| {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("seed-{name}")), data).unwrap();
    };

    for (arch, name) in [(Arch::X86_64, "x86_64"), (Arch::Aarch64, "aarch64")] {
        let elf = sample_elf(arch);
        write("elf", name, &elf);
        let mut pie = elf.clone();
        pie[16] = 3; // ET_DYN
        write("elf", &format!("{name}-pie"), &pie);
        let mut bss = elf.clone();
        // memsz larger than filesz: a .bss.
        bss[64 + 40..64 + 48].copy_from_slice(&0x5000u64.to_le_bytes());
        write("elf", &format!("{name}-bss"), &bss);
    }

    write("dns", "a", &dns_query(0x1234, "pypi.org", 1, &[]));
    write("dns", "aaaa", &dns_query(7, "files.pythonhosted.org", 28, &[]));
    write("dns", "txt", &dns_query(8, "example.com", 16, &[]));
    write("dns", "single-label", &dns_query(9, "localhost", 1, &[]));
    // An EDNS OPT record in the additional section.
    write(
        "dns",
        "edns",
        &dns_query(10, "github.com", 1, &[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]),
    );
    let mut compressed = dns_query(11, "a.example.com", 1, &[]);
    compressed[4..6].copy_from_slice(&[0, 2]);
    compressed.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    write("dns", "two-questions-compressed", &compressed);

    for (i, (id, port, host)) in [(1u64, 443u16, "pypi.org"), (u64::MAX, 80, "a.b.example.com")]
        .into_iter()
        .enumerate()
    {
        let req = Request {
            sandbox_id: id,
            port,
            host: host.into(),
        };
        write("wire", &i.to_string(), &req.encode().unwrap());
    }
    write("wire", "reply", &[0, 0, 0, 0, 0, 0]);

    write("sniff", "tls", &sniff::client_hello_for_test(&["pypi.org"]));
    write("sniff", "tls-two-names", &sniff::client_hello_for_test(&["a.example", "b.example"]));
    write("sniff", "tls-no-sni", &sniff::client_hello_for_test(&[]));
    write("sniff", "http", b"GET /simple/ HTTP/1.1\r\nHost: pypi.org\r\nAccept: */*\r\n\r\n");
    write(
        "sniff",
        "http-absolute",
        b"POST http://example.com:8080/x HTTP/1.0\r\nHost: example.com:8080\r\nContent-Length: 0\r\n\r\n",
    );
    write("sniff", "http-two-hosts", b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n");

    write(
        "policy",
        "file",
        b"# comment\n\nallow pypi.org\nallow files.pythonhosted.org:443\nallow *.github.com:80,443,9418\n",
    );
    write("policy", "bad", b"allow *\nallow *.com\nallow a.example:0\nallow a.example:99999\ndeny x\n");

    write(
        "vfs_path",
        "paths",
        b"/etc/passwd\0/loop\0a/b/c\0up/passwd\0/abs\0dir/deep\0/../../etc\0dir/parent/etc/\0/long/x\0empty\0//bin//sh/\0",
    );

    write("shebang", "sh", b"#!/bin/sh\necho hi\n");
    write("shebang", "env", b"#!  /usr/bin/env   python3 -u  \n");
    write("shebang", "empty", b"#!   \n");
    let mut long = b"#!/".to_vec();
    long.extend(std::iter::repeat_n(b'a', 300));
    write("shebang", "long", &long);

    write("sigreturn", "zero", &[0; 4096]);
    write("sigreturn", "ones", &[0xff; 1200]);

    for (arch, name) in [(Arch::X86_64, "x86_64"), (Arch::Aarch64, "aarch64")] {
        let mut memory = b"/etc/motd\0".to_vec();
        memory.resize(64, 0);
        memory.extend_from_slice(b"hello\n");
        let at_fdcwd = Arg::Raw(-100i64 as u64);
        write(
            "syscalls",
            name,
            &program(
                arch,
                &memory,
                &[
                    (Sysno::Write, &[Arg::Small(1), Arg::Scratch(64), Arg::Small(6)]),
                    (
                        Sysno::Openat,
                        &[at_fdcwd, Arg::Scratch(0), Arg::Small(0), Arg::Small(0)],
                    ),
                    (Sysno::Read, &[Arg::Small(3), Arg::Scratch(128), Arg::Small(64)]),
                    (
                        Sysno::Mmap,
                        &[
                            Arg::Small(0),
                            Arg::Raw(0x10000),
                            Arg::Small(3),
                            Arg::Small(0x22),
                            Arg::Raw(u64::MAX),
                            Arg::Small(0),
                        ],
                    ),
                    (Sysno::Getpid, &[]),
                    (Sysno::ExitGroup, &[Arg::Small(3)]),
                ],
            ),
        );
    }
    let _ = SCRATCH;
}
