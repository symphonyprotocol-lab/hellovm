//! Test hook: a hardened kernel process that runs programs on request.
//!
//! `hellovm --insecure-test-session --root DIR [--trace] [--egress SOCKET]
//! [--splice-to ADDR] [--sandbox-id ID] [--sandbox MODE]` opens the image,
//! hardens itself exactly like a normal `hellovm` run, and then serves
//! requests on stdin, one sandbox (one kernel, one filesystem) for the
//! whole session, writing replies to stdout. The end-to-end tests run
//! their in-process scenarios through it, so that every one of them runs in
//! a kernel process with least privilege. Only with the
//! `insecure-test-hooks` feature.
//!
//! Wire format: every message is a `u32` little-endian length and that
//! many bytes; inside, integers are little-endian and byte strings are
//! length-prefixed (`u32`).

use std::io::{self, Read, Write};

use hellovm_core::host::OutboundFlow;
use hellovm_core::{Arch, ExitStatus, Outcome, SyscallRecord};

/// What the client asks for.
#[derive(Debug)]
pub enum Request {
    /// Runs a program in the session's sandbox.
    Run {
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        stdin: Vec<u8>,
        /// After the program ends, wait this long for outbound bytes.
        drain_ms: u32,
    },
    SetFsLimit(u64),
    IssueFakeIp,
}

/// A program's run.
#[derive(Debug)]
pub struct RunOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The syscalls of this run (with `--trace`).
    pub trace: Vec<SyscallRecord>,
    /// Every outbound flow of the session so far.
    pub flows: Vec<OutboundFlow>,
}

/// What the server answers.
#[derive(Debug)]
pub enum Reply {
    Ran(RunOutput),
    ExecFailed {
        path: String,
        errno: i64,
        reason: String,
    },
    Failed(String),
    Done,
    FakeIp(Option<[u8; 4]>),
}

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    fn list(&mut self, v: &[Vec<u8>]) {
        self.u32(v.len() as u32);
        for item in v {
            self.bytes(item);
        }
    }
}

struct Dec<'a>(&'a [u8]);

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated session message")
}

impl Dec<'_> {
    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.0.len() < n {
            return Err(short());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }
    fn list(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.bytes()).collect()
    }
}

/// Writes one framed message.
pub fn send(out: &mut impl Write, body: &[u8]) -> io::Result<()> {
    out.write_all(&(body.len() as u32).to_le_bytes())?;
    out.write_all(body)?;
    out.flush()
}

/// Reads one framed message; `None` at end of input.
pub fn receive(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let mut body = vec![0; u32::from_le_bytes(len) as usize];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        match self {
            Request::Run {
                argv,
                env,
                stdin,
                drain_ms,
            } => {
                e.u8(0);
                e.list(argv);
                e.list(env);
                e.bytes(stdin);
                e.u32(*drain_ms);
            }
            Request::SetFsLimit(bytes) => {
                e.u8(1);
                e.u64(*bytes);
            }
            Request::IssueFakeIp => e.u8(2),
        }
        e.0
    }

    pub fn decode(body: &[u8]) -> io::Result<Request> {
        let mut d = Dec(body);
        Ok(match d.u8()? {
            0 => Request::Run {
                argv: d.list()?,
                env: d.list()?,
                stdin: d.bytes()?,
                drain_ms: d.u32()?,
            },
            1 => Request::SetFsLimit(d.u64()?),
            2 => Request::IssueFakeIp,
            _ => return Err(short()),
        })
    }
}

fn encode_status(e: &mut Enc, status: ExitStatus) {
    match status {
        ExitStatus::Exited(code) => {
            e.u8(0);
            e.u64(code as i64 as u64);
        }
        ExitStatus::Signaled(sig) => {
            e.u8(1);
            e.u64(sig.into());
        }
    }
}

fn decode_status(d: &mut Dec<'_>) -> io::Result<ExitStatus> {
    Ok(match d.u8()? {
        0 => ExitStatus::Exited(d.u64()? as i64 as i32),
        _ => ExitStatus::Signaled(d.u64()? as u32),
    })
}

fn encode_record(e: &mut Enc, r: &SyscallRecord) {
    e.u32(r.tid);
    e.u8(match r.arch {
        Arch::X86_64 => 0,
        Arch::Aarch64 => 1,
    });
    e.u64(r.nr);
    e.u8(r.sysno.is_some() as u8);
    for arg in r.args {
        e.u64(arg);
    }
    match r.outcome {
        Outcome::Returned(v) => {
            e.u8(0);
            e.u64(v as u64);
        }
        Outcome::Continued => e.u8(1),
        Outcome::Ended => e.u8(2),
    }
}

fn decode_record(d: &mut Dec<'_>) -> io::Result<SyscallRecord> {
    let tid = d.u32()?;
    let arch = if d.u8()? == 0 {
        Arch::X86_64
    } else {
        Arch::Aarch64
    };
    let nr = d.u64()?;
    let known = d.u8()? != 0;
    let mut args = [0; 6];
    for arg in &mut args {
        *arg = d.u64()?;
    }
    let outcome = match d.u8()? {
        0 => Outcome::Returned(d.u64()? as i64),
        1 => Outcome::Continued,
        _ => Outcome::Ended,
    };
    Ok(SyscallRecord {
        tid,
        arch,
        nr,
        sysno: if known { arch.sysno(nr) } else { None },
        args,
        outcome,
    })
}

fn encode_flow(e: &mut Enc, f: &OutboundFlow) {
    e.u64(f.sandbox_id);
    e.u32(f.guest_pid);
    e.bytes(&f.dest_ip);
    e.u32(f.dest_port.into());
    match &f.host {
        Some(host) => {
            e.u8(1);
            e.bytes(host.as_bytes());
        }
        None => e.u8(0),
    }
}

fn decode_flow(d: &mut Dec<'_>) -> io::Result<OutboundFlow> {
    let sandbox_id = d.u64()?;
    let guest_pid = d.u32()?;
    let ip = d.bytes()?;
    let dest_ip = ip.as_slice().try_into().map_err(|_| short())?;
    let dest_port = d.u32()? as u16;
    let host = if d.u8()? != 0 {
        Some(d.string()?)
    } else {
        None
    };
    Ok(OutboundFlow {
        sandbox_id,
        guest_pid,
        dest_ip,
        dest_port,
        host,
    })
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        match self {
            Reply::Ran(out) => {
                e.u8(0);
                encode_status(&mut e, out.status);
                e.bytes(&out.stdout);
                e.bytes(&out.stderr);
                e.u32(out.trace.len() as u32);
                for r in &out.trace {
                    encode_record(&mut e, r);
                }
                e.u32(out.flows.len() as u32);
                for f in &out.flows {
                    encode_flow(&mut e, f);
                }
            }
            Reply::ExecFailed {
                path,
                errno,
                reason,
            } => {
                e.u8(1);
                e.bytes(path.as_bytes());
                e.u64(*errno as u64);
                e.bytes(reason.as_bytes());
            }
            Reply::Failed(msg) => {
                e.u8(2);
                e.bytes(msg.as_bytes());
            }
            Reply::Done => e.u8(3),
            Reply::FakeIp(ip) => {
                e.u8(4);
                match ip {
                    Some(ip) => {
                        e.u8(1);
                        e.bytes(ip);
                    }
                    None => e.u8(0),
                }
            }
        }
        e.0
    }

    pub fn decode(body: &[u8]) -> io::Result<Reply> {
        let mut d = Dec(body);
        Ok(match d.u8()? {
            0 => {
                let status = decode_status(&mut d)?;
                let stdout = d.bytes()?;
                let stderr = d.bytes()?;
                let n = d.u32()? as usize;
                let trace = (0..n)
                    .map(|_| decode_record(&mut d))
                    .collect::<io::Result<_>>()?;
                let n = d.u32()? as usize;
                let flows = (0..n)
                    .map(|_| decode_flow(&mut d))
                    .collect::<io::Result<_>>()?;
                Reply::Ran(RunOutput {
                    status,
                    stdout,
                    stderr,
                    trace,
                    flows,
                })
            }
            1 => Reply::ExecFailed {
                path: d.string()?,
                errno: d.u64()? as i64,
                reason: d.string()?,
            },
            2 => Reply::Failed(d.string()?),
            3 => Reply::Done,
            4 => Reply::FakeIp(if d.u8()? != 0 {
                Some(d.bytes()?.as_slice().try_into().map_err(|_| short())?)
            } else {
                None
            }),
            _ => return Err(short()),
        })
    }
}

/// The server side: serves requests on stdin until it closes.
#[cfg(target_os = "linux")]
pub fn serve(
    mut kernel: hellovm_core::Kernel<hellovm_host::CaptureHost>,
) -> Result<(), Box<dyn std::error::Error>> {
    use hellovm_core::KernelError;
    use hellovm_platform_seccomp::SeccompPlatform;

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    while let Some(body) = receive(&mut input)? {
        let reply = match Request::decode(&body)? {
            Request::SetFsLimit(bytes) => {
                kernel.set_fs_limit(bytes);
                Reply::Done
            }
            Request::IssueFakeIp => Reply::FakeIp(kernel.issue_fake_ip()),
            Request::Run {
                argv,
                env,
                stdin,
                drain_ms,
            } => {
                let host = kernel.host_mut();
                host.stdout.clear();
                host.stderr.clear();
                host.stdin.clear();
                host.stdin.extend(stdin);
                let traced = kernel.trace().len();
                let result = SeccompPlatform::new()
                    .map_err(|err| KernelError::Platform(err.into()))
                    .and_then(|mut app| {
                        kernel.exec(&mut app, &argv[0], &argv, &env)?;
                        kernel.run(&mut app)
                    });
                if drain_ms > 0 {
                    kernel
                        .host_mut()
                        .drain_streams(std::time::Duration::from_millis(drain_ms.into()));
                }
                match result {
                    Ok(status) => {
                        let host = kernel.host();
                        Reply::Ran(RunOutput {
                            status,
                            stdout: host.stdout.clone(),
                            stderr: host.stderr.clone(),
                            trace: kernel.trace()[traced..].to_vec(),
                            flows: host.outbound_flows().to_vec(),
                        })
                    }
                    Err(KernelError::Exec {
                        path,
                        errno,
                        reason,
                    }) => Reply::ExecFailed {
                        path,
                        errno: errno.0,
                        reason,
                    },
                    Err(err) => Reply::Failed(err.to_string()),
                }
            }
        };
        send(&mut output, &reply.encode())?;
    }
    // Like `hellovm` at exit.
    kernel
        .host_mut()
        .drain_streams(std::time::Duration::from_secs(10));
    Ok(())
}
