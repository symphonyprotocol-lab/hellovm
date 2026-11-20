# hellovm

A sandbox for AI models.

## The kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `hellovm-core` | `kernel/core` | Syscall emulation: processes, threads, signals, pipes, ELF loading, memory map, filesystem, terminal, `/proc`, IPv4 sockets; independent of the host OS |
| `hellovm-host` | `kernel/host` | Host interface implementations: console, image directory, random bytes, clocks, outbound streams to the egress proxy |
| `hellovm-platform-seccomp` | `kernel/platform-seccomp` | Linux platform: ptrace and `SECCOMP_RET_TRACE` (see below) |
| `hellovm-platform-hvf` | `kernel/platform-hvf` | macOS platform on Apple silicon: a Hypervisor.framework VM with no guest kernel (see **The HVF platform (macOS)**) |
| `hellovm-sandbox` | `kernel/sandbox` | Least privilege for the kernel process itself (see **Hardening**) |
| `hellovm` | `kernel/hellovm` | Command-line launcher; warm-clone templates and clones, and the control protocol's client (`hellovm::warm`) |
| `hellovm-egress` | `kernel/egress` | The egress proxy (`hellovm-egress` binary): default-deny domain allowlist, one per host |
| `hellovm-egress-wire` | `kernel/egress-wire` | The flow header and hostname rule the kernel and the proxy share |
| `hellovm-test-guest` | `kernel/test-guest` | Small test programs built at build time |
| `hellovm-noded`, `hellovm-api`, `hellovm-control` | `kernel/noded`, `kernel/api`, `kernel/control` | The control plane: the node daemon, the public API, and what they share (see **Control plane**) |

Syscall interception on Linux is ptrace plus `SECCOMP_RET_TRACE`, not
seccomp user notification. Every app thread is a host process. Its filter
returns `SECCOMP_RET_TRACE` for every native-ABI syscall, and one
event-loop thread is the ptrace tracer of those processes: it emulates the
syscall and skips it, so the host kernel does not run it. Changes to an
address space, and new tasks, are injected `mmap`, `munmap`, `mprotect` and
`clone` through a trusted stub page, with arguments the tracer wrote.
`kernel/platform-seccomp/src/spawn.rs` is the full argument, including why
an in-app stub plus user notification was rejected.

What runs today (milestone U5b): x86_64 and aarch64 Linux programs,
static or dynamically linked, with any number of processes and threads.
A busybox shell runs external commands, pipelines, background jobs, traps
and job control; dynamically linked glibc programs and CPython (with
`subprocess`, `threading` and file I/O) run in images assembled from a
Debian system.

- **Processes and threads**: `fork`, `vfork`, `clone` (threads with TLS,
  `CLONE_CHILD_CLEARTID`, robust futex lists), `execve`/`execveat` (static
  and dynamic ELF, `#!` scripts, close-on-exec), `exit`/`exit_group`,
  `wait4`/`waitid`, process groups, sessions, reparenting to init and
  zombies. The sandbox's first process plays init: when it ends, every
  other process is killed.
- **Waiting**: one event loop serves the whole sandbox. A syscall that has
  to wait (pipe I/O, `wait4`, `futex`, sleeps, `poll`/`ppoll`,
  `select`/`pselect6`, `sigsuspend`, console input) parks its thread
  without blocking anything else.
- **Pipes** with blocking, end of file, `PIPE_BUF` atomicity and
  `SIGPIPE`/`EPIPE`.
- **Signals**: handlers on correct signal frames (with FP state) and
  `rt_sigreturn` on both architectures, masks, `sigaltstack`, default
  actions including core-dump status and job-control stops, `kill`,
  `tgkill`, `rt_sigqueueinfo`, `SIGCHLD`, `alarm` and `ITIMER_REAL`,
  interrupted syscalls with `SA_RESTART`, faults the program can handle,
  and asynchronous signals to code that never makes a syscall.
- **Memory**: the kernel loads programs and their interpreter itself and
  owns every address space (`brk`, `mmap`, `munmap`, `mprotect`, `mremap`);
  `MAP_SHARED` anonymous memory stays shared across `fork`.
- **Filesystem**: a read-only image directory under an in-memory writable
  layer. Paths are resolved entirely inside the kernel and cannot leave the
  sandbox root; writes never reach the image directory.
- **`/proc`**: `self`, `<pid>/{exe,cwd,fd,maps,stat,status,statm,cmdline,
  comm,task}`, `meminfo`, `cpuinfo`, `uptime`, `stat`, `loadavg`, `mounts`,
  `net/tcp`, `net/udp`; `ps` works.
- **Warm clones**: a template sandbox loads its environment once (CPython
  with its modules imported, say) and new sandboxes are forked from it in
  a few milliseconds (see **Warm clones**).
- **Control plane**: `hellovm-api` and `hellovm-noded` create sandboxes
  with CPython already loaded over HTTP in 7 to 8 ms, run commands and
  Python in them, read, write and edit their files, and keep tenants
  apart (see **Control plane**).
- **Terminal**: when hellovm runs on a terminal, the sandbox console is a
  terminal too (`/dev/console`, `/dev/tty`): line editing, echo, termios,
  window size, a foreground process group, and Ctrl-C, Ctrl-\ and Ctrl-Z
  for the foreground job.

**Networking.** Sockets are emulated in the kernel. There is no
packet-level TCP/IP stack and no smoltcp: that is a user-approved deviation
(2026-11-13) from design §4.4, which described an in-kernel userspace stack
behind a normal NIC. The guest still sees a POSIX socket API and one
virtual NIC. The only way out is a TCP connect to an address the kernel's
own DNS issued for a name; the kernel sends that flow, named by the
hostname, to the egress proxy, which decides (see **Egress** below).
Everything else stays in the kernel or is refused. `pip install` and
`git clone` over HTTPS work through it.

| Role | Address | What the guest sees |
|---|---|---|
| Guest NIC | `192.0.2.2/24` (TEST-NET-1) | The guest's own address. `SIOCGIFCONF` / `SIOCGIFADDR` report it as `eth0`. |
| Gateway / DNS | `192.0.2.1` port 53 | In-kernel DNS, UDP and TCP (see **Virtual DNS**). Any other port is `ECONNREFUSED`. |
| Rest of the NIC net | other `192.0.2.0/24` | `EHOSTUNREACH` |
| Loopback | `127.0.0.0/8`, and `0.0.0.0` as a wildcard | In-kernel TCP and UDP. Connecting to `0.0.0.0` uses `127.0.0.1`. |
| Fake-IP pool | `198.51.100.0/24` (TEST-NET-2) | The only destinations that may leave the sandbox, and only after virtual DNS bound that address to a name. |

`bind` is allowed on `0.0.0.0`, `127.0.0.0/8`, and `192.0.2.2`. Anything else,
including the gateway, the rest of `192.0.2.0/24`, and any fake IP, is
`EADDRNOTAVAIL`. Ports the guest does not choose come from **32768–60999**
(Linux's default `ip_local_port_range`), unique per local address and
protocol; the range answers `EADDRINUSE` when it is exhausted. `listen`'s
backlog is clamped to **[1, 128]**; a full accept queue refuses the next
in-kernel connect with `ECONNREFUSED`. A connection whose client sends and
closes before the server calls `accept` stays queued: `accept` returns it
and the server reads the data, then EOF.

UDP follows Linux: a full receive queue (64 datagrams or 64 KiB) drops the
datagram and `sendto` still succeeds, an unconnected `sendto` never changes
the socket's bound address, and a connected UDP socket may `connect` again
or dissolve the association with `AF_UNSPEC`. Virtual DNS over TCP accepts
frames up to the 65535-byte maximum and applies backpressure: a client that
never reads its replies gets `EAGAIN` (or blocks) instead of growing memory.

A connect or send that is not loopback, not the guest NIC, not virtual DNS,
and not an issued fake IP fails immediately with `ENETUNREACH`. That
includes metadata (`169.254.169.254`), RFC1918, and any other public
address. Outbound UDP is `ENETUNREACH` except virtual DNS and in-kernel
loopback / the guest NIC. Without `--egress`, a connect to any fake IP is
also `ENETUNREACH`. The guest address is never used as a host dial
address.

`shutdown(SHUT_WR)` half-closes: the peer reads EOF and the caller can
still receive. A bare FIN does not cause `EPIPE`. After a clean full close
the first write is accepted and the next one returns `EPIPE` and raises
`SIGPIPE`, unless the write used `MSG_NOSIGNAL`. A reset (the peer closed
with unread data, or a host write fails) fails the write immediately. A
non-blocking connect that will proceed returns
`EINPROGRESS`; `poll` then reports `POLLOUT` and `SO_ERROR` is the result.
A blocking connect to a loopback address with no listener is `ECONNREFUSED`.
The same connect on a non-blocking socket is `EINPROGRESS` with
`SO_ERROR == ECONNREFUSED`.

*Inbound connections (ingress).* The host side can open a connection to
a TCP port a guest process listens on: a warm clone's requester hands
its kernel process connected stream sockets over the clone's ingress
channel (see **Warm clones**), each with a guest port; the API's ingress
uses it (see **Ingress** in **Control plane**). The connection arrives
at the guest NIC address, `192.0.2.2:PORT`: a listener on `0.0.0.0` or
`192.0.2.2` gets it, one bound to `127.0.0.1` only does not (as on Linux,
where loopback-only means not reachable from outside). Its peer, what
`accept` and `getpeername` report, is the gateway `192.0.2.1` on a port
of the ephemeral range, taken in turn: never a loopback address, which
servers often trust without asking for credentials (Jupyter, debuggers,
admin pages). The real client's address is in the HTTP headers the
ingress adds. The kernel queues the connection on the listener's accept
queue like an in-kernel one, or refuses it (no such listener, a full
backlog, or 256 inbound connections already open in the sandbox), and
the first byte the opener reads is the verdict: `A`, then the guest's
bytes, or `R` and the end of the connection. From then on it is a host
stream like an outbound one: 64 KiB buffered each way in the kernel
process with back-pressure both ways, half-close both ways (the guest's
`shutdown(SHUT_WR)` is a FIN to the opener and the opener's is EOF to the
guest), a guest that closes the listener resets the connections still
queued on it (the opener reads the end without a byte), and the end of
the sandbox ends them all. The kernel process keeps at most 64 handed
over and not yet taken, and 256 with helper threads (two each), apart
from the 512 outbound ones; past either, the next is refused. Nothing a
guest does can open one or learn more than a peer address and the bytes;
the classification of guest connects is unchanged (`192.0.2.1` other
than port 53 is still `ECONNREFUSED`).

Unnamed `AF_UNIX` `socketpair` (`SOCK_STREAM` and `SOCK_DGRAM`) works.
`socket(AF_UNIX)`, path-bound `AF_UNIX`, `AF_INET6`, and netlink
(`AF_NETLINK`) return `EAFNOSUPPORT`. IPv6 and raw sockets are
`EAFNOSUPPORT` / `EPROTONOSUPPORT`.

glibc 2.39 (this host's libc, also what CPython and distro busybox-static
are built with) opens a netlink socket in `getifaddrs` and in
`getaddrinfo`'s `AI_ADDRCONFIG` check. When that socket returns
`EAFNOSUPPORT`, `getifaddrs` fails with errno 97 and does not fall back to
ioctl. `__check_pf` instead assumes both IPv4 and IPv6 are configured, so
`AI_ADDRCONFIG` still returns IPv4 answers. Confirmed in the sandbox:
`getifaddrs` and CPython `socket.if_nameindex()` fail with `EAFNOSUPPORT`,
while `getaddrinfo("127.0.0.1")` and `getaddrinfo("localhost")` return
`127.0.0.1`, and busybox `nc` moves `hi` across `127.0.0.1:5000`. Netlink
is not implemented.

There are at most 4096 sockets. `SO_REUSEADDR` is stored but a second
bind of the same port, including `0.0.0.0` against a specific address, is
still `EADDRINUSE`.

**Virtual DNS.** The kernel replaces `/etc/resolv.conf` (in the writable
layer, creating `/etc` if the image has none) with one naming `192.0.2.1`,
the only resolver the guest can reach. Without `--egress`,
every query is NXDOMAIN. With it:

- An `A` query for a hostname binds the next fake IP from
  `198.51.100.1`–`198.51.100.254` to that name and answers it (TTL 300 s).
  A repeated query gets the same address. The pool stays a /24: at most
  **254 names bound at once per sandbox**. When all are bound, a new name
  takes over the address of the name unused longest (no `A` query for it
  and no connect to its address), provided that is at least 600 s, twice
  the TTL; otherwise the new name is `SERVFAIL` (names already bound still
  answer). A guest that keeps an address past that and connects to it after
  it was rebound opens a flow named for the new owner, which the proxy
  refuses because the SNI or `Host` names the old one; connections already
  open are not affected. A sandbox can only exhaust its own table.
- A hostname is at most 253 bytes of at least two labels, each 1–63
  letters, digits and `-` (not at either end), with a last label that is
  not all digits; matching is case-insensitive. Any other name (one label
  such as `localhost`, `_service` names, numeric names) is NXDOMAIN.
- Any other type for a hostname, `AAAA` included, is an empty NOERROR
  answer. A class other than `IN` is REFUSED, an opcode other than QUERY
  is NOTIMP, and a message without exactly one parsable question is
  FORMERR. Responses are not cached by the kernel and carry no EDNS.
- glibc sends its `A` and `AAAA` queries together with `sendmmsg`, which is
  implemented.

**Egress.** A TCP connect to a fake IP that DNS bound opens a Unix stream
from the kernel process to the egress proxy (`--egress SOCKET`). The
kernel names the flow by the hostname from its own DNS table, never by
anything the guest passes at connect time, and the proxy is never told
the fake IP. The guest's `connect` completes when the proxy has connected
upstream:

| Outcome | Guest sees |
|---|---|
| Allowed and connected | `connect` succeeds (non-blocking: `EINPROGRESS`, then `POLLOUT` and `SO_ERROR == 0`) |
| Name or port not allowed, name does not resolve, every address blocked, upstream refused, per-sandbox or total flow limit, proxy not running | `ECONNREFUSED` |
| Upstream connect timed out, or no verdict from the proxy in 30 s | `ETIMEDOUT` |
| SNI or `Host` does not match, or the first bytes are neither (checked after `connect`) | The connection closes before any byte goes upstream: EOF during the TLS handshake |
| A fake IP no name was bound to, a raw IP, metadata | `ENETUNREACH` (the proxy is never asked) |

The proxy, `hellovm-egress`, is a separate binary in this workspace,
written in Rust rather than the Go of the design sketch so that the
repository keeps one toolchain and one CI gate. One proxy serves every
sandbox on a host:

```sh
hellovm-egress --listen /run/hellovm/egress.sock --policy /etc/hellovm/egress.policy --audit /var/log/hellovm-egress.log &
hellovm --egress /run/hellovm/egress.sock --root / /usr/bin/python3 -m pip install six
```

The socket file's permissions are the proxy's access control: any process
that can connect to it can open flows (under the allowlist). It is
created with the proxy's umask; put it in a directory of its own that
only the sandbox host processes can reach (a kernel process inside its
namespaces keeps that directory, so that it finds the socket again after
the proxy is restarted, and can see whatever else is in it). Run the
proxy as a different user than the sandboxes where you can: the kernel
then keeps a compromised sandbox host process from signalling it. `--sandbox-id` (16 hex digits or a decimal
number; random by default) names the sandbox in every flow and audit
line.

*Policy*: deny by default. A rule is `NAME[:PORT[,PORT...]]` or
`*.SUFFIX[:PORT[,PORT...]]`, given with `--allow RULE` or as `allow RULE`
lines in a `--policy FILE` (`#` comments and blank lines ignored; several
of each may be given). Without ports a rule allows 443 only; plain HTTP
must be asked for (`pypi.org:80,443`). `*.SUFFIX`
matches names below the suffix (`*.github.com` matches `api.github.com`,
not `github.com`); the suffix needs two labels, so `*` and `*.com` are
errors. Then, for an allowed name:

1. The proxy resolves the name itself (the host's resolver, 5 s) and drops
   every address in `0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`,
   `169.254/16` (link-local and `169.254.169.254`), `172.16/12`, `192.0.0/24`,
   `192.0.2/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`,
   `224/4` and `240/4`; of IPv6 it keeps only global unicast `2000::/3`
   minus `2001::/23`, `2001:db8::/32` and `2002::/16` (so no loopback,
   link-local, unique-local, multicast or IPv4-mapped address). A name
   that resolves to a mix is dialed only at addresses that passed, in
   resolver order (at most 4 tried within the 10 s connect budget).
2. The first bytes the guest sends must be a TLS ClientHello whose SNI
   equals the flow's hostname, or an HTTP/1.x request (`GET`, `HEAD`,
   `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`) with exactly one `Host`
   header naming it (a port in it must be the flow's port; an absolute
   request target must agree). Port 443 must be TLS, port 80 must be HTTP,
   other allowed ports may be either. Traffic is never decrypted.
5. A plain-HTTP flow carries **one request**. Its head must be strict
   HTTP/1.x (CRLF line ends only, no control bytes, no folded headers, one
   `Host`, at most one `Content-Length`, no `Transfer-Encoding`). The proxy
   forwards it with `Connection: close` in place of any `Connection`,
   `Keep-Alive` or `Proxy-Connection` header, then exactly the declared
   body, and nothing the guest sends after that, so a second request with
   another `Host` cannot ride on a checked connection. A TLS flow is opaque
   after its ClientHello: what the guest says inside it, including an HTTP
   `Host` that differs from the SNI, is not visible to the proxy.

*Audit*: one line per allowed flow when it ends, and one per refusal
subject to a per-peer rate limit, to stdout or `--audit FILE` (appended):

```text
egress ts=1794881916.960 sandbox=540b8195fe6e630a host=pypi.org port=443 verdict=allow reason=ok addr=151.101.0.223:443 up=681 down=2169 ms=6 peer=4711
egress ts=1794881916.969 sandbox=540b8195fe6e630a host=pypi.org port=443 verdict=deny reason=sni-mismatch sni=evil.example addr=151.101.0.223:443 up=0 down=0 ms=0 peer=4711
```

`ts` is Unix time with milliseconds; `sandbox` 16 hex digits (`-` if the
header was unreadable); `verdict` `allow` or `deny`; `reason` is `ok` or
`idle-timeout` for `allow`, and for `deny` one of `bad-request`, `limit`,
`policy`, `resolve`, `blocked-address`, `upstream-refused`,
`upstream-timeout`, `sni-mismatch`, `host-mismatch`, `not-tls`, `not-http`,
`unparsable`, `sniff-timeout`. `sni=` or `http_host=` follows `reason` on a
mismatch. `addr` is the upstream address dialed (for `blocked-address`,
the first blocked one; else `-`); `up` and `down` are bytes delivered
upstream and to the guest. `peer` is the process id of the connecting
kernel process as the host kernel reports it (`SO_PEERCRED`); unlike
`sandbox`, the connecting process cannot choose it. Each peer may log 50
refusals in a burst and 5 per second after that; the next line written for
that peer ends with `suppressed=N`, the number of its refusals left out.

*Bytes per kernel process*: the proxy counts the bytes it relays per
connecting process, named by its process id and start time (`SO_PEERCRED`
and field 22 of `/proc/PID/stat`, which together name one process for the
life of the host), as they move, not when a flow ends. With `--stats PATH
--stats-token-file FILE` it answers `noded`'s questions about them on a
second Unix socket (`kernel/egress/src/usage.rs`): the token on a line,
then `PID:START` keys (at most 4096), and it answers `PID:START SENT
RECEIVED` per key and `.`. Put that socket in a directory of its own: a
kernel process sees the flow socket's directory. The sandbox id of the
flow header is not used (the connecting process chooses it); the token
keeps a kernel process that can still reach the socket (a host without
mount namespaces) from reading other sandboxes' traffic, and
connections that never present it from keeping `noded` out: of the 8
questions answered at once, the one that waited longest without the
token makes room for a new one. At most 16384 processes are counted at
once (when the table is full, those that ended are dropped, the longest
idle first; a process that still runs keeps its counter, and a flow of a
new process past that is relayed but not counted).

*Limits*:

| What | Limit |
|---|---|
| Flow header | 16 + at most 253 bytes, within 5 s |
| Concurrent flows | 1024 in total (`--max-flows`); 64 per sandbox id and 64 per connecting process, whatever ids it claims (`--max-flows-per-sandbox`) |
| Name resolution | 5 s, at most 16 addresses kept, at most 256 resolutions in flight (more fail at once) |
| Upstream connect | 10 s across all addresses (`--connect-timeout`), at most 4 addresses tried |
| SNI / `Host` sniffing | 16 KiB within 10 s |
| Relay | 16 KiB buffered per direction in the proxy; idle (no byte either way) 300 s closes the flow (`--idle-timeout`) |
| Kernel side | 30 s for the proxy's verdict; at most 512 outbound streams open or draining (past that, `connect` is `EAGAIN`); 64 KiB buffered each way per stream; a closed stream keeps flushing while the peer makes progress, and gives up after 45 s without |
| At exit | hellovm closes the remaining streams and waits at most 10 s for queued bytes to reach the proxy |

Bytes waiting on an outbound stream are visible to `poll`, `select` and
`FIONREAD` before any `recv`.

*Not supported*: plain-HTTP keep-alive, pipelining, chunked request bodies
and upgrades (WebSocket), since a plain-HTTP flow is one request; a
ClientHello using Encrypted Client Hello is checked
by its outer SNI, so it is refused unless that names the flow's host;
protocols where the server speaks first (SSH, SMTP), `git://`, and HTTP
`CONNECT` are refused; outbound UDP (including QUIC/HTTP/3) and IPv6
sockets stay unavailable; there is no per-sandbox policy (one allowlist
per proxy) and no rate or byte limit in the proxy (the API has a byte
budget per tenant and period: see **Quotas and metering**).

*Test hooks*: the cargo feature `insecure-test-hooks` (off by default)
adds `hellovm --splice-to 127.0.0.1:PORT`, which sends every outbound flow
to a loopback TCP address with no policy, and `hellovm-egress
--insecure-test-hosts FILE`, a static name table (`NAME ADDR[:PORT]...`
per line) whose loopback entries are the only exception to the blocked
ranges. Default builds reject both flags as unknown; `run-e2e.sh` checks
that. The tests enable the feature through dev-dependencies.

Loopback in one command (the trace lists `socket`, `connect`, `sendto`, and
`recvfrom`; libc has no separate `send`/`recv` syscall):

```sh
mkdir -p /tmp/image/bin && cp /bin/busybox /tmp/image/bin/busybox && ln -sfn busybox /tmp/image/bin/sh && ln -sfn busybox /tmp/image/bin/nc && ln -sfn busybox /tmp/image/bin/echo && ln -sfn busybox /tmp/image/bin/cat && ln -sfn busybox /tmp/image/bin/usleep && timeout 15 cargo run -p hellovm -- --root /tmp/image --no-tty --trace /bin/sh -c ': > /got; { n=0; while [ ! -s /got ] && [ "$n" -lt 300 ]; do usleep 10000; n=$((n + 1)); done; } | nc -l -p 5000 > /got & i=0; while [ "$i" -lt 50 ]; do echo hello-loopback | nc -w 2 127.0.0.1 5000 && break; i=$((i+1)); done; wait; cat /got'
```

`eventfd2` works (counter and semaphore modes; libcurl 8.18 wakes its
resolver thread with one, so `git clone` needs it on recent distros). On
aarch64 the guest does not see BTI or MTE in `AT_HWCAP2`: both need
`PROT_BTI` / `PROT_MTE` mappings, which the kernel does not provide, and a
dynamic loader that sees BTI refuses to load marked libraries without it.

Not yet: `epoll` (neither `pip install` nor `git clone` calls it),
`timerfd`, `inotify`, `clone3` (glibc falls back to `clone`), `fexecve`,
POSIX timers, `ITIMER_VIRTUAL`/`ITIMER_PROF`, priority-inheritance futexes,
writable shared *file* mappings (they are private copies), and permission
checks (the guest is root). Unimplemented syscalls fail with `ENOSYS` and
are logged.

Both the aarch64 and the x86_64 builds have been tested end to end
(busybox shell, CPython, pthreads, signals, dynamic linking and the
terminal). The x86_64 run is `kernel/dev/run-e2e.sh` on a native x86_64
Linux host.

## The HVF platform (macOS)

On macOS on Apple silicon, `hellovm` runs aarch64 Linux programs in a
virtual machine of Hypervisor.framework (`kernel/platform-hvf`). Since
milestone P1b it runs processes: `fork` with copy-on-write, `execve`,
`vfork`, shared memory and dynamically linked programs, so a busybox
shell runs pipelines and CPython runs scripts that start subprocesses.
Since P1d the threads of a program run in parallel on several vCPUs
(`--vcpus`, by default one per host CPU, at most 8). The same kernel
core handles every system call; only the platform differs.

**How it works.** The program runs at EL0 of a VM that has no guest kernel.
At EL1 there is only a shim: a 4 KiB page whose 16 exception vectors are
each one `hvc` instruction. A `svc` from the program, or any fault or
undefined instruction, enters a vector, which leaves the VM at once:
`hv_vcpu_run` returns in the kernel process, which reads the program's
registers (untouched by the exception) and `ESR_EL1`, `FAR_EL1`,
`ELR_EL1`, and hands the core a syscall or a fault. To resume, the kernel
process sets the program counter and `CPSR` (EL0) itself; nothing runs at
EL1 on the way back, except one of the shim's two flush routines after
page tables changed: the whole TLB (`tlbi vmalle1is`, `ic ialluis`,
`eret`), or one page of one address space (`tlbi vae1is` with the ASID
and page number the kernel process put in `x0`, whose value it saved in
`TPIDR_EL1` for the routine to restore). hellovm writes the program's
page tables itself; the VM never does.

**vCPUs and scheduling.** vCPU 0 belongs to the kernel's event-loop
thread and runs inside the platform's `wait`, as the only vCPU did
before P1d; each other vCPU has a host thread of its own (`hellovm-vcpuN`),
made with the platform, before the kernel process hardens itself. Tasks
(every thread of every process) are register contexts that the vCPUs
take from one scheduler, behind one lock: the runnable task that has
spent the least time in a vCPU runs next, so a process that mostly
waits for a pipe or a child runs as soon as it can. A task runs for one
5 ms slice at most (on a single vCPU: while another task is runnable):
the guest's virtual timer ends the slice, so a program that never makes
a system call cannot keep the others from running; a task keeps its
slice across the system calls it makes in between. A task that becomes
runnable starts at most one slice behind the others' least run time, so
time spent waiting gives no claim on a vCPU later. A task's registers
stay in the vCPU that last ran it until that vCPU runs another task, and
until then only that vCPU runs it (a system call round trip then moves
no registers); the core asking for the registers of such a task (signal
delivery, `clone`) has the vCPU save them first. A task made runnable
that vCPU 0 would run next is left to it (a system call round trip on
vCPU 0 moves nothing between host threads); any other wakes the thread
of the vCPU its registers are in, or one idle vCPU thread, and busy ones
pick up work when their slice ends. What vCPU 0 would run next goes to
another vCPU once it has waited 50 µs while the event loop handles other
vCPUs' traps. An idle vCPU thread, and the event loop with nothing to
run, poll for 50 µs before they sleep. A trap on another
vCPU goes into a queue that `wait` returns from, and makes vCPU 0 leave
the VM if it is running a task (`hv_vcpus_exit`), so that the event loop
sees it at once; when `wait` returns, a runnable task whose registers are
in vCPU 0 is saved, so that another vCPU can run it while the core does
something else. No lock is held while a vCPU runs. `kill` (`exit_group`,
`execve` of a sibling) and `interrupt` (a signal for a thread that makes
no system call) of a task running on another vCPU kick that vCPU out of
the VM, and `kill` waits until it has let go of the task. A `wait`
timeout is the same timer as the slice; a waker or `--timeout` calls
`hv_vcpus_exit` from another thread (for `--timeout`, on every vCPU).
Address spaces that found no ASID (see below) run on vCPU 0 only.

**The VM layout.**

| Guest-physical | Size | Stage 2 | What |
|---|---|---|---|
| `0x1_0000` | 16 KiB | read, execute | The shim page (vectors at 0, flush routines at `0x800` and `0x900`) |
| `0x4000_0000` | 64 MiB | read | Page tables, written only by the kernel process |
| `0x1_0000_0000` | 2 GiB | read, write, execute | The program's memory |

Each region is host memory of the kernel process, reserved up front and
committed on first touch. Stage 1 uses a 4 KiB granule and 48-bit
addresses. `TTBR0_EL1` is the program's address space (`0x1_0000` to
`1 << 48`); `TTBR1_EL1` maps only the shim, at `0xffff_0000_0000_0000`,
for EL1 (read and execute, `UXN`). The system registers: `SCTLR_EL1` turns
on the MMU and caches and lets EL0 use `DC ZVA`, `CTR_EL0` and cache
maintenance by address (as Linux does), with stack alignment checks and
without alignment faults, `WXN` or pointer authentication; `TCR_EL1`
selects the granule, inner-shareable write-back walks, and top-byte-ignore
for EL0 addresses; `MAIR_EL1` attribute 0 is normal write-back memory
(the host maps the same memory the same way, so both see the same bytes);
`CPACR_EL1` lets FP and SIMD run untrapped; `CNTKCTL_EL1` lets EL0 read
the virtual counter and nothing else of the timers; `VBAR_EL1` is the
shim. The program starts with `PSTATE` EL0t; the only bits of `PSTATE` a
program (or a signal frame) can set, and the ones kept across every exit,
are the condition flags and `DIT` (data-independent timing, which
`AT_HWCAP` reports: a library that sets it finds it still set after a
system call).

The page size the program sees (`AT_PAGESZ`) is 4 KiB, as aarch64 Linux
programs expect; the host's 16 KiB pages only matter to `hv_vm_map`,
which maps the three regions once. Memory is allocated a 4 KiB page at a
time when the program first touches it (a translation fault the platform
resolves without telling the core), from the 2 GiB pool; a sandbox that
uses it up gets `SIGKILL`, the process that needed the page, as the OOM
killer would kill it on Linux; the others go on. Freed pages go back to
the pool, not to the host.

Address space costs page tables only where it is used. A mapped range
with no memory yet that covers the whole span of a table entry above the
last level (2 MiB, 1 GiB, 512 GiB) is one descriptor there, a
reservation, with no table below it: the 64 GiB `PROT_NONE` reservation
of a language runtime takes a table or two at its edges, and is split
into smaller ones only where a part of it is touched, unmapped or given
another protection. A table whose last entry goes is freed, so the 64 MiB
of tables (16384 of them, each for 2 MiB of pages) bound what is mapped
page by page at one time (32 GiB), not what was ever mapped. A cache
maintenance instruction (`ic ivau`, `dc cvau`: `__clear_cache`) on a page
with no memory yet is taken as a read, as on Linux, whatever its syndrome
says of writing.

**Processes and copy-on-write.** The core makes every process change
through the platform: `fork` is `clone_task` without shared memory,
`execve` loads the new program into a new address space (`spawn`) and
then ends the old task, and `vfork` and threads are `clone_task` with
the same address space. `clone_task` copies the parent's table tree at
once: a new table for each of the parent's tables, the same descriptors,
and each frame shared between the two. Each frame of program memory has
a reference count, kept in the kernel process (not in guest memory): the
number of page descriptors, in all address spaces, that point at it.
Private writable pages become read only in both trees: their software
`PROT_*` bits still allow writing, and that difference is what makes a
page copy-on-write. The first write faults; if the frame is still
shared, the page gets a copy, otherwise (the other process exited or
wrote its own copy) the page is just made writable again. The core's own
writes into a process's memory (`Platform::write`: `read` results,
signal frames, file-backed mappings) copy the same way, and its reads
follow the same descriptors, so they see the process's own copy.
Reservations and pages that never had memory are copied as descriptors,
with no memory. Pages of `MAP_SHARED` mappings carry a software bit
(`DBM`, bit 51, which the hardware ignores while `TCR_EL1.HD` is clear)
and are never copied: both processes keep the same frame. A shared page
(or a whole reservation) with no memory yet takes none at the `fork`
either, as on Linux: the `fork` marks it, in both address spaces, as
taking its memory from a shared object made for that `fork`, a table on
the host side from page address to frame. Whoever touches the page first
gets a frame and enters it there, the others find it there, and the
object keeps what was written for those who have not touched the page
yet, until the last descriptor that names it is gone. So a `fork` with
gigabytes of untouched shared memory costs no memory and no table. `execve` frees the old address space with its last
task: each frame's count goes down, a frame with no users left goes back
to the pool, and every table goes back too.

Copying the tables at once, rather than sharing lower-level tables
copy-on-write, keeps one owner per table and one rule for every page;
it costs the parent's tables and a pass over their descriptors. A `fork`
of a process with 256 MiB touched (65,536 pages, 128 last-level tables)
takes about 0.3 ms through the core (below), which did not justify the
extra state of shared tables. The tables are counted before anything is
copied: when the table pool cannot hold the copy, `fork` fails with
`EAGAIN` and nothing changed. Memory is counted in frames, not mappings:
a `fork` takes only tables, and each copy on a write takes one frame from
the pool. A fork bomb therefore ends with `EAGAIN` once the table pool
(or the core's limit of 1024 processes) is used up; the kernel process
allocates nothing beyond its pools and the core's bounded per-process
state.

Threads work too, because they need nothing beyond what `vfork` needs
(the platform cannot tell the two apart): they share an address space,
and run in parallel when there is more than one vCPU.

**What keeps processes apart.** The stage-1 tables hellovm writes are the
boundary between processes, so these are the invariants (each checked by
the tests below):

* A frame is reachable only through the descriptors its reference count
  counts, and goes back to the pool only when that count reaches zero.
  Frames and tables are zeroed before they are handed out again.
* A private page is writable in hardware only if its frame has one user.
  Counts only grow in `fork`, which first makes every such page read only
  in both trees.
* Each address space has its own ASID, so switching between processes
  flushes nothing. The M3's vCPU reports 8-bit ASIDs (16-bit ones are
  used where a vCPU has them), so 255 address spaces have their own. A TLB
  entry can only be stale if the tables changed after it was cached, and
  every such change is recorded: a descriptor that goes, changes or
  points at another frame, or a table that is freed. Before the next
  instruction of any program runs on any vCPU, that vCPU invalidates the
  whole TLB, or only that page's entries of that ASID when one page
  changed (a copy-on-write page that was written; making a page writable
  again needs it too, or the old read-only entry would fault once more).
  After `fork`, which made the parent's writable pages read only, the
  whole TLB goes. An ASID is reused only after its address space is gone,
  which freed its tables and so flushed the TLB. When no ASID is free,
  new address spaces share ASID 0, run on vCPU 0 only, and switching
  between two of them flushes the whole TLB (correct, and as slow as the
  prototype was).
* With several vCPUs, other threads of a process may be running while
  its tables change: a page fault on one vCPU (memory on first touch, a
  copy-on-write copy), or the core's `mmap`, `munmap`, `mprotect`,
  `write` into the process, `fork` or the end of the address space. The
  tables and the frame and table pools are behind one lock, and a
  change that left TLB entries stale adds the invalidation to every
  vCPU's pending set and then makes every vCPU that is running that
  address space leave the VM (`hv_vcpus_exit`, repeated until its run
  count has moved), still holding the lock. A vCPU's run count is odd
  from just before it takes its pending invalidations until
  `hv_vcpu_run` returns; the pending ones are added before the counts are
  read (both sequentially consistent), so every vCPU either takes them
  before its next run or is seen running and waited for. The shim's
  `tlbi ...is` reaches every CPU of the host, so the first vCPU to run
  the space again cleans the TLB of every CPU, wherever the others run.
  Because no other change gets the lock in between, no frame a stale
  entry still reaches is handed out again before every vCPU that could
  use it has left the VM and will invalidate first; and once `munmap`,
  `mprotect` or `fork` returns, no thread of the process writes through
  an entry the change made stale. Descriptors are written with single
  64-bit stores, since a vCPU's table walk may read them at any time, and
  app memory is copied in and out with raw copies (another vCPU may be
  writing it), never through references.

**What the program can and cannot touch.** The isolation boundary is the
stage-2 mapping, which Hypervisor.framework enforces: the VM's whole
guest-physical address space is the three regions above, so nothing in it
can address any other memory of the kernel process or the host. Inside
the VM, the stage-1 tables hellovm writes decide what EL0 reaches: the
pages the core mapped, with their protections (`PROT_NONE` pages are not
valid; executable pages are never executable at EL1, `PXN`), and nothing
else. The shim page is mapped for EL1 only, and the page tables are not
mapped at stage 1 at all; stage 2 makes both read-only, so not even code at
EL1 could change them. EL0 reaches EL1 only by taking an exception, which
lands in a vector and leaves the VM. System registers are out of reach
from EL0: the tests check that `mrs`/`msr` of EL1 registers, `tlbi`,
`hvc`, `eret`, the timer registers and `msr daifclr` are illegal
instructions (`SIGILL`), that loads, stores and jumps to the shim and the
vectors are `SIGSEGV`, that the guest-physical addresses of the page
tables and of program memory are not mapped, and that a context with every
`PSTATE` bit set still runs at EL0. Not tested directly (true by
construction): that EL1 cannot write the shim or the tables.

What the kernel process trusts from the VM: nothing but the exit record
and the vCPU's registers, which it decodes without panicking on any value
(`exit.rs` is checked against every exception class with random
syndromes); page tables are read only from the region the VM cannot
write.

**Building, signing, running.** Hypervisor.framework requires the
`com.apple.security.hypervisor` entitlement; an ad-hoc signature is
enough for local builds (no developer account), and nothing else is
needed (no root, no System Settings change). Without it, creating the VM
fails with `HV_DENIED`. `kernel/.cargo/config.toml` makes
`kernel/platform-hvf/sign-and-run.sh` the runner of every binary `cargo
run` and `cargo test` start on `aarch64-apple-darwin`: it signs the
binary with `kernel/platform-hvf/hellovm.entitlements`, then runs it. A
binary run directly needs the same signature:

```sh
cd kernel
cargo build -p hellovm
codesign --force --sign - --entitlements platform-hvf/hellovm.entitlements target/debug/hellovm
mkdir -p /tmp/image && cp target/debug/build/hellovm-test-guest-*/out/hello /tmp/image/
target/debug/hellovm --sandbox require --root /tmp/image /hello
```

On the Mac, `hellovm --root DIR PROGRAM [ARGS...]` works with `--trace`,
`--timeout`, `--env`, `--fs-limit`, `--tty`/`--no-tty`, `--vcpus N` (1
to 64, at most what Hypervisor.framework allows; by default one per host
CPU, at most 8) and `--sandbox
require|best-effort|off` (the kernel process confines itself with a
Seatbelt profile, see **Hardening**). `--egress`, `--template` and
`--clone` are refused. `hellovm-noded` and the API stay Linux-only.

The test guests for the Mac (`kernel/test-guest/asm`, and
`kernel/test-guest/asm/hvf` for the HVF tests) are built by
`test-guest/build.rs` with the system's clang
(`--target=aarch64-linux-gnu`) and the Rust toolchain's own `rust-lld` as
the linker: no Linux toolchain is needed. On a Mac without those (a Rust
that is not rustup's may lack `rust-lld`) the workspace still builds:
the build prints a warning, and the tests that need the guests skip (or
fail under `HELLOVM_REQUIRE_E2E=1`). Everything that needs a Linux libc
comes from the dev container: `kernel/platform-hvf/build-guests.sh`
builds the C guests of `kernel/test-guest/c` there (`smoke`, `pie`,
`signals`, `threads`, `forks`, `smp` statically, with the flags of
`test-guest/build.rs`, and `dynamic` linked dynamically) with the
container's gcc and glibc, and assembles one image directory,
`kernel/target/hvf-guests/root`: the guests under `/guests`, the
container's busybox (Debian `busybox-static`) with applet links in
`/bin`, the container's CPython (Debian `python3`) with its standard
library and extension modules, and every shared library and the program
interpreter they need (from `ldd`), at the paths they have in the
container. Its `MANIFEST` records the image id and the versions (for the
measurements below: Debian 12.15, gcc 12.2.0, glibc 2.36, busybox 1.35.0,
Python 3.11.2). No binary is checked in; the tests find the image through
`HELLOVM_HVF_GUESTS`:

```sh
docker build -t hellovm-dev kernel/dev
kernel/platform-hvf/build-guests.sh
cd kernel
HELLOVM_HVF_GUESTS=$PWD/target/hvf-guests/root cargo test -p hellovm-platform-hvf
HELLOVM_HVF_GUESTS=$PWD/target/hvf-guests/root cargo test -p hellovm --test hvf_cli
target/debug/hellovm --sandbox require --root target/hvf-guests/root /bin/sh -c 'seq 100 | grep 7 | wc -l'
```

The tests (`kernel/platform-hvf/tests/hvf.rs` and `guests.rs`, the unit
tests in `kernel/platform-hvf/src`, and `kernel/hellovm/tests/hvf_cli.rs`)
cover the hello world end to end (through the core and through the
command line), `SIGSEGV` delivery, fault events from unmapped and
protected memory (and that `mprotect` and `munmap` reach a program whose
TLB already held the page), the EL1 and shim probes above, registers
(every general, SIMD and FP register, `SP`, `TPIDR_EL0`, the flags)
surviving exits for two tasks sharing the vCPU, odd register values at
exits (system calls with all-ones arguments and number, odd `PC`, `SP` and
`PSTATE`, and 300 random contexts), wait timeouts, wakers, interrupts and
the killer. For processes: `kernel/test-guest/c/forks.c` (fork and wait,
copy-on-write of `.data`, `.bss`, heap and stack in both directions,
shared memory written by both sides, fork then `execve`, `vfork`,
`posix_spawn`, a fork of a fork, 64 MiB copied, five children at once, a
pipe between two children, and a child that never makes a system call
next to a parent that must still run), `signals.c` (every check, its
children and `vfork` included), `threads.c` (every check), `pie.c`, `dynamic.c` (its interpreter maps libc and libm), the C
`smoke.c`, a busybox shell running pipelines of up to five processes, a
loop, command substitution and a background job, CPython importing
standard modules, computing, writing and reading files and running a
shell and itself with `subprocess`, a fork bomb in a sandbox with 2 MiB
of tables, which ends with `EAGAIN`, and a child that runs out of memory
on a copy-on-write fault, which gets `SIGKILL` while its parent goes on.
Threads in parallel, on 1, 2 and 4 vCPUs (`kernel/test-guest/c/smp.c`,
`threads_in_parallel`): a `fork` while three threads write, whose child's
copy must not change (the writers on other vCPUs held writable entries),
20 times; `mprotect` to read only and `munmap` of a page another thread
writes without a system call, after which no write may land and the
writer must fault, and for `munmap` none of its writes may reach 256
pages mapped next (where its frame may be reused), 20 rounds each; four
threads writing every page of 64 copy-on-write pages at once after a
`fork`, ten times, with no write lost, the child's copy unchanged, and a
flag written after data on another copy-on-write page never seen before
the data; futex ping-pong between two threads (20,000 rounds); `SIGUSR1`
to a thread that spins without a system call (20 rounds); 300 system
calls next to 16 spinning threads; `exit_group` from the main thread and
from another thread while eight threads spin; `execve` while four spin;
CPython's `threading` (eight threads, a lock, a queue); and a busybox
pipeline. `cpu_work_scales_with_vcpus` checks that four threads of CPU
work give the right sum and take less than 0.6 of the time on four vCPUs
than on one. The whole platform suite runs with any vCPU count
(`HELLOVM_HVF_VCPUS`). After every program the test checks that every frame and table (but the
shim's) went back to its pool. On the platform alone: after `fork`, the
parent stores through the writable entry its TLB held before the fork
and the child does not see it, and 400 switches between the two read
each its own page without a flush; a frame freed with one process and
handed to another (with the same ASID, at the same address) is not
reached through what the TLB held for the first; the core's write into a
copy-on-write page whose read-only entry the program's TLB holds is what
the program reads next; tasks sharing memory see each other's stores;
two spinning tasks share the vCPU fairly while a third, making system
calls, gets more than 1000 round trips in 500 ms; when ASIDs run out
each process still reads its own page; and a slice that ends while the
vCPU is in an exception vector (on its way out with a page fault that
needs nothing from the core) still ends the run (it did not before P1d:
the run went on with no timer, and a program that kept touching new
pages and then spun kept the vCPU until something else stopped it). `mmu.rs` has unit tests for
reference counts, forks of forks, shared mappings, writes by the core,
frames freed exactly once and pools exhausted in the middle of a `fork`
(nothing is left half-copied), and a randomized test against a model: 3
fixed seeds, 4000 steps each, of map, unmap, protect, write, read, touch
(an access by the program), fork and destroy over up to six address
spaces, checked after every step against a map of each address space's
pages (protection, sharing, contents), against the invariants above
(every reference count, every table's count of used entries, no frame or
table leaked or freed twice, no writable shared private page) and
against a simulated TLB that keeps what each touch cached until the
platform says it may be stale; a second run with tiny pools makes 42%
of the operations fail and checks the same invariants and that nothing
leaks. Breaking the code on purpose in any of eight ways (no read-only
parent after `fork`, no invalidation after a copy, an early free, a
frame not zeroed, shared pages without memory not tied to one shared
object at `fork`, that object not keeping its frames, the core's writes
not copying, `mprotect` making a shared frame writable) makes it fail. A test binary that cannot use the hypervisor
(not signed) prints `SKIPPING` and passes, unless
`HELLOVM_REQUIRE_E2E=1`. Hypervisor.framework allows one VM per process,
so the tests take turns. The same `forks.c` runs on the seccomp platform
in `kernel/hellovm/tests/forks.rs`, and `smp.c` in
`kernel/hellovm/tests/smp.rs`, and print the same lines.

**Performance.** One system call round trip (the program's `svc` to the
platform's next trap, with the trap reported to and answered by the
caller) costs **834 ns** on an M3 Max (macOS 27.2), measured as the best
of 5 runs of 1,000,000 `svc` in a loop answered straight through the
`Platform` trait (`cargo test --release -p hellovm-platform-hvf --test
hvf -- --ignored --nocapture syscall_round_trip`). Through the kernel
core (`getpid` in a loop, `kernel/test-guest/asm/hvf/getpid_loop.S`), it
is **904 ns** per call, VM creation and loading included. Of the 834 ns,
736 ns is the VM exit and entry alone (`hv_vcpu_run` with nothing read);
reading a general register costs about 5 ns and a system register 11 ns
(`exit_cost_breakdown` in `platform-hvf/src/app.rs`). Measured the same way as on Linux, through the command line
(release build, `--sandbox off`, wall clock of a run of 1,000,000 calls
minus a run of 0, best of 5), HVF takes 906 ns per `getpid`, and starting
`hellovm` (VM creation included) about 5 ms. For comparison only, in a
different environment: the seccomp platform in the dev container under
Docker Desktop on the same Mac (whose Linux runs in a VM, so every ptrace
stop goes through that VM's kernel) took about 23 µs per `getpid` with
the same loop and method. That is not what seccomp costs on a native Linux
host, which this Mac cannot measure.

Processes, on the same Mac (release builds; the in-guest times are the
guest's own `CLOCK_MONOTONIC`, `kernel/test-guest/c/forks.c bench 1000
256`, and the Python benchmark is `PY_BENCH` in
`kernel/platform-hvf/tests/guests.rs`: recursion, a dictionary of
200,000 entries, sorting and formatting, best of 3; command-line times are
wall clock, best of 10; each line is the typical one of three runs):

| | HVF | seccomp, Docker Desktop (different environment) |
|---|---|---|
| `fork` + `exit` + `wait` | 36 µs | 870 µs |
| `fork` with 256 MiB touched | 0.3 ms | 8.5 ms |
| ... and the child writing all of it | 180 ms (2.8 µs a page) | 290 to 480 ms |
| pipe round trip between two processes | 8 µs | 120 to 270 µs |
| `hellovm ... /usr/bin/python3 -c pass` | 22 ms | 125 ms |
| `hellovm ... /bin/sh -c 'seq 1 20000 \| grep 7 \| sort -rn \| uniq \| head -3'` | 19 ms | 59 ms |
| Python benchmark | 43 ms | 151 ms |

The same Python benchmark run natively in the container, without
hellovm, takes 140 ms and `python3 -c pass` 18 ms there: the container's
own CPU speed accounts for most of the Python difference, so the second
column says little about seccomp on a native Linux host. The pipe round
trip (each side touching 64 pages between messages) takes 14 µs on HVF
when every switch between processes flushes the whole TLB, as the
prototype did; with ASIDs it takes 8 µs. A pipeline or a `fork` loop
showed no difference.

Several vCPUs (P1d), same Mac and method, measured on 2026-11-20 while
the host had a load average of 4 to 6 from other work, so the `main`
build (before P1d) was measured again alongside. CPU work scales with the
vCPUs: `smp scale 8 50000000` (eight threads, each 50 million rounds of
xorshift, best of 3) takes 606 ms on 1 vCPU, 311 ms on 2, 167 ms on 4
and 84 ms on 8 (7.2 times faster), and four threads take 309 ms on 1
vCPU and 83 ms on 4; the sums are the same. What crosses the core costs
about the same or a little more (medians of five runs; the in-guest
times are the guest's own clock):

| | `main` (1 vCPU) | 1 vCPU | 2 vCPUs | 8 vCPUs |
|---|---|---|---|---|
| `getpid` through the command line | 946 ns | 969 ns | | 991 ns |
| system call round trip, platform only (`syscall_round_trip`) | | 884 ns | | 906 ns |
| `fork` + `exit` + `wait` | 31 µs | 31 µs | 38 µs | 40 µs |
| `fork` with 256 MiB touched | 0.45 ms | 0.49 ms | 0.49 ms | 0.54 ms |
| ... and the child writing all of it | 139 ms | 143 ms | 142 ms | 150 ms |
| pipe round trip between two processes | 7.9 µs | 7.4 µs | 5.7 µs | 7.4 µs |
| futex ping-pong between two threads | | 3.7 µs | 4.2 µs | 3.6 µs |
| `getppid` from one thread (its main thread in `pthread_join`) | | 0.98 µs | 1.4 µs | 1.3 µs |
| `getppid` from two threads at once, per call | | 1.85 µs | 1.57 µs | 1.66 µs |
| `getppid` from four threads at once, per call | | 1.88 µs | 2.27 µs | 1.88 µs |
| `hellovm ... /usr/bin/python3 -c pass` (best of 10) | 19.2 ms | 17.6 ms | | 18.1 ms |
| `hellovm ... /bin/sh -c 'seq 1 20000 \| grep 7 \| sort -rn \| uniq \| head -3'` | 16.0 ms | 15.6 ms | | 12.7 ms |

On one vCPU nothing measurably changed (a few tens of nanoseconds per
system call for the locks and atomics). With more vCPUs a task that runs
on a vCPU other than vCPU 0 pays a hop between host threads for each
system call (about 0.4 µs, thanks to the idle threads polling for 50 µs
before they sleep: without that, a pipe round trip took 18 µs), and
system calls of several threads do not get faster in total, since one
event loop handles them all. A `fork` costs about 7 µs more, as parent
and child end up on different vCPUs.

**What works, and what does not yet.** Static and dynamically linked
aarch64 Linux programs, any number of processes: `fork`, `execve`,
`vfork`, `posix_spawn`, `wait`, pipes between processes, signals between
them, `MAP_SHARED` anonymous memory, file-backed private mappings of
shared objects (the interpreter's relocations write copy-on-write pages
and `mprotect` RELRO), busybox shells and CPython with `subprocess`,
threads in parallel on up to 64 vCPUs. Not yet: x86_64 programs
(Rosetta is not used); memory returned to the host (the pools only grow
to their high-water mark); warm clones; `AT_HWCAP2` (zero) and emulated
`mrs` of ID registers (`HWCAP_CPUID` is not reported, so programs do not
try). A process that writes a copy-on-write page when the pool is used
up gets `SIGKILL` rather than an error.

What several vCPUs do not do yet, or not well. The core is one event
loop on one host thread: system calls of threads on different vCPUs are
handled one at a time, so system-call-heavy threads do not scale (see
**Performance**), and a thread that runs on a vCPU other than vCPU 0
pays a hop between host threads per system call. Tasks have no affinity
beyond keeping their registers in the last vCPU, and there is no load
balancing beyond "an idle vCPU takes the task that has run least"; a
task's slice is 5 ms on every vCPU. Address spaces beyond the ASIDs the
vCPU has (255 on the M3) share ASID 0 and run on vCPU 0 only, so their
threads do not run in parallel. A copy-on-write copy replaces a valid
descriptor with another (a different frame) while other vCPUs may hold
the old one, without the architecture's break-before-make sequence: the
other vCPUs are made to leave the VM and invalidate right after, and
the old frame stays valid memory of the other process until then, but
a CPU could in principle report a TLB conflict abort in that window
(none was seen; it would reach the program as `SIGSEGV`). App memory
that another vCPU writes while the core reads it (a `write` system call
from a buffer another thread is filling) is copied as it is at that
moment, as on Linux. `--vcpus` does not limit how many host CPUs the VM
uses at once beyond its own count; macOS schedules the vCPU threads.

## Hardening

The kernel process (`hellovm`) parses guest-controlled bytes all the time
(ELF files, syscall arguments, signal frames, DNS queries), so it is
built on the assumption that one of those parsers has a bug. Before it
reads anything from the guest, once the image directory is open and the
egress socket path is known, it takes away everything it does not need
(`kernel/sandbox`). The app processes are forked from it and inherit
every layer except the seccomp allowlist's effect (see below), on top of
their own filter.

| Layer | What it does | Skipped when | Required by `--sandbox require` |
|---|---|---|---|
| Inherited fds | Every fd above 2 is closed first thing in `main` | never (`--sandbox off` only) | yes |
| Namespaces | `unshare` of a user, mount, network and IPC namespace. The root becomes an empty read-only tmpfs that holds two bind mounts: the image directory, and the directory of the egress socket (the directory, so that a restarted proxy's new socket is found). The old root is detached and the image is served from an fd opened inside the new root, so no other host path can be named, not even with `..` from a directory fd. The network namespace has only a loopback that is down; every capability is dropped afterwards. Uid and gid are mapped to themselves. The whole sequence is first rehearsed in a forked child, because a process cannot leave a user namespace again: if the rehearsal fails, the layer is skipped and the process is untouched. A failure after a successful rehearsal stops hellovm in every mode (exit 125): it never runs guest code half-confined. | The rehearsal fails: `unshare(CLONE_NEWUSER)` is refused (Docker's default seccomp profile, `kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0`), or it succeeds without capabilities and a later step is denied (AppArmor's `restrict_unprivileged_userns`, the default on Ubuntu 24.04 and later) | no |
| Resource limits | `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 4096, `RLIMIT_MEMLOCK` 0, `RLIMIT_MSGQUEUE` 0 (soft and hard limits are lowered only, never raised) | `setrlimit` fails | yes |
| `no_new_privs` | `PR_SET_NO_NEW_PRIVS` | never in practice | yes |
| Landlock | Reading files and directories beneath the image directory is the only filesystem right; TCP bind and connect are denied (ABI 4+); signals and abstract Unix sockets are scoped to the kernel process's own domain, i.e. its app processes (ABI 6+). Landlock also stops ptrace and `process_vm_*` of processes outside the domain. | no Landlock in the host kernel (before 5.13, or not in `lsm=`), or the syscalls are refused | no, but one of Landlock and the namespaces is |
| Not dumpable | `PR_SET_DUMPABLE` 0: no core dump, no ptrace attach and no `/proc/<pid>/mem` of the kernel process by other processes of the same user | never in practice | yes |
| Seccomp | An allowlist of the syscalls the kernel process makes, with argument checks; anything else kills the process | `seccomp` refused or the code ranges cannot be read from `/proc/self/maps` at start-up | yes |

`--sandbox best-effort` (the default) uses every layer the host allows
and logs each skipped one with the reason: at info level when
`--sandbox require` would still start, as a warning (shown by default)
when it would not. In particular, on a host with neither namespaces nor
Landlock the kernel process is not confined to the image at all, and
every run says so.
`--sandbox require` refuses to start (exit 125, listing the layers) when
a required one is unavailable; `--sandbox off` uses none.
`HELLOVM_LOG=debug` lists the active layers:

```text
hellovm: debug: sandbox: inherited fds closed: active (0 closed)
hellovm: debug: sandbox: user/mount/network/IPC namespaces: active (user, mount, network, IPC)
hellovm: debug: sandbox: resource limits: active (core 0, nofile 4096)
hellovm: debug: sandbox: no_new_privs: active ()
hellovm: debug: sandbox: Landlock: active (ABI 8: image read-only, no TCP, signals and abstract sockets scoped)
hellovm: debug: sandbox: not dumpable: active ()
hellovm: debug: sandbox: seccomp allowlist: active (62 syscalls, 305 instructions, 5 code ranges)
```

*The seccomp allowlist.* App processes are forked from the kernel
process, so its filter is stacked under theirs, and seccomp's most
severe verdict wins. A filter that killed every syscall the kernel never
makes would kill the guest's emulated `open`. So the filter looks at the
instruction pointer: a syscall made from the kernel process's own
executable mappings (its binary, libc, the dynamic linker, the vDSO,
recorded once at start-up) is checked against the allowlist and kills
the process if it is not on it; a syscall from anywhere else gets
`SECCOMP_RET_TRACE`, which is what the app's own filter returns anyway
(and in the kernel process, which nobody traces, `ENOSYS`). The platform
reserves those code ranges in every app address space, so guest code
never runs there. The allowlist (62 calls on aarch64, 4 of them for warm
clones, see **Warm clones**) was measured with
`HELLOVM_SECCOMP_LEARN=FILE` (a test-hooks build), which records every
syscall the kernel process makes and lets it continue, over the whole
test suite (the control plane's included: templates running the sandbox
agent, and their clones), on Debian bookworm (glibc 2.36) and Ubuntu 26.04 (glibc
2.43, which adds `fstat` and the termios2 `ioctl`s);
`kernel/sandbox/learn-summary.py FILE` condenses the log. The x86_64
list is the same calls by name, and CI measures it: the `test-x86_64`
job runs the end-to-end tests once with `HELLOVM_SECCOMP_LEARN=FILE`
(`cargo test -p hellovm -p hellovm-api --no-fail-fast`) and then
checks the recording against the allowlist
(`HELLOVM_SECCOMP_LEARNED=FILE cargo test -p hellovm-sandbox measured`),
which names any call the list lacks. Do the same after changing what the
kernel process does.
Arguments are checked where they decide what a call reaches: `socket`
only `AF_UNIX` streams, `clone` only thread and fork flags (no
namespaces; `clone3` fails with `ENOSYS` so glibc falls back), `ptrace`
only the requests of a tracer of its own children (no `PTRACE_ATTACH`
or `PTRACE_SEIZE`), `openat` read-only without `O_CREAT`, `mmap` and
`mprotect` never executable, `execveat` only of the stub memfd, `kill`,
`tgkill` and `pidfd_send_signal` only the signals the platform sends,
`prctl`, `ioctl` and `fcntl` only the operations used.

*What it does not stop.* The kernel process drives its app processes
with ptrace and makes them execute `mmap`, `munmap`, `mprotect` and
`clone` for it; code that takes over the kernel process completely can
make an app process execute any syscall, or fork a child of its own and
trace it. Against that, the layers the app processes inherit
(namespaces, Landlock, resource limits) are the fence; seccomp shrinks
the host kernel's surface, turns a kernel bug that makes a stray syscall
into a dead process, and keeps an exploit from simply calling `socket`
or `open`. Without the mount namespace a pathname Unix socket other than
the egress socket can still be reached with `connect`: neither Landlock
(before a Linux release that covers Unix `connect`) nor seccomp can check
a socket path. Without the network namespace and Landlock's TCP rights,
the seccomp `socket` rule is the network fence. `RLIMIT_NPROC` is per
user across the host, so it is not set (the core caps a sandbox at 1024
threads and 2048 tasks). There is no `RLIMIT_AS`: the app processes
would inherit it and programs that reserve address space they never
touch would fail, while it bounds virtual size, not memory in use; run
each sandbox in a memory cgroup for that.

Seccomp cannot tell one process id from another, and the kernel process
needs `ptrace`, `process_vm_readv`/`writev` and `kill` for its own app
processes. What stops a compromised kernel process from using them on
other processes of its user: the user namespace and Landlock each refuse
ptrace-level access (attach, reading or writing memory) to a process
outside, so that holds wherever one of the two is active. Signals are
only scoped by Landlock ABI 6 (Linux 6.12); on an older host a
compromised kernel process can `SIGKILL` other processes of its user.
Give each tenant its own uid, and the egress proxy another one.

A new app process is emptied (stack, vDSO and whatever else the host
mapped) with two `munmap`s by address range, since the confined kernel
process cannot read `/proc/<pid>/maps`. Before it confines itself,
hellovm starts one app process, clears it the same way and reads its
maps: if anything of the host is left, it refuses to start.

*Image directory.* The image is opened once and every lookup walks from
that directory fd with `openat(O_NOFOLLOW | O_DIRECTORY)` per component,
then `fstatat`/`readlinkat`/`openat` of the last one without following
it. No symlink in the image, pointing inside or outside it, is ever
followed on the host (the core resolves symlinks itself), FIFOs and
device nodes are never opened, and a host-side change to the directory
cannot make a lookup leave it. Recently used directories and files stay
open (32 and 16), so a lookup does not walk from the root each time.

*The egress proxy.* `hellovm-egress` makes itself non-dumpable with no
core dumps at start-up, so that no other process of its user (a
compromised sandbox host process, say) can attach to it or read or write
its memory, where the allowlist lives. It is not hardened further yet.
It parses the flow header and the first bytes of every flow (SNI,
`Host`), so it would benefit from more of the same treatment:
`no_new_privs` and an fd limit are trivial; Landlock would allow reading the
policy file, writing the audit file and creating the listening socket
(or take it already bound); a seccomp allowlist is possible but must
cover the host resolver (`getaddrinfo` reads `/etc/resolv.conf`,
`/etc/hosts`, `/etc/nsswitch.conf` and may load NSS modules, so those
files must stay readable and its socket calls allowed); it needs the host
network, so no network namespace.

*Testing.* Every end-to-end test runs in a hardened kernel process (the
warm-clone templates too, and their clones): the
in-process scenarios go through `hellovm --insecure-test-session` (a
test hook that applies the same hardening, then runs programs on
request), the rest run the binary. `kernel/hellovm/tests/hardening.rs`
makes the hardened kernel process itself (`--insecure-fence-test`, a test
hook) open `/etc/passwd`, connect a TCP socket, connect to a host
abstract Unix socket, open `/etc/passwd` with `..` from every directory
fd it holds, read its parent's memory, call `setns` and `PTRACE_ATTACH`
its parent, and asserts each is refused or kills it; with `--sandbox
off` each succeeds, as a control. The filesystem attempts are repeated
with Landlock left out (a test hook), to show that the namespaces hold
on their own where the host has them. In the dev container and in an Ubuntu 26.04 container
(Docker's default seccomp profile) the namespaces are skipped and every
other layer is active; with `--security-opt seccomp=unconfined` all
seven are.

**On macOS (the HVF platform).** The threat model is the same: assume a
guest has taken over the kernel process (arbitrary code in it). The VM
stays the first boundary (see **The HVF platform**); the kernel process
is the second. Before the kernel reads any guest input, and once the
image directory, the VM and its vCPUs, `/dev/urandom` and the terminal's
settings and window size are set up, `hellovm` applies the macOS layers
of `kernel/sandbox` (`macos.rs`, `seatbelt.rs`), while the only other
threads are the HVF platform's vCPU threads (made with the platform,
idle, and reading no environment):

| Layer | What it does | Required by `--sandbox require` |
|---|---|---|
| Inherited fds | Every fd above 2 is closed first thing in `main` (listed with `proc_pidinfo(PROC_PIDLISTFDS)`, then checked again: macOS has no `close_range`) | yes |
| Resource limits | `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 256, `RLIMIT_NPROC` 1 (only ever lowered). macOS checks `RLIMIT_NPROC` against the user's whole process count, so `fork` and `posix_spawn` fail whatever the profile says; the kernel process never makes a process (app processes are register contexts in its one VM) | yes |
| Environment cleared | Every environment variable is removed: nothing reads one after start-up, and an operator's environment (tokens, keys) is not for a compromised kernel process to read. The program's environment comes from `--env` only | yes |
| No debugger | `ptrace(PT_DENY_ATTACH)`: no debugger can attach afterwards. Skipped (and so `require` refuses) when a debugger already traces the process, which `PT_DENY_ATTACH` would kill | yes |
| Seatbelt profile | The process enters a Seatbelt sandbox itself (`sandbox_init_with_parameters`) with the profile below, then checks from inside that `/` cannot be opened (`EPERM`) | yes |

`--sandbox require` refuses to start (exit 125, listing the layers) when
any layer is unavailable or the check fails; `best-effort` (the default)
runs anyway and warns, saying the kernel process is not confined when the
Seatbelt layer is the one missing; `off` applies none. A hardened run
prints nothing; `HELLOVM_LOG=debug` lists the layers:

```text
hellovm: debug: sandbox: inherited fds closed: active (0 closed)
hellovm: debug: sandbox: resource limits: active (core 0, nofile 256, nproc 1)
hellovm: debug: sandbox: environment cleared: active (31 removed)
hellovm: debug: sandbox: no debugger (PT_DENY_ATTACH): active ()
hellovm: debug: sandbox: Seatbelt profile: active (7 rules)
```

*Why Seatbelt, self-applied.* macOS offers no seccomp, Landlock or
namespaces. What it has: the Seatbelt sandbox (the kernel's `Sandbox`
policy module, configured with a profile in SBPL), entered either at
launch through App Sandbox entitlements, by `sandbox-exec`, or by the
process itself with `sandbox_init_with_parameters`; resource limits;
`PT_DENY_ATTACH`; the hardened runtime (a code-signing flag that keeps
other processes from injecting libraries or getting the task port, i.e.
protects the process from others, not others from it); and running as
another user, which needs root. App Sandbox was rejected: it applies at
`exec`, before the kernel process has opened anything, so the profile
would have to allow opening any `--root` the user names (App Sandbox
expects that through user-selected-file extensions), it brings Apple's
large application profile (many Mach services, `application.sb`), and
it filters no system calls. `sandbox-exec` has the same timing problem.
Self-applying after start-up lets the profile be tighter than anything
applied at launch: it never needs `dyld`, frameworks, the executable, the
hypervisor set-up or the terminal's device node, because all of that is
done when it is entered. Browsers confine their renderer processes the
same way (Chromium's and Firefox's macOS sandboxes are built on
`sandbox_init_with_parameters` with their own SBPL profiles).

*The profile* (`kernel/sandbox/src/seatbelt.rs`), measured, not guessed:
the real workloads (the C guests, the busybox pipeline, CPython with
`subprocess`, the fork bomb, `--timeout`, `--trace`, `--fs-limit`, stdin
from a pipe, stdout to a file, a terminal through script(1)) ran under a
learning variant (`HELLOVM_SEATBELT_LEARN=1`, a test-hooks build) that
denies without killing, and the denials were read from the unified log
until there were none and every run matched its `--sandbox off` output.
For several vCPUs (P1d) the same was done with 1, 2 and 8 of them over
`smp.c` (every check, CPU work, `exit_group`, `execve`), `forks.c`,
`threads.c`, `signals.c`, a busybox pipeline and CPython threads; then
the same runs enforced. The first multi-vCPU run under the old profile
was killed: libpthread traps (`EXC_BREAKPOINT`) when `psynch_mutexwait`
fails, the first time the platform's mutex is contended.
`(version 3)` and `(deny default)`, then:

| Rule | Why |
|---|---|
| `file-read-data`, `file-read-metadata`, `file-test-existence` beneath the image (`(subpath (param "IMAGE"))`, its canonical path) | the image: lookups walk it with `openat`/`fstatat`/`readlinkat` from the directory fd; a missing name is a test for existence |
| `system-info` `vfs.disk-space` | listing an image directory: `opendir` checks the file system's flags (`fstatfs`) |
| `system-fcntl` `F_GETFD`, `F_SETFD` | close-on-exec of the image fds |
| `file-ioctl` `TIOCSETA` | restoring the host terminal's settings at exit (they and the window size were read before) |
| `process-info-setcontrol` of itself | naming its own threads (`hellovm-stdin`) |
| `syscall-unix`: `write`, `ioctl`; `read`, `pread`, `fstat64`, `fstatat64`, `fstatfs64`, `getdirentries64`, `readlinkat`; `mmap`, `munmap`, `mprotect`, `madvise`; `gettimeofday`; `bsdthread_create`, `bsdthread_terminate`, `thread_selfid`, `__disable_threadsignal`, `sigaltstack`; `psynch_cvbroad`, `psynch_cvsignal`, `psynch_cvwait`, `ulock_wait`, `ulock_wake`; `psynch_mutexwait`, `psynch_mutexdrop`, `psynch_cvclrprepost`, `ulock_wait2` | stdio and the terminal; reading the image; memory; the wall clock (libc reads it from the commpage and makes the call only while the kernel updates it there: rare, and before P1d it killed the process when it happened); the stdin reader and `--timeout` watchdog threads; locks between them; the vCPU threads: the platform's mutex contended (libpthread traps when these fail), a timed condition variable wait that times out as another thread signals, a lock wait with a 64-bit timeout |
| `syscall-mach`: `_kernelrpc_mach_vm_map_trap`, `_kernelrpc_mach_vm_deallocate_trap`, `_kernelrpc_mach_vm_protect_trap`, `mach_vm_reclaim_update_kernel_accounting_trap`; `_kernelrpc_mach_port_mod_refs_trap`, `_kernelrpc_mach_port_destruct_trap` | memory (`malloc`); a vCPU thread that ends when the platform goes (libpthread lets go of the thread's own port rights; neither trap can get a right the process does not hold) |
| any other `syscall-unix`, `syscall-mach` or `syscall-mig`: `(deny ... (with send-signal SIGKILL))` | a system call or Mach trap outside the lists kills the process, as seccomp does on Linux |

Everything else is denied: every other file (read, write, create,
metadata), every network operation, process creation and `exec`,
signals to other processes, `process-info` of other processes, every
Mach service lookup and IOKit user client, every sysctl, POSIX IPC. No
Mach message trap is allowed at all (`mach_msg2_trap` is not on the
list), so the process cannot talk to any Mach service or call any MIG
kernel routine, `task_for_pid` and `task_name_for_pid` (Mach traps) kill
it, and so does `sysctl`. To keep it that way the `--timeout` watchdog
does not use `thread::sleep`: `nanosleep` asks the kernel's clock service
through Mach IPC, a timed condition variable wait does not. The self-check
at start-up (`/` cannot be opened) is silenced in the log with a rule of
its own, `(with no-report)`; because of that rule it shows that a
profile was entered, not that the profile denies by default. A unit test
pins the operations the profile allows.

*Does a guest-chosen path reach the host?* Only as plain names relative to
the image's directory fd (see *Image directory* above: every component
checked, `O_NOFOLLOW` everywhere, symlinks never followed on the host).
File access cannot be narrowed to descriptors opened before the profile
is entered, because Seatbelt checks the path each `openat` resolves to,
not the directory fd it starts from, and the guest can name any file of
its image; so the profile allows reading beneath the image's canonical
path and nothing else. A hard link inside the image to a file outside it
would be readable (the operator builds the image; the confined process
cannot make links, nor write anywhere).

*Hypervisor.framework inside the sandbox* needs nothing from the profile:
measured with a test program, `hv_vm_create`, `hv_vcpu_create`,
`hv_vm_map` and `hv_vcpu_run` work under `(deny default)` before or after
the sandbox is entered (on Apple silicon they are hypervisor traps
checked against the entitlement, not IOKit or Mach services, and
Seatbelt's system call lists do not cover them). `hellovm` makes the VM
and its vCPUs (and their threads) first anyway, so that the profile never
has to allow what creating them might need on another macOS release; the
confined process makes no thread and no vCPU of its own afterwards
(`hv_vcpus_exit`, which other threads call to stop a vCPU, needs nothing
either). The consequence: the
confined process keeps the whole hypervisor interface. It can destroy its
VM and create another, map any memory of its own into it and run code at
EL1 there. It gains no memory it did not have (a VM maps only memory of
the process that made it, and only one VM per process exists at a time),
but the hypervisor's own code (in the macOS kernel and below it) is
attack surface a compromised kernel process can reach, as KVM is on
Linux. There is no way to give up the entitlement at run time.

*What a compromised kernel process can still do:* read every file beneath
the image directory; read stdin and write stdout and stderr (whatever the
operator connected: a terminal, a pipe, a file) and change the terminal's
settings (`TIOCSETA`); use its own memory, threads and the hypervisor as
above; spend CPU and memory (macOS has no memory cgroup, and the platform's
fixed pools bound the guest, not code running in the kernel process);
make the system calls the kernel exempts from Seatbelt's
system call lists. That exempt set is not documented; measured, it
includes at least `open`, `openat`, `close`, `fcntl`, `kill`,
`proc_info` and `exit`, which still go through their own checks (a file
open outside the image fails with `EPERM`, `kill` of another process with
`EPERM`, `proc_info` of another process with `EPERM`). What it cannot do,
tested from inside the confined process (below): read or list a file or
directory outside the image (an absolute path, a `..` path, `openat` with
`..` from every fd it holds, the user's home, `/etc/passwd`), create or
write any file (outside the image or in it), connect a TCP or Unix socket
or send a UDP datagram, resolve a name, signal another process; and
inherited fds and the environment are gone. Enforced by the profile but
*not* tested from inside: process creation (`fork`, `posix_spawn`,
`exec`), task ports (`task_for_pid`, `task_name_for_pid`), `ptrace` and
`proc_pidinfo` of other processes, sysctls, IOKit, Mach service lookups,
and what the hypervisor allows (a second VM while one exists fails with
`HV_BUSY`; destroying the VM and making another works). These attempts
were in the first version of the test and each behaved as described
when run by hand one at a time, but two runs of the whole test file
(attempts in parallel) on macOS 27.2 (Darwin 27.2.0, M3 Max) coincided
with kernel panics of the host ("Kernel data abort" in `kernel_task`, no
kernel extension in the backtrace), and it is not known which attempt,
or which combination, caused them. They were removed from the test hook;
the tests that remain run one at a time whatever `--test-threads` says
(a lock in the test process and a lock file between the two test
binaries) and log each step to `kernel/target/hvf-test-steps.log`
(synced) before it starts.

*Not covered:* bugs in the macOS kernel reachable through the allowed and
exempt system calls, and in the hypervisor; denial of service (CPU,
memory, filling the disk through a stdout the operator redirected to a
file; `RLIMIT_FSIZE` is not set because it would cut off legitimate
output, and the profile lets the process write no other file); a hard
link the operator put in the image; side channels.

*Deprecated and undocumented interfaces relied on.* The SDK's
`sandbox.h` declares only `sandbox_init` with a named profile and marks
it deprecated ("No longer supported", macOS 10.8). `sandbox_init_with_parameters`
(an SBPL string with parameters) is exported by `libsystem_sandbox` but
declared in no header; `hellovm` looks it up with `dlsym`, so a macOS
without it still runs `hellovm`, and `--sandbox require` refuses to start
there. SBPL itself is undocumented; `(version 3)`, `syscall-unix`,
`syscall-mach`, `syscall-mig`, `machtrap-number`, `(with send-signal
SIGKILL)` and `(with no-report)` are what Apple's own profiles use
(`/System/Library/Sandbox/Profiles`, e.g. `com.apple.mtlcompilerservice.sb`).
If Apple removes the function or rejects the profile, the Seatbelt layer
fails and `require` refuses (tested by a hook that hands Seatbelt a
profile it rejects). If Apple kept accepting the profile but stopped
enforcing part of it, nothing at start-up would notice: the self-check
(`/` is not readable) only fails when no profile is in force at all.
Only the tests would show it. Rerun them after a macOS update.

*Violations* are reported by the kernel to the unified log, one line per
operation and target. Do not rely on it: a denial reported recently is
counted, not reported again, and after the tests' burst of denials the
log showed none from `hellovm` (any operation, any path, a renamed or
re-signed copy too) for the rest of the more than 15 minutes it was
watched, while other processes' denials still appeared. Why is not
known (a limit on reports per program would explain it; this was not
confirmed), and the test of the log is not run by default for that
reason. So the log shows what was denied, not every denial, and its
absence proves nothing:

```sh
log show --last 10m --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "hellovm("'
```

```text
kernel: (Sandbox) Sandbox: hellovm(4242) deny(1) file-test-existence /etc/passwd
```

A killed kernel process (a system call outside the lists) shows up there
as `deny(1) syscall-unix NUMBER` and exits with `SIGKILL` (status 137).

*Compared with Linux, line by line:*

| Linux | macOS |
|---|---|
| Inherited fds: `close_range` | the same, by listing fds with `proc_pidinfo` |
| Namespaces (user, mount, network, IPC; empty root) | none on macOS; the Seatbelt profile's file and network rules take their place |
| Resource limits: core 0, nofile 4096, memlock 0, msgqueue 0 | core 0, nofile 256, nproc 1 (no processes to make, see above); no memlock or message queue limits (the profile denies `mlock` and POSIX IPC) |
| `no_new_privs` | nothing to do: the process cannot `exec` at all |
| Landlock: read the image only, no TCP, scoped signals | Seatbelt: read the image only, no network at all (TCP, UDP, Unix, name resolution), no signals to others, no Mach services |
| Not dumpable | `RLIMIT_CORE` 0 and `PT_DENY_ATTACH` (no core dump, no debugger attaching); other processes of the user cannot get its task port without a debugger's rights in any case |
| Seccomp allowlist with argument checks, measured | Seatbelt's `syscall-unix` and `syscall-mach` lists, measured, by number only (no argument checks), with an undocumented set of calls exempt; the operation rules (files, `fcntl`, `ioctl`, `process-info`) check some arguments |
| Seccomp's instruction-pointer trick for stacked app filters | not needed: app processes are not host processes |
| Environment kept | cleared |
| Egress socket allowed | no egress on macOS yet |

*Cost.* The hardening runs once at start-up: a few `setrlimit`s, the
environment, `PT_DENY_ATTACH`, compiling and entering the profile, and
the self-check. A guest's system call is a VM exit handled inside the
kernel process and never becomes a host system call, so the hot path
does not pass through Seatbelt; the host system calls the kernel process
makes on behalf of a guest (reading the image, writing stdout) are each
checked against the profile's lists. Measured on the M3 Max (release
build, through the command line, wall clock, best of 10, three runs):
starting `hellovm` and running the hello world takes 5.8 ms with
`--sandbox off` and 11.2 to 11.8 ms with `--sandbox require`; a `getpid`
round trip (`getpid_loop`, 1,000,000 calls minus 0, best of 5) takes 977
to 980 ns either way.

## Warm clones

A template sandbox starts once and runs until its environment is loaded;
new sandboxes are then made from it in a few milliseconds, each with the
template's memory, processes and files as they were at that moment, and
each isolated from the template and from the others.

```sh
hellovm --template /run/hellovm/py.sock --root / /usr/bin/python3 -c '
import json, decimal, sqlite3          # the environment
code = open("/dev/hellovm-clone", "rb").read()
exec(code)' &
hellovm --clone /run/hellovm/py.sock --ready
echo '{"a": 1}' | hellovm --clone /run/hellovm/py.sock \
  --input 'import sys; print(json.load(sys.stdin)["a"] + 1)'
```

**The clone point.** Every sandbox has a character device
`/dev/hellovm-clone`. In an ordinary run a read returns end of file at
once, so a template program also runs on its own. In a template, the
first read is where the template freezes: the thread blocks in that read,
and it returns only in the clones, each with the bytes its requester sent
as input (`--input`, at most 64 KiB), then end of file. The guest chooses
the moment, so it can get ready for it: flush its output, close its
outbound connections, reseed what must differ (below). Writes to the
device fail with `EINVAL`.

**Using it.** `hellovm --template SOCKET [options] --root DIR PROGRAM...`
runs `PROGRAM` as a template, hardened exactly like an ordinary run, with
no console input (stdin is at end of file) and its output on hellovm's
stdout and stderr. Once frozen it serves clones on the Unix socket
`SOCKET`, which it creates (it must not exist) before it confines
itself, until it is killed; its clones die with it. `--tty` and
`--timeout` are refused for a template (a clone has no terminal; a
clone's timeout is its requester's). `hellovm --clone SOCKET [--sandbox-id
ID] [--input DATA] [--timeout SECONDS]` asks for a clone whose console is
its own stdin, stdout and stderr, and exits with the clone's status (125 if
none was made, 124 after `--timeout`, which kills the clone); `--ready`
waits until the template is frozen. A node daemon speaks the protocol
directly: one connection per request, the stdio fds passed with
`SCM_RIGHTS` (and, with a flag, a fourth: the clone's ingress channel, a
Unix stream socket whose other end the requester keeps; on it each
message is a guest port, two bytes, with one connected socket attached,
which the clone's kernel process takes as an inbound connection, see
**Networking**), answers `R` (ready), `S` (the clone runs: its sandbox id and
kernel process id), `X` (exit status) or `E` (error text). Closing the
connection kills the clone. `kernel/hellovm/src/warm.rs` documents the
bytes and has a client (`hellovm::warm::WarmClone`). Who can connect to
the socket can make clones: put it in a directory only the node daemon
can reach. The socket file outlives the template (the confined template
cannot remove it); `hellovm-noded` removes it.

**How a clone is made.** The template's kernel process (K) runs the
guest as usual until a thread reads the clone point. From then on K
resumes no thread: running threads are interrupted, a thread that traps
in the meantime keeps its syscall for later (the clone runs it, as if the
thread had not reached it yet; a signal that comes first restarts it),
and when nothing runs K checks that the sandbox can be cloned (below).
The platform then copies the memory of every address space into a
memfd made before K confined itself: only the pages that are not all
zero, appended one after the other as extents (runs of such pages; fewer
than 128 KiB of zero pages between two runs are stored with them, so a
fragmented heap does not become thousands of extents). An area the guest
cannot read is made readable first; anonymous memory that was never
writable (an address-space reservation, guard pages) is known to be zero
and not read at all. It keeps every thread's registers, FP/SIMD state
including the extended state (x86_64 XSAVE: AVX, AVX-512; aarch64 SVE),
thread pointer and (aarch64) pointer-authentication keys, kills the
app processes and seals the file (`F_SEAL_WRITE | F_SEAL_GROW |
F_SEAL_SHRINK | F_SEAL_SEAL`): nobody, not even a compromised clone
holding the fd, can change it again. Everything else, the kernel state
(processes, pids, fd tables, pipes and their bytes, sockets, the writable
layer, DNS bindings, signal state), stays as it is in K's memory. K then
only serves its socket. For each request it forks itself; the child K' is
the clone's kernel process and gets a copy-on-write copy of all that
state from the host. K' enters a Landlock domain of its own (see
**Hardening** below), makes the requester's fds its console, takes its
sandbox id, and rebuilds the app processes: per address space a fresh app
process (the normal bootstrap) in which K' injects, per area, an anonymous
mapping and one `mmap(MAP_PRIVATE | MAP_FIXED)` of the memfd per extent,
then `close` of the memfd, and one injected `clone(CLONE_VM)` per further
thread; each task gets its registers back. The host shares the template's
pages among all clones and copies a page only when a clone writes it.
Memory that was zero in the template is anonymous memory in the clone and
never mapped from the file: the host fills a hole of a memfd at the first
touch through a private mapping, read or write, seals or not, so clones
would otherwise grow the file they all share (a test compares the file's
allocated size before and after clones that write 32 MiB of such memory). K' completes the parked read
of the clone point with the input, reports `S` and runs the sandbox; K
reaps K', watches the connection, and reports for a K' that dies without
reporting itself. `kernel/platform-seccomp/src/snapshot.rs` and
`Kernel::run_template` / `Kernel::thaw` are the details.

Rejected designs:

* *Fork the app processes, and K with them.* A forked K does not inherit
  tracees. Handing the copies to K' needs `PTRACE_SEIZE` on the
  allowlist and `PR_SET_PTRACER` in the copies (Yama), and every clone
  would stay in the template's Landlock domain, where a compromised K'
  could `ptrace`, read and kill its siblings' processes.
* *Serialize the kernel state into a new kernel process.* Every core
  structure would need an encoding and a parser for it in a privileged
  process; `fork` copies all of it exactly, for free.
* *One kernel process serving the template and its clones.* One parser
  bug would reach every tenant.
* *Copy the memory into each clone.* Tens of megabytes per clone instead
  of shared pages.
* *Freeze at a moment the driver picks.* The guest could not prepare
  (buffered output, open connections, random state), and a template
  frozen mid-computation is rarely what is wanted. The guest decides.

**What a clone sees.** The same pids, memory, open files, current
directories, pipes with their unread bytes, loopback sockets (listening,
connected, queued connections and data), eventfds, signal handlers,
masks and pending signals, interval timers, and writable layer as the
template had. Blocked threads stay blocked in the same syscalls (a
`futex`, a pipe read, `wait4`, `poll`, a sleep). Different per clone: the
sandbox id (the requested one, else a random one; it names the clone's
egress flows), the console, and anything read from the host afterwards
(`getrandom` and `/dev/urandom` are read from the host per call). Clocks
are the host's: deadlines that passed while the template waited (a
sleep, an `alarm`) expire at once in the clone. Copied, and therefore the
same in every clone until the guest changes it, is everything the guest
derived before the freeze: the `AT_RANDOM` bytes and what libc made of
them (stack protector canary, pointer guard), the pointer-authentication
keys, CPython's hash seed and
`random` state, any user-space PRNG. A template that needs those to
differ must reseed after the clone point (`random.seed()`; the hash seed
cannot be changed in a running CPython, so dictionaries iterate in the
same order and hash flooding is the same in all clones). The virtual DNS
table is copied too: names the template resolved keep their fake IPs
(the guest may have cached them), and each clone's table evolves on its
own from there. Output the template buffered and did not flush is
written by every clone.

**What can be cloned.** Any number of processes and threads, in any of
the states above, zombies and stopped jobs (`tests/warm.rs` freezes one
template in all of them at once). Register state: general registers, the
basic FP/SIMD state, the extended state as the host's ptrace gives it
(`NT_X86_XSTATE` on x86_64, `NT_ARM_SVE` on aarch64, so a thread
interrupted in the middle of AVX or SVE code continues correctly; a
thread in SME streaming mode or with ZA enabled is not supported), the
thread pointer, and on aarch64 the
pointer-authentication keys, which the clone's new processes must get from
the template (Ubuntu builds glibc and CPython with `-mbranch-protection`:
with new keys, returning through a frame the template signed is
`SIGILL`). A host with pointer authentication whose kernel does not let a
tracer set the keys (`CONFIG_CHECKPOINT_RESTORE`) cannot freeze. Checked
and refused with the reason (the template answers every request with
`E` and exits):

| Not clonable | Why |
|---|---|
| An outbound connection through the egress proxy that is open (or one that is closed but still delivers bytes after 10 s) | a host connection, and the threads behind it, cannot be copied; close it before the clone point |
| `MAP_SHARED` anonymous memory while there is more than one address space | it may be shared between processes, and a rebuilt process cannot share pages with another one; a single process may have it (it is copied) |
| A terminal console | refused on the command line: a template has plain streams |
| The program ends before its clone point | nothing to clone |

Limits: 512 connections served at once per template; a request must be
complete within 10 s of connecting (an idle connection gets `E` and is
closed); 64 KiB of input; at most 1 TiB of stored pages (how much address
space the template has mapped does not matter).

**Hardening.** A clone's kernel process is a fork of the template's, so
it has every layer the template has, the same way (the seccomp filter,
`no_new_privs`, limits, namespaces, Landlock, not dumpable; the tests
compare `/proc/PID/status` and `/proc/PID/limits` of both). In addition,
before it creates its app processes, it puts itself into a Landlock
domain nested in the template's (a ruleset with no rules: it denies
nothing new on the filesystem but makes a new domain). Landlock refuses
ptrace-level access, `process_vm_readv`/`writev` included, from one
domain into a process outside it and its children, and with ABI 6
signals: a compromised clone kernel process cannot read, write or kill
the app processes of the template or of another clone (all of them run
as the same user and would otherwise be reachable, since seccomp cannot
tell pids apart), and they cannot reach it. A test has one clone's
kernel process try both on a sibling clone's app process (test hook):
refused, and with the nested domain left out, both succeed. Without
Landlock on the host nothing fences the clones of one template from each
other (they are forks, so they share its user namespace too, and a
separate uid per tenant is not possible within one template):
`--sandbox require` therefore refuses to start a template there, and
`best-effort` warns that the template is fit for one tenant only.

A clone starts with a copy of the template kernel process's memory, so
that process keeps nothing of one request where another's clone would
find it: the bytes of a request live in one buffer per connection that is
never reallocated, is zeroed when the request has been handed to its
clone or the connection ends, and the forked child zeroes the other
connections' buffers before it does anything else.

What `--template` adds to the allowlist, for templates and their clones
only (a sandbox started without it gets the list without these; measured
with `HELLOVM_SECCOMP_LEARN` over the whole suite, warm-clone tests
included): `accept4` (`SOCK_CLOEXEC` only) and `recvmsg`
(`MSG_CMSG_CLOEXEC` only) for the control socket, `fcntl(F_ADD_SEALS)`
for sealing the snapshot, and `landlock_create_ruleset` and
`landlock_restrict_self` (flags 0) for the clone's domain, which can only
take rights away. The memfd is created and sized before the hardening, so
`memfd_create` and `ftruncate` are not on the list; forking K' is the
`clone` with `fork` flags that starting app processes already uses, and
`PR_SET_PDEATHSIG` (clones die with the template) was already allowed.
No layer is weakened. The app processes' residual host-syscall surface
(see `spawn.rs`) gains, during the rebuild and before any guest code runs
in the process, `mmap` of the snapshot memfd (only that fd, `MAP_PRIVATE
| MAP_FIXED`, a range the platform checked) and `close` of it.

The template is trusted more than a clone: everything a clone starts
from comes from the template's kernel process, which ran the template's
guest. A template program that compromised its kernel process would
compromise every clone made from it. Templates should be built from
programs and images the operator controls; the clones' guests never
reach the template: after the fork, a clone shares no writable state with
it (the snapshot is sealed; K' closes its copies of the listening socket,
the other connections and their clones' pidfds at once); what K' keeps of
the template's fds is the image directory (read-only), the egress socket
directory, `/dev/urandom`, and hellovm's own stdin, stdout and stderr
(its log lines go to stderr).

**Measurements.** `kernel/hellovm/tests/warm_bench.rs` (`cargo test
--release -p hellovm --test warm_bench -- --ignored --nocapture`) runs a
CPython program that imports `asyncio`, `json`, `decimal`, `hashlib`,
`http.client`, `email.parser`, `ssl`, `xml.etree.ElementTree`,
`urllib.request`, `argparse`, `dataclasses`, `pathlib` and `sqlite3`,
waits at the clone point and prints a line. Release build,
on an Apple M3 Max in Docker Desktop (Linux 7.0.14-linuxkit, aarch64, 14
CPUs), default seccomp profile (namespaces skipped, the other layers
active), medians of 30 clones and 5 cold starts:

| | Debian bookworm (CPython 3.11) | Ubuntu 26.04 (CPython 3.14) |
|---|---|---|
| Native `python3`, start to first line | 38.8 ms | 44.1 ms |
| Cold `hellovm`, start to first line | 193.6 ms | 141.8 ms |
| Template, start to frozen (once) | 222.5 ms | 176.3 ms |
| Snapshot (stored pages, areas) | 29.9 MiB, 128 | 35.8 MiB, 105 |
| **Clone, request to first guest instruction** (`S`) | **7.0 ms** (4.1–10.4) | **5.7 ms** (3.7–9.1) |
| **Clone, request to first line** | **8.2 ms** (4.7–11.3) | **6.6 ms** (4.6–10.3) |
| Clone, request to exit status | 24.7 ms | 25.7 ms |
| **Sandbox through `hellovm-api`, request to ready** (see **Control plane**) | **8.3 ms** (5.8–8.7) | **7.1 ms** (4.1–7.9) |

The 50-clone test makes 50 clones one after another and then 50 at once,
each running and ending a small program, in about half a second each way
in a debug build.

Where a clone's time goes (`HELLOVM_LOG=debug` on the template logs it
per clone): rebuilding the app processes takes 3.8–5.5 ms of it, that is
a fresh app process plus the injected `mmap`s (two ptrace stops each,
roughly 30–40 µs on this VM): one per extent of the snapshot (125 for the
128 areas of this program on bookworm; the template logs the number) and
an anonymous one for each area that is not a single extent; the fork of K' and its set-up (Landlock domain, console) take
tens of microseconds; the rest is the request, the `S` frame and the
guest's own work. Fewer, larger areas would make it faster; so would
batching the injected `mmap`s, which the current one-syscall-per-stop
injection does not do. A clone's exit takes longer than its
start: CPython's finalization writes to most of its objects, and every
first write to a page shared with the template is a copy.

## Control plane

Two services make sandboxes available over the network, both in Rust in
this workspace:

| Crate | Path | Role |
|---|---|---|
| `hellovm-api` | `kernel/api` | The public API: authenticates tenants, enforces their limits, places sandboxes on a node, keeps the sandbox metadata, passes each request about a sandbox to its node |
| `hellovm-noded` | `kernel/noded` | The node daemon, one per host: keeps warm templates alive, makes sandboxes by cloning them, carries `exec` and file operations to the agent inside each sandbox, removes sandboxes, reports capacity |
| `hellovm-control` | `kernel/control` | What both share: a small HTTP/1.1 server and client, sandbox ids, token comparison, the JSON types |

```text
client --HTTP, tenant token--> hellovm-api --HTTP, node token--> hellovm-noded
                                                                    | warm-clone protocol (Unix socket)
                                                                    v
                         hellovm --template (frozen CPython running the agent)
                                                                    | fork per sandbox
                                                                    v
                    clone kernel process <-- console pipes: agent frames --> noded
                                         <-- ingress channel: inbound connections -- noded

HTTP client --PORT-SANDBOX.DOMAIN--> TLS proxy --> hellovm-api ingress listener
     --TCP, handed over by noded--> clone kernel process --> the guest's accept()
```

They live in `kernel/` because `noded` uses the warm-clone client of the
`hellovm` crate and the whole repository has one workspace and one CI
gate. When the API is deployed apart from the nodes (U6), `api` and
`control` would move to a top-level `services/` workspace, with `noded`
staying next to the kernel it drives.

**Running it.** One egress proxy and one `noded` per host, and one `api`
for all of them (see **Scheduling** below for several nodes):

```sh
hellovm-egress --listen /run/hellovm/egress/egress.sock --policy /etc/hellovm/egress.policy \
  --stats /run/hellovm/egress-stats/stats.sock --stats-token-file /etc/hellovm/egress-stats.token &
hellovm-noded --config /etc/hellovm/noded.json &
hellovm-api --config /etc/hellovm/api.json &
```

```json
{"node": "node-1", "listen": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token",
 "hellovm": "/usr/local/bin/hellovm", "state_dir": "/run/hellovm-noded",
 "egress": "/run/hellovm/egress/egress.sock", "max_sandboxes": 64, "max_memory_mb": 16384,
 "egress_stats": {"socket": "/run/hellovm/egress-stats/stats.sock",
                  "token_file": "/etc/hellovm/egress-stats.token"},
 "templates": [{"name": "python", "root": "/", "python": "/usr/bin/python3",
                "preload": ["json", "decimal", "sqlite3"], "memory_limit_mb": 1024,
                "fs_limit_mb": 1024}]}
```

```json
{"listen": "0.0.0.0:7070",
 "tenants": [{"name": "acme", "token_file": "/etc/hellovm/acme.token", "max_sandboxes": 10,
              "max_memory_mb": 8192, "requests_per_second": 50,
              "cpu_seconds_per_period": 36000, "egress_bytes_per_period": 10737418240}],
 "nodes": [{"name": "node-1", "addr": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token"}],
 "default_idle_timeout": 600, "max_idle_timeout": 86400,
 "default_lifetime": 3600, "max_lifetime": 86400,
 "admin": {"listen": "127.0.0.1:7079", "token_file": "/etc/hellovm/admin.token"},
 "ingress": {"listen": "127.0.0.1:7080", "domain": "sandbox.example.com", "behind_proxy": true},
 "metering": {"period": "month", "log": "/var/lib/hellovm-api/usage"}}
```

Unknown fields in either file are errors. Tokens are at least 22
printable characters; two tenants cannot share one. Both services run
unprivileged and log to stderr (`HELLOVM_LOG`, default `info`).

```sh
curl -s -H "Authorization: Bearer $TOKEN" -d '{"template": "python"}' http://127.0.0.1:7070/v1/sandboxes
curl -s -H "Authorization: Bearer $TOKEN" -d '{"command": "ls /", "timeout": 10}' \
  http://127.0.0.1:7070/v1/sandboxes/sb-.../exec
```

**The API.** JSON bodies; errors are `{"error": {"code": ..., "message": ...}}`.

| Method and path | Body | Answer |
|---|---|---|
| `GET /v1/templates` | | `{"templates": [{"name", "ready"}]}` |
| `POST /v1/sandboxes` | `{"template", "idle_timeout"?, "lifetime"?}` (seconds) | `201`, the sandbox |
| `GET /v1/sandboxes` | | `{"sandboxes": [...]}`, the caller's |
| `GET /v1/sandboxes/{id}` | | `{"id", "tenant", "template", "node", "egress_id", "created_at", "last_used_at", "expires_at", "idle_timeout", "memory_bytes", "memory_limit_bytes", "ready_ms", "usage"}` (`usage`: below) |
| `DELETE /v1/sandboxes/{id}` | | `204`; `202` when its node does not answer (deleted there later) |
| `POST /v1/sandboxes/{id}/exec` | `{"command"` or `"python", "stateful"?, "timeout"?, "cwd"?, "env"?, "stdin"?, "max_output"?}` | when it ended: `{"exec_id", "exit_code", "signal", "timed_out", "cancelled", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "stdout_bytes", "stderr_bytes", "duration_ms"}`, and for a stateful call `"value"?, "error"?, "state_lost"` |
| `POST /v1/sandboxes/{id}/execs` | the same | `201` once it started: `{"exec_id", "kind", "state": "running", "started_at", "cancel_requested", "result": null}` |
| `GET /v1/sandboxes/{id}/execs` | | `{"execs": [...]}`: the latest exec, running or ended |
| `GET /v1/sandboxes/{id}/execs/{exec}?cursor=&wait=&max_bytes=` | | `{"exec_id", "state", "events", "next_cursor", "eof", "result"}` |
| `POST /v1/sandboxes/{id}/execs/{exec}/cancel` | | the exec, once it ended (or after 5 s) |
| `POST /v1/sandboxes/{id}/python/reset` | | `{"had_state"}` |
| `GET /v1/sandboxes/{id}/files?path=P` | | the file's bytes |
| `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `{"bytes"}` |
| `POST /v1/sandboxes/{id}/files/edit` | `{"path", "old", "new", "replace_all"?}` | `{"replacements"}` |
| `GET /v1/sandboxes/{id}/ingress` | | `{"token", "ports": [{"port", "public", "url"}]}` (see **Ingress**) |
| `PUT /v1/sandboxes/{id}/ingress/ports/{port}` | `{"public"?}` | the same, with the port exposed (or `public` changed) |
| `DELETE /v1/sandboxes/{id}/ingress/ports/{port}` | | the same, without it |
| `POST /v1/sandboxes/{id}/ingress/token` | | the same, with a new token |
| `GET /v1/usage` | | `{"tenant", "period", "usage", "sandboxes", "memory_limit_bytes", "quotas", "exceeded"}` (see **Quotas and metering**) |

| Status | Code | When |
|---|---|---|
| 400 | `bad_request`, `is_directory`, `not_regular`, `not_text` | malformed request; not a file; not UTF-8 (edit) |
| 401 | `unauthorized` | no or unknown token |
| 404 | `sandbox_not_found` | no such sandbox, **or another tenant's** (the same answer) |
| 404 | `not_found`, `template_not_found`, `exec_not_found` | no such file or working directory; no such template; no such exec (only the latest is kept) |
| 404 | `ingress_disabled` | an ingress endpoint, on an API without `ingress` in its configuration |
| 409 | `busy` | the sandbox is running another request or exec (one at a time; reading, listing and cancelling an exec are not requests that take it) |
| 409 | `too_many_ports` | the sandbox has 16 ports exposed already |
| 410 | `sandbox_ended` | the node removed it and still remembers why (idle, lifetime, memory, its agent ended) |
| 413 | `too_large` | a body or file over 16 MiB |
| 422 | `no_match`, `ambiguous` | edit: `old` does not occur, or occurs more than once without `replace_all` |
| 429 | `tenant_limit`, `memory_limit` | the tenant has `max_sandboxes` already; its sandboxes' memory limits and the new one's would be over its `max_memory_mb` |
| 429 | `rate_limited` | more requests than `requests_per_second` allows; `Retry-After` says in how many seconds a request is taken again |
| 429 | `budget_exceeded` | creating a sandbox or starting an exec while the tenant's CPU or egress budget of the period is used up; `Retry-After` is the end of the period |
| 502 | `sandbox_failed`, `node_unreachable` | the sandbox's agent broke (the sandbox is removed); the sandbox's node does not answer, or is marked unreachable (try again later) |
| 503 | `template_not_ready`, `node_full` | the template is starting, or ready on no node that takes sandboxes; no node has room: try again |
| 507 | `no_space` | the writable layer is full |

*exec.* `command` runs as `/bin/sh -c COMMAND`; `python` runs the
source in a fork of the sandbox's warm interpreter, so the template's
modules are already imported (`SystemExit` sets the exit code, an
uncaught exception prints its traceback and exits 1); `python` with
`"stateful": true` runs it in the sandbox's interpreter (below). The working
directory is `/root` unless `cwd` says otherwise (relative paths in file
operations are relative to it too); `env` adds variables; `stdin` is
the command's input (otherwise it reads end of file). `timeout` (default
60 s, at most 3600 s) kills the command's whole process group with
`SIGKILL`: `timed_out` is `true` and `signal` 9. Output is decoded as
UTF-8 with invalid bytes replaced; each stream keeps at most
`max_output` bytes (default 64 KiB, at most 1 MiB): the first and the
last half, with `[... N bytes omitted ...]` between them, and
`stdout_bytes` says how much there was. Limits: command, Python source
and stdin 1 MiB each, 256 environment variables in 64 KiB. Every exec has
an id (`ex-N`, increasing per sandbox), and a cancelled one says
`cancelled` (with `signal` 9).

*Streaming and cancelling.* `POST .../execs` starts the same exec and
answers as soon as it runs; its output is then read with a cursor, a
byte position in its stdout and stderr interleaved in the order the
agent read them:

```text
POST /v1/sandboxes/sb-.../execs  {"command": "make test", "timeout": 600}
  -> 201 {"exec_id": "ex-4", "state": "running", ...}
GET  /v1/sandboxes/sb-.../execs/ex-4?cursor=0&wait=30
  -> {"state": "running", "events": [{"type": "stdout", "data": "cc -c a.c\n"},
      {"type": "stderr", "data": "warning: ...\n"}], "next_cursor": 31, "eof": false, "result": null}
GET  /v1/sandboxes/sb-.../execs/ex-4?cursor=31&wait=30
  -> {"state": "done", "events": [...], "next_cursor": 2048, "eof": true, "result": {... "exit_code": 0}}
```

A poll answers as soon as there is output past `cursor`, the exec ended,
or `wait` seconds (default 0, at most 30) passed; it returns at most
`max_bytes` (default 256 KiB, 1 KiB to 1 MiB) and never splits a UTF-8
character while the exec runs. A client follows an exec by polling with
each answer's `next_cursor` until `eof`; any connection can poll, any
number of times (a poll changes nothing), so a dropped connection loses
no output. Order between the two streams is exact only for output
written at different moments (two pipes are read; a PTY would make it
one stream). Output not yet read is held by the node as the result is:
the first `max_output` bytes and the last `max_output` bytes of both
streams together, in at most 4096 runs of one stream each (output that
switches between the streams more often than that is dropped in the
middle the same way); a cursor in the part dropped between them gets an
`{"type": "omitted", "bytes": N}` event and then the rest. `result` is
the same as `POST .../exec` answers, with each stream cut by itself.
`POST .../execs/{exec}/cancel` kills the exec's process group (a
stateful call is interrupted first, see below) and answers once it
ended, at most 5 s later; it works from any connection, while polls
wait (they are woken), for an exec started by `POST .../exec` too (its
id is in `GET .../execs`), and a second cancel or one after the end
changes nothing. A client that goes away does nothing to the exec: it
runs to its end, its timeout or a cancel, and its output stays readable
until the next exec of the sandbox starts (a sandbox keeps its latest
exec only). A poll holds a connection for at most 30 s, and at most
four polls wait on one exec at once (`429 too_many_polls` for the next);
an exec holds
its sandbox for at most its timeout, and the sandbox's lifetime still
applies.

*Stateful Python.* `{"python": CODE, "stateful": true}` (on either
endpoint) runs CODE in the sandbox's interpreter: a process forked from
the warm interpreter on first use (so the template's modules are
imported), which keeps its namespace between calls, like a notebook
kernel: variables, imports, open files and objects, threads it started.
The value of the code's last expression, when it ends in one that is
not `None`, comes back as `value` (its `repr`, at most 16 KiB of
characters, the middle cut; it is also `_`); an exception as `error`:
`{"type", "message", "traceback"}` (the traceback shows the lines of
the cells it went through, at most 16 KiB), with `exit_code` 1, and the
state survives it. Its output streams like any exec's; `stdin` is
`sys.stdin` for the call; `cwd` and `env` are refused (the interpreter
has its own: change them with `os.chdir` and `os.environ`). At its
timeout or on a cancel the interpreter gets `SIGINT`: code that can be
interrupted stops with `KeyboardInterrupt` and the state is kept; code
that does not stop within 2 s (a long call in C, an ignored `SIGINT`)
is killed with its process group, the call says `InterpreterKilled` and
`state_lost: true`, and the next call starts a fresh interpreter. An
interpreter that ends by itself (`os._exit`, a crash) is reported the
same way (`InterpreterExited`, with its status). `POST .../python/reset`
kills it (`had_state` says whether there was one); the next call starts
afresh. It is a process of the sandbox like any other: its memory and
processes count against the sandbox's limits (going over removes the
sandbox, as always), and it is separate per sandbox, so per tenant.
Output written between calls by what a call left running is dropped.

*State between requests.* Kept: the filesystem (the writable layer),
processes started in the background that hold none of the command's
pipes (`nohup server >log 2>&1 &`; output written to the pipes after
the command ended is dropped, 100 ms after it ended), and everything the
template set up. Not kept: the shell's working directory, variables and
functions (each `command` is a new shell), and the variables of a
`python` run (each is a new fork): what is to persist goes to the
stateful interpreter.

Relative paths and the default working directory are the agent's home:
`HOME` from the template's `env`, else `/root`. The user `noded` runs as
must be able to read that directory in the image (a host's own `/root`
is not, for anyone but root): set `HOME` to one that is.

*Files.* `read_file` and `write_file` take any path (`write_file`
creates the parent directories); only regular files are read or written
(a FIFO or device is refused, never opened for blocking I/O); at most
16 MiB. `edit_file` replaces exactly one occurrence of `old` by `new` in
a UTF-8 file (all of them with `replace_all`) and says how many it
replaced. Both write a new file next to the target and rename it over
it (through symbolic links, keeping the mode), so a write that fails,
for lack of space say, leaves the old contents.

*Life cycle.* A sandbox is removed by `DELETE`, after `idle_timeout`
seconds without a request (a running request is not idle), at the end
of its `lifetime` however busy it is (both default and capped by the API
configuration, at most a week), when its processes' private memory goes
over the template's `memory_limit_mb`, when it has more processes and
threads than the template's `max_processes`, or when its agent ends. Its
node answers `410` with the reason for a while (the node and the API each
remember 4096 ended sandboxes), then `404`; a sandbox its tenant deleted
is `404` at once.

*Tenants.* A tenant is a bearer token in the API's configuration. Every
request about a sandbox looks it up and checks the tenant before
anything reaches a node, and the node checks again (`X-Hellovm-Tenant`):
another tenant's sandbox answers exactly like a missing one. Sandbox ids
are `sb-` and 128 random bits (`getentropy`). A tenant's sandboxes and
creations in progress count against its `max_sandboxes` (`429` past
it). Tokens are compared in constant time, all of them on every request.

*Egress.* `noded` passes `--egress` to every template, and gives each
clone a sandbox id for the proxy: the first 64 bits of the sandbox id,
so the `sandbox=` field of the proxy's audit lines is `egress_id`, the
first 16 hex digits of the id. Nothing about outbound traffic changes:
the policy is the proxy's.

**How exec and files reach the guest.** By an agent that is part of the
template: `noded` runs every template as `python3 -I -c AGENT MODULE...`
(the agent is `kernel/noded/src/agent.py`, compiled into `noded`). The
agent imports the template's modules, makes `/root`, and waits at the
clone point. Each clone continues in the agent with its own console,
which `noded` creates as three pipes and passes with the clone request:
requests come in on stdin, answers go out on stdout, the agent's own log
on stderr (`noded` logs at most 64 KiB of it per sandbox). A frame is
`[header length u32][body length u32][JSON header][body]`; the agent
greets with its version (2) once the clone runs, and each answer carries
its request's id. `noded` sends one request at a time. An exec is
answered `started` at once, then its output follows as `output` frames
(at most 64 KiB each) as the agent reads it from the command's pipes,
then its final answer (the status, and a stateful call's value and
traceback; no output: `noded` keeps that, so the truncation rule is in
one place). While an exec runs `noded` may send `cancel`, which is
never answered. The sandbox's watch thread reads the agent's stdout all
the time, through an incremental parser, and hands each frame to what
it belongs to. The agent is the sandbox's first process, so it also
reaps orphans. Its frames are untrusted: anything in the sandbox can
write to `/dev/console`, so `noded` bounds every length before
allocating (a 64 KiB header; a body no longer than what is outstanding
can produce: nothing when nothing is, 64 KiB of output, a file read's
16 MiB), wants a frame that started complete within 30 s and the next
answer by its deadline (an exec's: its timeout plus 10 s), has a
deadline on every write, takes a frame only for the request
outstanding and in its order, checks every field, and on any violation
removes the sandbox (it can only have broken itself). A guest that
forges frames can lie about its own output and status, or end its own
sandbox; it cannot make `noded` allocate past those bounds, block it,
or reach another sandbox. The stateful interpreter is a child of the
agent with pipes of its own (calls in, answers out, stdout, stderr),
which the agent bounds the same way for its own sake. Rejected:

* *Something in the kernel process.* A command runner and file server
  in the process that parses guest bytes would enlarge the most
  exposed process and its seccomp allowlist, and could not run a
  command without a guest process anyway. The kernel stays generic.
* *Another channel* (a socket passed as a fourth fd, or a connection
  into the guest's loopback). It needs a protocol change and kernel
  support for a host connection reaching a guest socket (that is
  ingress, U6). The console exists, is already per clone, and carries
  the agent's traffic well.
* *A new `hellovm` (or clone) per exec.* State would not survive
  between execs, and each would pay the clone again.

**Why long polling for streams.** Reading an exec's output by polling a
cursor needs nothing new in the HTTP layer (requests and answers with a
`Content-Length`, as before), and the API passes polls to the node like
any request. A poll holds a connection for 30 s at most, at the API and
at the node; any connection can resume where another stopped; a cancel
is an ordinary request; a slow or absent reader costs a bounded buffer
on the node and nothing else. The price: a round trip per batch of
output (on loopback the first output of `echo hi` arrives 10 ms after
the request, see below), and a little more traffic than a stream.
Rejected: *a streamed response* (chunked NDJSON, or server-sent events)
would hold a connection slot at both hops for the whole exec (up to an
hour, from a pool of 256, 32 per client), needs streaming in the
server, in the client and in the API's forwarding, notices a client
that left only when a write fails, and loses output when a connection
drops unless it adds a cursor anyway; server-sent events can be added
later on the same cursor (it is the `Last-Event-ID`) for browsers.
*Killing an exec whose client left*: that is what cancel is for, and
it would make every network blip fatal to a long build. *WebSockets*: a
second protocol to harden for what polls do. *Interactive stdin or a
PTY* is not done; it would be a write endpoint taking bytes for the
running exec (`POST .../execs/{exec}/stdin`, carried as an agent frame
like `cancel`) and a `pty` flag that makes the agent run the command
on a pseudo-terminal, whose single output stream fits the same cursor.

**Why a forked worker for stateful Python.** The interpreter is a fork
of the warm agent, so it starts with the template's modules in about
8 ms and needs no new code in the image; it is a process of its own,
so a timeout can interrupt it (`SIGINT`, which CPython turns into
`KeyboardInterrupt` in the code running) or kill it without touching
the agent, and its memory is the sandbox's. Rejected: *running calls in
the agent itself* (a call that hangs or crashes would take the channel
with it); *a Jupyter kernel* (ZeroMQ, a kernel spec and an image that
has them, for what one pipe protocol does); *keeping the state by
pickling the namespace between forks* (most objects do not pickle:
open files, sockets, threads, modules).

**How `api` and `noded` talk.** HTTP/1.1 with JSON, the same shapes as
the public API (the node API is listed in `kernel/noded/src/server.rs`):
`POST /v1/sandboxes` carries the id, tenant, template and the resolved
timeouts the API chose. Each node has its own bearer token, which the
API presents; every request about a sandbox also names its tenant.
`GET /v1/node` reports the node's templates and load, and `POST
/v1/node/drain` (`{"draining": true}` or `false`) stops or resumes its
taking new sandboxes (see **Scheduling**). For ingress: `GET`, `PUT`,
`DELETE .../ingress[/ports/{port}]` and `POST .../ingress/token` keep a
sandbox's token and exposed ports, `POST .../ingress/connect?port=P`
answers `200` and hands that very connection to the sandbox, and `POST
/v1/node/touch` (`{"sandboxes": [ids]}`) restarts idle timeouts (see
**Ingress**). With
many nodes, the node API needs TLS with a certificate per node (mutual
TLS, so a node knows the API and the API knows the node), which is not
done: the node API must listen on loopback or a private network until
then. Rejected: gRPC (out of scope for now, and many dependencies for
what a dozen JSON routes do); a Unix socket (does not reach other
hosts).

**Where the metadata lives.** The nodes are the source of truth: each
knows the tenant, template, deadlines and memory of every sandbox it
runs, and removes them itself. The API keeps a store (`Store` in
`kernel/api/src/store.rs`; `MemoryStore` in its memory today) of which
sandbox is whose and where, rebuilt from the nodes when it starts and
reconciled every `reconcile_interval` (2 s): a sandbox a node no longer
lists is dropped, one created while the node was being asked is kept.
Postgres replaces `MemoryStore` behind the same trait: a row per
sandbox written on create and delete, the tenant's count and
reservation in the same transaction, and the reconciliation updating
rows from the nodes. Listing and per-sandbox requests ask the node
anyway, so what a client sees is fresh.

**Restarts.** The API: nothing is lost; it rebuilds its store and what
it knows of every node from the nodes before serving, and running
sandboxes keep their state (tested, with three nodes too).
`noded`: its templates die with it (`PR_SET_PDEATHSIG`) and their clones
with them, so its sandboxes are gone; the next `noded` removes the
stale sockets, starts the templates again, and the API drops the lost
sandboxes at its next reconciliation (tested). A template that dies is
started again at once (if it had run a minute; otherwise after a delay
that doubles up to 30 s), and its sandboxes are gone (tested). Keeping
sandboxes across a `noded` restart would need the templates and the
clones' control connections to outlive it (an fd store, re-adoption):
not done.

**Scheduling.** The API takes any number of nodes and places each new
sandbox on one of them (`kernel/api/src/nodes.rs`).

*What a node reports.* `GET /v1/node` on `noded`: its templates (name,
ready, the tenant of a template that is not shared), `sandboxes` and
`creating` (both count against its `max_sandboxes`), `memory_bytes` (the
private memory of all its sandboxes, as last measured) and
`memory_limit_bytes` (`max_memory_mb` in its configuration; by default
the host's memory, `MemTotal`), and `draining`. `noded` refuses a
create (`503`) when it is full by count, when its sandboxes hold
`memory_limit_bytes` or more, and while it drains.

*Node states.* The API probes every node every `reconcile_interval`,
each on a thread of its own (a slow node does not delay the others):
`GET /v1/node` within `node_timeout`, then its sandbox list, which
reconciles the store as before. A node is

| State | Meaning | New sandboxes | Its sandboxes |
|---|---|---|---|
| `healthy` | answers | yes | served |
| `draining` | answers, and says it drains | no | served, can be deleted |
| `unreachable` | `unhealthy_after` failed probes in a row, or as many connections for requests that could not be made | no | `502 node_unreachable` at once |
| `unknown` | not probed yet (only before the API serves) | no | |

A failed probe is one that got no answer in time, or a status or list
that is not valid (malformed JSON, another node's name, numbers out of
range, a body over its bound: 1 MiB for a status, 8 MiB for a list); a
good probe resets the count, so one slow answer does not flap a node,
and answered requests do not (a node whose status cannot be had is not
known, whatever else it answers). Requests count only when no
connection could be made (within 5 s), on a count of their own that an
answered request resets. A request that was sent and not answered in
time is not counted: how long it takes is partly up to the sandbox, and
one tenant must not make a node unreachable for the others. An unreachable node
becomes healthy again after `healthy_after` good probes in a row (only
probes bring it back), and its sandboxes are reconciled as they always
are: those its `noded` still runs are served again, those that died
with it are dropped (`404`). The first probe decides at once. Every
change is logged as one line:

```text
api: info: node state change: node=node-2 from=healthy to=unreachable error="connecting: Connection refused (os error 111)"
api: info: node state change: node=node-2 from=unreachable to=healthy
```

*Placement.* Among the nodes that are healthy (not draining, not
unreachable) and have the template, for this tenant, the API asks first
those that have it ready and room by what it knows, then the others
(whose report may be stale: the node decides); in each group the least
loaded first, a node's load being the larger of its sandboxes over
`max_sandboxes` and its memory in use over its limit; nodes of equal load
in random order. A node that refuses (full, starting its template,
draining) or cannot be connected to is followed by the next, until
three have refused (the reports are at most a probe old, so the first
choices are the ones with room if any has; a refusal that is none of
those is logged as a warning); one that may have made the sandbox (its
answer was lost) ends the attempt, as before. Load reports lag by up to `reconcile_interval`, so the API
counts what it does itself at once: every creation in flight and every
sandbox it placed are added to the node's reported count until a
report asked after them arrives. Concurrent creates therefore spread
over the nodes instead of all going to the one that was emptiest at the
last report (a thundering herd), and one API needs no randomness to
avoid that; the random tie-break is for nodes of equal load. When no
node can take the sandbox the tenant gets `503 node_full` (no room or
none healthy), `503 template_not_ready` (the template is ready on no
node that takes sandboxes) or `404 template_not_found` (every node has
reported and none has it; while a node has never reported, as after an
API restart with that node down, an unknown template answers `503
node_full`, since that node may have it); the node's own error never
reaches the tenant. `GET /v1/sandboxes` asks only the nodes that have
sandboxes of the tenant.

*Exactness.* The tenant limit is counted by the API across all nodes
under one lock, creations in progress included, so concurrent creates
on several nodes never exceed it (tested with 20 at once). A sandbox
whose create answer was lost is kept in the store (it counts) unless
its node confirms deleting it, until the node's next list shows whether
it exists. The sandboxes of an unreachable node keep counting until their
tenant deletes them: the delete is accepted (`202`) and done on the node
once it answers (see **Quotas and metering**). Not exact: an API that restarts while a
node is unreachable does not know that node's sandboxes until it
answers, so a tenant may then go over its limit by those (it cannot
create more until it is under it again); and a tenant's sandbox list
omits the sandboxes of unreachable nodes.

*Templates across nodes.* `GET /v1/templates` answers from the last
reports, not by asking every node: a template is listed when some node
has it (for this tenant), and `ready` when it is ready on a node that
takes sandboxes now, so a create of a template listed as ready is not
refused for want of one (it may still be for want of room).

*Draining.* `POST /admin/v1/nodes/{name}/drain` (below) tells the node,
which refuses new sandboxes from then on; its sandboxes run to their
end and are served and deleted as usual. `.../undrain` reverses it. The
flag lives in the `noded` process: an API that restarts finds it there,
and a restarted `noded` (which lost its sandboxes anyway) takes
sandboxes again, unless its configuration says `"start_drained": true`:
then it starts drained (logged as `draining=true (start_drained)`) until
an operator undrains it, so a host being retired does not fill again
when its `noded` restarts (tested). To retire a host: drain it, wait until its sandboxes
are gone (`report.sandboxes` is 0), stop it, and remove it from the
configuration.

*The admin API.* Served only when `admin` is configured, on a listener
of its own (`admin.listen`: keep it on loopback or a private network),
with a token of its own (`admin.token` or `admin.token_file`, which may
not be a tenant's or a node's token). The tenants' listener does not
route `/admin` at all (`404`), and the admin listener takes no tenant
token (`401`), so a tenant can neither reach it nor learn of nodes
through it. At most 16 connections.

| Method and path | Answer |
|---|---|
| `GET /admin/v1/nodes` | `{"nodes": [NODE...]}` |
| `GET /admin/v1/nodes/{name}` | `NODE`: `{"name", "addr", "state", "since", "last_error", "reported_ms_ago", "placed_since_report", "in_flight", "report"}` (`report`: the node's last status: counts, memory, `draining`, templates) |
| `POST /admin/v1/nodes/{name}/drain` | `NODE`, once the node drains |
| `POST /admin/v1/nodes/{name}/undrain` | `NODE`, once it takes sandboxes again |
| `GET /admin/v1/usage` | `{"tenants": [USAGE...], "sandboxes_metered", "odd_reports", "deletes_waiting", "ingress_connections", "log"}` (`ingress_connections`: open now, `null` without ingress) (`USAGE` as `GET /v1/usage` answers; `log`: `null` without one, else `{"path", "healthy", "last_error", "written", "backlog", "dropped"}`) |
| `GET /admin/v1/usage/{tenant}` | `USAGE` |

*Configuration.* In the API's file: `nodes` (each `name`, `addr`,
`token` or `token_file`), `reconcile_interval` (seconds between probes,
default 2), `node_timeout` (seconds a probe may take, default 5, at most
60), `unhealthy_after` (default 3) and `healthy_after` (default 2), 1 to
100 each, `admin`, and `metering` (below). In `noded`'s: `max_sandboxes`,
`max_memory_mb`, `start_drained` (default `false`) and `egress_stats`. With the defaults a node that refuses connections is
unreachable after about 6 s (three probes 2 s apart; sooner when
requests to it fail), one that hangs after up to 21 s (each probe waits
5 s), and either is healthy again about 4 s after it answers.

Rejected: *the node pushing its load* (heartbeats to the API): the API
would need a listener for nodes and to know the nodes anyway to reach
them; polling also notices a node that died without a word. *Power of
two random choices*: it fits many independent schedulers with stale
views; one API that counts its own placements does better with the
least loaded. *Placement by free memory alone*: sandboxes are small
next to their limits, so count and memory both matter, and the larger
fraction protects whichever runs out first. *Drain state in the API*:
it would be lost on an API restart, which the nodes outlive; on the
node, it is what the node does. *Admin routes on the tenants' listener*:
one leaked or guessed path would be reachable from wherever tenants
are; a separate listener can be firewalled. *Retrying a create on
another node after an ambiguous failure*: it could make the sandbox
twice. Not done (out of scope): moving running sandboxes between nodes,
several API instances (their in-flight counts would not be shared; the
tenant limit then needs a shared store), and TLS between the API and
the nodes (see above).

**Quotas and metering.** The nodes measure what each sandbox uses, the
API adds it up per tenant and period, writes it to a usage log, and
refuses new work to a tenant over its quotas
(`kernel/api/src/{meter,meterlog,quota}.rs`).

*What a node measures.* Every sandbox's `usage` (in `GET
/v1/sandboxes/{id}`, and in the node's lists): `run_ms` (wall-clock time
since it was made), `cpu_ms`, `memory_byte_seconds` and
`egress_sent_bytes` / `egress_received_bytes`. Each counter only grows,
lives as long as the sandbox, and keeps its last value when it ends.
(`ingress_received_bytes` / `ingress_sent_bytes` are in the same `usage`
object but counted by the API, which relays them: see **Ingress**; a
node reports them as 0, and the API ignores what a node says of them.)

* CPU time: the scan that measures memory once a second (see **Resource
  limits**) also reads `utime + stime + cutime + cstime` of the clone's
  kernel process and of every process below it. A guest process that
  ended was waited for by its parent below the kernel process, so its
  time is in that parent's `cutime`/`cstime`, and counted. Not counted:
  a process whose host parent went away before waiting for it (it was
  reparented out of the tree) after the last scan that saw it. A sandbox
  is measured once more as it is removed, before its processes are
  killed, so it pays for its last second too (and one that lived less
  than a second, for what it used). The node keeps the
  largest sum seen, so a process moving from one place of the sum to
  another never makes it go down.
* Memory: each measurement of private memory counts for the time since
  the one before (byte-seconds), the same overestimate as for the limit.
* Egress: counted by the egress proxy, which relays every byte, not by
  the kernel process: the kernel process parses guest input and could be
  made to lie, and it sees bytes it buffered rather than bytes that left.
  The proxy counts per connecting process (see **Egress**, *Bytes per
  kernel process*) and `noded`, which knows each sandbox's kernel process
  id and start time, asks it once a second on the stats socket
  (`egress_stats` in its configuration; without it, egress is 0). Counted:
  the bytes of allowed flows delivered upstream (`sent`: the guest's
  request, TLS handshake included) and delivered to the guest
  (`received`), as they move. Not counted: DNS (answered by the kernel
  process; nothing leaves), refused flows, bytes the proxy read while
  sniffing a flow that was then refused, TCP/IP and TLS framing the host
  kernel adds, and bytes still in the proxy's buffers when a sandbox
  ends (the counters are read for 2 s after it ended).

A sandbox that ended stays in the node's memory (4096 of them); 2 s
after its end its usage is final and gets a number, `seq`, increasing
per `noded` process. The API asks `GET /v1/sandboxes?ended_after=SEQ`
and gets, with the live sandboxes, those that ended since (at most 1024
per answer, `ended_more` when there are more) and the node's `boot`, a
random number per `noded` process (a new one means the numbering started
again).

*What the API counts.* The probes the API makes anyway (every
`reconcile_interval`) bring every sandbox's counters. Per sandbox, the
meter keeps the counters it took last; what grew since is added to the
tenant's total for the current period and to the sandbox's next record.
A node is not trusted to report sense:

| Report | What the API does |
|---|---|
| a counter lower than the last one taken | nothing is counted, the higher value is kept (nothing is counted twice when it climbs back) |
| a counter that grew more than possible since the last report (run time faster than the clock; CPU time faster than the node's CPUs, `cpus` in its status; egress faster than 100 Gbit/s; memory beyond the node's memory), each with 30 s of slack | counted up to that bound only |
| a value beyond 2^53 | taken as 2^53 |
| the first report of a sandbox made in the time the meter counts | counted from zero, up to what the time the meter has counted allows (not what the run time the node reports would) |
| a sandbox reported with another tenant than the API made it for, or than it was first seen with, or from another node, or of a tenant not in the configuration | ignored (and logged) |
| an ended sandbox listed again, or a `seq` not past the last one taken | ignored |
| a node whose `boot` changed (it restarted, its sandboxes died) | its sandboxes are ended (`lost`) with what was counted, and its ended sandboxes are asked for from the first again |
| a sandbox its node has not listed, live or ended, for 60 s while it answered | the same; if the node lists it again, it is counted on from where its counters stood |

Each of these counts in `odd_reports` (admin). A node that lies can
therefore add to its own tenants' usage at most what its hardware could
have done, and nothing to a sandbox it does not run; a node that does
not answer adds nothing, and what its sandboxes did meanwhile is counted
when it answers again (counters are cumulative). A sandbox that ends
between two probes is counted by its final counters from the node's list
of ended ones. A sandbox first seen made before the time the meter
counts (the period's start; without a log, also this API's start) is
counted from its first report on.

*The usage log.* `metering.log` is a path prefix: the records of the
period that starts at `S` go to `PREFIX.YYYYMMDDTHHMMSSZ.jsonl` (`S` in
UTC), then `.1.jsonl`, `.2.jsonl`... once a file holds `max_file_mb`
(256). Files are only appended to; old periods' files are the operator's.
One JSON object per line:

```json
{"v":1,"kind":"usage","ts":1794963600123,"period":1794960000,"tenant":"acme",
 "sandbox":"sb-...","node":"node-1","template":"python",
 "delta":{"run_ms":60000,"cpu_ms":1520,"memory_byte_seconds":2516582400,"egress_sent_bytes":812,"egress_received_bytes":40213,
          "ingress_received_bytes":1204,"ingress_sent_bytes":88410},
 "total":{"run_ms":180000,"cpu_ms":4210,"memory_byte_seconds":7549747200,"egress_sent_bytes":812,"egress_received_bytes":40213,
          "ingress_received_bytes":3610,"ingress_sent_bytes":265230},
 "memory_bytes":41943040}
```

| `kind` | When | `delta` |
|---|---|---|
| `usage` | every `metering.interval` (60 s) for a sandbox that grew | what grew since its previous record |
| `final` | it ended; `end`: `ended` (its node said so) or `lost` | what grew since its previous record |
| `carry` | a period began, for every sandbox running | zero (`total` carries its counters into the new period) |
| `delete_pending`, `delete_done` | a delete waits for an unreachable node, and was done | none |
| `late` | ingress bytes counted after the sandbox's `final` record (its last connections ended as it did), or for one its node never reported (it ended before the next probe, a minute on) | those bytes; counted in the period's totals, nothing else |

`ts` is when it was made (Unix ms), `period` the start of its period (Unix
seconds), `total` the sandbox's counters as taken, `memory_bytes` its
memory at the last measurement. The `delta`s of a period's records add
up to the tenants' totals for it, and a sandbox's add up to its `total`
(tested). A writer thread appends once a second and syncs the file;
when it cannot (a missing directory, a full disk) the API serves on,
logs `usage log: cannot write ...` once and `usage log: writing again`
when it can, and the records wait in memory (100000 at most; past that
the oldest are dropped, logged and counted in the admin view's
`log.dropped`). The usage counted for quotas does not depend on the log.

*Restarts.* At start the API reads the current period's files (the
totals, the last counters of each sandbox, the deletes still to do) and
the previous period's (the last counters of sandboxes running across the
boundary), at most `max_read_mb` (1024) in all: beyond it, it logs an
error and its totals are short. A line that is not a record (one cut
short by a crash: the next record starts a new line) is skipped and
counted. Then every sandbox goes on from its logged counters, so what it
used while no API ran, and in the last interval before the restart (not
yet written), is counted once when the API sees it again; an ended
sandbox with a final record is not counted again when its node lists it
(tested). Without a log a restarted API starts the period's totals from
zero and counts every running sandbox from its first report.

*Quotas.* Per tenant, all optional:

| Field | Limit | Checked | Past it |
|---|---|---|---|
| `max_sandboxes` | sandboxes at once | create, under one lock with the next | `429 tenant_limit` |
| `max_memory_mb` | the memory limits of its sandboxes, summed | create, under the same lock, creations in progress included (with the largest limit any node reports for the template, the node not being chosen yet; when the sandbox made has a larger limit than that, or no node had reported one, the check is made again with the real limit and the sandbox is removed if the tenant is over) | `429 memory_limit` |
| `requests_per_second`, `request_burst` (default two seconds' worth, at least 10) | requests: a token bucket per tenant | every request with the tenant's token | `429 rate_limited`, `Retry-After` |
| `cpu_seconds_per_period` | CPU time of its sandboxes in the period | creating a sandbox, starting an exec (`exec`, `execs`) | `429 budget_exceeded`, `Retry-After` until the period ends |
| `egress_bytes_per_period` | egress bytes, sent and received, in the period | the same | the same |

`metering.period` is a number of seconds (default 86400), aligned to
multiples of itself since the Unix epoch, so a day is a UTC day and the
budgets start again at midnight UTC; or `"month"`: calendar months in
UTC, from the first of each month at 00:00 UTC to the next (28 to 31
days). Everything follows the period's real bounds: the usage answers
(`period.start`, `end`, and `seconds`, the length of this month),
`Retry-After` of `budget_exceeded` (to the end of the month), the log's
file names (`PREFIX.20261101T000000Z.jsonl` for November 2026), the
`carry` records at the boundary, and the files read back at start-up (the
current month's and the previous one's, tested). A tenant over a budget gets no new sandbox and no
new exec; everything else works (reads, lists, polls, cancels, files,
resetting the interpreter, deletes), and what runs is not stopped: a
long exec or a busy background process can take a tenant past its
budget, by up to what it does before it ends (budgets are measured, not
enforced in the guest). Usage reaches the API within about a second plus
`reconcile_interval`, so a tenant can also go past a budget by what it
does in that time. A budget of 0 refuses all new work.

The rate limit is checked after the token and before anything else:
a request without a valid token takes nothing from any bucket (it is a
`401`), and a tenant over its rate gets `429` at once, without waiting
and without touching a node, so one tenant's burst costs the others
nothing (tested: another tenant's requests are all answered at once
while one is refused). Every request counts, polls included.

A tenant reads its own usage with `GET /v1/usage`:

```json
{"tenant": "acme", "period": {"start": 1794960000000, "end": 1795046400000, "seconds": 86400},
 "usage": {"run_ms": 7260000, "cpu_ms": 41250, "memory_byte_seconds": 302003200000,
           "egress_sent_bytes": 18233, "egress_received_bytes": 9120344,
           "ingress_received_bytes": 4096, "ingress_sent_bytes": 1048576},
 "sandboxes": 2, "memory_limit_bytes": 2147483648,
 "quotas": {"max_sandboxes": 10, "max_memory_bytes": 8589934592, "requests_per_second": 50.0,
            "request_burst": 100, "cpu_seconds_per_period": 36000.0, "egress_bytes_per_period": 10737418240,
            "max_ingress_connections": 128},
 "exceeded": []}
```

and operators everyone's with `GET /admin/v1/usage`, which also shows
the log's state.

*Deleting a sandbox of an unreachable node.* The delete is accepted
(`202`): the sandbox stops counting against the tenant at once (its slot
and memory are free), is listed no more, and answers `404`. The API
keeps it among the deletes to do (at most 4096 per node; past that the
delete answers `502 node_unreachable` as before) and writes a
`delete_pending` record to the usage log before it answers (when the log
cannot be written, the record waits in memory like any other, and the
delete is still accepted). When the
node answers a probe again, the API deletes it there (`delete_done`); a
sandbox whose node no longer lists it needs nothing more. The node's
list does not bring it back meanwhile: the reconciliation leaves out
sandboxes with a delete to do (tested). It runs on the node until then
(its idle timeout and lifetime still apply), but from the moment the
delete is accepted what it uses is not its tenant's: what it used up to
the last report before the delete is counted (and recorded, in a `usage`
record written with the `delete_pending` one), and from then on its
node's reports move its counters without charging anything, until its
`final` record (whose `delta` is what was counted before the delete and
not yet recorded, usually nothing). Since the API cannot know when
within the time its node did not answer the sandbox used what, the time
between the last report and the delete is not charged either: a tenant
pays at most for less than it used, by what one sandbox does in the time
its node was unreachable before the delete. An API that restarts before
the node is back reads the deletes to do back from the log and does them,
and knows from the `delete_pending` record that the sandbox is not to be
charged, also when the delete was done but its final report not yet
taken (tested, with a sandbox burning CPU from before its delete to after
its node was back: nothing of it charged). Without a log it does not
know of them, and the sandbox shows again (and counts) once the node
answers, until its tenant deletes it again or its idle timeout ends it.

*Configuration.* `metering`: `period` (seconds, 1 to 366 days, default
86400; or `"month"`), `log` (none: no log), `interval` (seconds between records of a
running sandbox, 1 to 86400, default 60), `max_file_mb` (256),
`max_read_mb` (1024). Per tenant: `max_memory_mb`,
`requests_per_second` and `request_burst`, `cpu_seconds_per_period`,
`egress_bytes_per_period`. In `noded`'s: `egress_stats` (`socket`, and
`token` or `token_file`: the proxy's `--stats-token-file`; the socket
may not be in the egress socket's directory).

Rejected: *a log per node* (each `noded` would need durable storage, and
the usage of a tenant would have to be gathered from every host to
check a budget); *a database* (the decision for now: metadata stays in
memory, and the log is the API's only durable state); *counting egress
in the kernel process* (it is the process a guest attacks, and it would
need a new channel to `noded`); *stopping a tenant's running sandboxes
or execs at its budget* (work would be lost at an arbitrary point; new
work is what the budget refuses); *429 for budgets from the HTTP layer's
per-address limit* (an address is not a tenant); *a rate limit before
authentication* (unauthenticated requests would spend a tenant's
budget); *weeks or other calendar periods* (seconds and months are what
billing needs; another kind is a variant of `Periods` in `meter.rs`).
For a delete on an unreachable node, rejected: *charging until the node
deletes it* (the tenant asked for it to stop; that the node did not
answer is the operator's problem, and a node that is down for an hour
would bill an hour of a sandbox nobody may use), *sharing the unknown
time pro rata* (the counters are cumulative; any split of the gap is a
guess, and a guess in the tenant's disfavour is the wrong default).
Not exact: with several API instances each would count its own rate and
reservations (one API is assumed, as for scheduling); usage is sampled,
so a budget can be passed by what a tenant does in about two seconds,
and by work that was running.

**Ingress.** An HTTP client outside reaches a server listening in a
sandbox at `PORT-SANDBOX.DOMAIN`, once the sandbox's tenant has exposed
that port (`kernel/api/src/ingress/`). HTTP/1.1 only, WebSocket and other
upgrades included; TLS is the reverse proxy's in front of the listener
(no TLS code here).

```sh
curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://127.0.0.1:7070/v1/sandboxes/sb-.../ingress/ports/8000
  -> {"token": "...", "ports": [{"port": 8000, "public": false, "url": "https://8000-sb-....sandbox.example.com/"}]}
curl -s -H "Authorization: Bearer $TOKEN" -d '{"command": "nohup python3 -m http.server 8000 >/dev/null 2>&1 &"}' \
  http://127.0.0.1:7070/v1/sandboxes/sb-.../exec
curl -s -H "X-Hellovm-Ingress-Token: ..." https://8000-sb-....sandbox.example.com/
```

*The path of a request.* The ingress listener (`ingress.listen`) is the
API process's own, apart from the tenants' and the operators'. For each
connection it reads the request head (32 KiB at most, within
`head_timeout`), takes the port and sandbox from `Host`, finds the
sandbox's node in the store, checks that the port is exposed and the
token unless the port is public, takes a connection slot, and asks the
node `POST /v1/sandboxes/{id}/ingress/connect?port=P` (node token,
tenant). `noded` checks the port again, counts the request as use of the
sandbox, answers `200` and then hands that TCP connection itself (the fd,
by `SCM_RIGHTS`) to the sandbox's kernel process over the clone's ingress
channel, and is done with it. The kernel process queues it on the guest's
listener (see **Networking**) and writes the verdict byte; the API reads
it, sends the rewritten request head, and relays the rest as bytes until
the exchange ends. So bytes go client, TLS proxy, API, kernel process,
guest: `noded` is on the path only for the hand-over, and holds nothing
per connection.

*Host names.* `PORT-SANDBOX.DOMAIN`, case-insensitive, an optional
`:PORT` of the listener after it: `PORT` 1 to 65535 in decimal without a
leading zero, `SANDBOX` a sandbox id exactly (`sb-` and 32 lowercase hex
digits), `DOMAIN` exactly `ingress.domain`, nothing else (no trailing dot,
no further label). Anything else is `404`. The wildcard name
`*.DOMAIN` points at the reverse proxy, whose certificate covers it. Use
a domain of its own, not one under the API's or any other site's: every
sandbox is a site under it, and its guests write the pages. Better still
list it in the Public Suffix List, so that browsers keep one sandbox's
cookies from another's (see the cookie below for what is done without it).

*The token.* Every sandbox has an ingress token (64 hex digits, random,
made with the sandbox on its node, kept there in memory with the exposed
ports, rotated by `POST .../ingress/token`). A request to a port that is
not public must carry it, in one of three ways:

* the header `X-Hellovm-Ingress-Token: TOKEN` (programs);
* the cookie `hellovm_ingress_token` (`__Host-hellovm_ingress_token`
  when `ingress.scheme` is `https`), which a browser gets by opening the
  URL once with `?hellovm_ingress_token=TOKEN`: that request is answered
  by the ingress itself with `303 See Other` to the same URL without the
  parameter (a path that begins with `//` or `/\`, which a browser would
  take for another host, is made to begin with one `/`) and `Set-Cookie: ...; Path=/; HttpOnly; SameSite=Lax`
  (`; Secure` over `https`). The parameter is taken only on `GET` and
  `HEAD` (`400` otherwise) and never forwarded. The cookie is host-only
  (one port of one sandbox), `HttpOnly` keeps the guest's own pages from
  reading it, and the `__Host-` prefix keeps another sandbox's guest from
  setting one for this host with `Domain=`; every value of the cookie
  that a request carries is tried (at most 16), so one forged by another
  site still cannot hide the right one;
* (a public port needs none).

The token is compared in constant time, never logged and never forwarded:
the header and the cookie are removed from the request the guest gets,
and a cookie of that name the guest sets is removed from its answer. A
rotated token works at once; connections already made go on.

*Answers of the ingress itself*, a short text body and `Connection:
close`:

| Status | When |
|---|---|
| `400` | a malformed request head (below), the token parameter on a method other than `GET` or `HEAD`, or given twice |
| `404` | a `Host` that is not one of the names above; no such sandbox, or one that ended or was deleted; a port that is not exposed; no token or a wrong one; a sandbox whose node cannot be asked and of which nothing is known yet. One answer for all, byte for byte: who does not have the token learns nothing, not even that the sandbox exists. |
| `408`, `431` | the head did not arrive within `head_timeout`, or is larger than 32 KiB |
| `303` | the token parameter, with the right token (above) |
| `502` | (with the right token, or to a public port) the sandbox's node is unreachable or the hand-over failed, nothing listens on the port in the sandbox, or the guest's answer is not HTTP |
| `503` | (likewise) the sandbox's or the tenant's connections are at their limit, `Retry-After: 1`; or the listener's (before anything is read) |
| `504` | the guest did not answer within `idle_timeout` |

"Another tenant's sandbox" does not arise at this listener, which has no
tenant: a client has a sandbox's token or does not. The tenant endpoints
(`GET`, `PUT`, `DELETE .../ingress...`) answer another tenant's sandbox
with `404 sandbox_not_found`, like every other endpoint. The API keeps
what each sandbox's node says of its ingress (filled on first use and on
every change made through the API, forgotten with the sandbox), so that
it can check a token while the node does not answer: then a request with
the right token (or to a public port) is told `502`, and one without the
same `404` as for no sandbox at all. What it cannot know (an API that
restarted while the node was down) is `404` until the node answers.

*Request heads* must be strict HTTP/1.0 or 1.1, or are refused (`400`)
before anything reaches a node or the guest: CRLF line ends only, no
control byte in a value but tab, header names of token characters directly
followed by `:`, no folded lines, at most 100 headers, a request target in
origin form (`/...`, no absolute form, no `*`), exactly one `Host`; at
most one `Content-Length` (digits only) or one `Transfer-Encoding`, whose
value is exactly `chunked` (not in an HTTP/1.0 request), never both; a
`Connection` that names `Host`, `Content-Length`, `Transfer-Encoding` or
`X-Forwarded-For` is refused. That leaves one reading of where a body
ends, which is the one the ingress follows: it forwards exactly
`Content-Length` bytes, or a chunked body up to its last chunk and
trailers (its chunk sizes, extensions and trailers checked and bounded as
they pass; it is relayed unchanged), and nothing after it. A second
request smuggled after a body's end, or pipelined, never reaches the
guest.

*What the guest gets.* The request line and headers as sent, except:
hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`,
`Trailer`, `Upgrade`, `Proxy-Authorization`, and those `Connection`
names) dropped; hellovm's own credentials removed: the token header and
cookie, every `X-Hellovm-*` header, and an `Authorization` header whose
credentials are any token of hellovm's (a tenant's, a node's, the
admin's, or the sandbox's ingress token); `Forwarded`, `X-Real-IP` and
the client's `X-Forwarded-*` dropped and replaced: `X-Forwarded-For` (the
client's address; with `behind_proxy`, the proxy's list with the proxy's
address appended), `X-Forwarded-Proto` (`ingress.scheme`; with
`behind_proxy`, the proxy's when it is `http` or `https`) and
`X-Forwarded-Host` (the `Host`); and `Connection: close` (or `Connection:
Upgrade` with the `Upgrade` header, for an upgrade). The answer's head is
checked the same way (a guest's answer that is not HTTP is a `502`),
hop-by-hop headers dropped (but not its framing), the token cookie
removed, `Connection: close` added; 1xx answers are passed on as they
come (at most 16), and the body is relayed by its framing (none for
`HEAD`, `204` and `304`; `Content-Length`, chunked, or to the guest's
end).

*One exchange per connection.* After the answer the connection ends
(`Connection: close` both ways); a client opens a new one for the next
request, and each is a new hand-over and a new connection in the guest.
Rejected: *keep-alive* would need the ingress to know where every answer
ends (chunked, `Content-Length`, `HEAD`, 1xx, a guest that gets it
wrong) to read and check the next request on the same connection, and
then to send it on the same guest connection, where a guest that
misframes its answer desynchronizes the pairs; one exchange per
connection costs a connection per request, and nothing can ride on a
checked one. Browsers open more connections and are fine with it.
Measured in `ingress.rs` (debug build, Docker Desktop on an Apple M3
Max, loopback, Python's `ThreadingHTTPServer` in the guest): a `GET`
from the client's connect to the end of the answer takes 2.1 ms
(median of 50, 1.9 to 3.8 ms), all of it new connections, the hand-over
and the guest's server; 32 MiB of answer take 0.39 s (about 80 MiB/s,
the API's relay and the kernel process's stream both in debug builds).

*Upgrades.* A request with `Connection: Upgrade` and one `Upgrade` is
forwarded with them; if the guest answers `101`, both directions are
then relayed as raw bytes, each half-closed when its side ends, until
both have or a deadline passes. A `101` to a request that asked for no
upgrade is a `502`.

*Bodies* of any length stream both ways, at most 16 KiB held per
direction in the API (and 64 KiB each way in the kernel process), with
back-pressure: a client that does not read slows the guest's writes, and
the other way round.

*Deadlines and limits* (`ingress` in the API's configuration):

| What | Default | Past it |
|---|---|---|
| The request head | 32 KiB, `head_timeout` 10 s | `431`, `408` (a client that sends nothing is closed without an answer) |
| The node's hand-over and the verdict | connect 5 s, answer 10 s | `502` |
| No byte either way | `idle_timeout` 60 s | `504` if the guest has not answered yet, else the connection ends |
| A connection in all | `max_duration` 3600 s | it ends |
| Connections at once | `max_connections` 512 in all, `max_connections_per_client` 64 from one address (not counted with `behind_proxy`), `max_connections_per_tenant` 128 (or the tenant's `max_ingress_connections`, at most that), `max_connections_per_sandbox` 32 | `503` |
| Requests to a node in progress (hand-overs, and questions about a sandbox's ingress state) | 64 per node at once (each holds one of the node's 256 HTTP connections for its moment, so the node's probes always find one), of which at most 16 for one tenant's sandboxes and 8 for one sandbox (a sandbox whose kernel process is slow to answer holds up its own share, not the other tenants') | `503` |
| Questions about one sandbox's ingress state (asked when the API does not know it yet) | one at a time per sandbox: requests that come meanwhile wait for its answer, and a question that failed is not asked again for 2 s | `404` when it fails |
| Exposed ports | 16 per sandbox | `409 too_many_ports` |
| Bytes held | 16 KiB per direction per connection in the API | back-pressure |

Every read and write waits at most a second before the deadlines are
looked at again, so a client or guest that is slow or silent holds a
connection only until one of them passes. Each connection has two
threads in the API (one per direction), so at most twice
`max_connections` threads, and none in `noded` after the hand-over; the
listener's slots are taken before anything is read and given back when
the connection ends, the per-tenant and per-sandbox ones only once the
request was found to be allowed (a client without the token cannot use
up a tenant's slots; one with it, or anyone for a public port, only that
sandbox's and tenant's). No lock is held across any I/O: the slot
counters, the ingress cache and the byte counters are each taken for a
moment. With the defaults a tenant may hold a quarter of all connections
(128 of 512; keep `max_connections_per_tenant` below `max_connections`),
so one tenant's load cannot take every connection; before authentication, a client is
bounded by its address's limit and the head timeout. Behind a reverse
proxy, all connections come from it: set `behind_proxy` (the per-address
limit is then not applied; limit per client in the proxy). Ingress
requests do not take from a tenant's `requests_per_second` bucket (its
API requests are what that limits), and a tenant over a budget still
serves through ingress what runs (budgets refuse new work only).

A failed or timed-out ingress request never counts against its node's
health (the hand-over is not one of the requests that can mark a node
unreachable): a sandbox that does not listen, or answers slowly, is the
sandbox's business; the probes find a node that stopped answering.

*Use and idle timeouts.* Ingress is use of the sandbox: each hand-over
restarts its idle timeout on the node, and a connection that moves bytes
(a WebSocket, a long download) marks its sandbox as used at most once a
second; the probe of each node (every `reconcile_interval`) then tells it
`POST /v1/node/touch` with those sandboxes. A sandbox in use through
ingress therefore stays (tested with only bytes on one upgraded
connection for twice its idle timeout); its lifetime still applies.

*Metering.* The API counts the bytes it relays, per connection, as they
are written: `ingress_received_bytes` (delivered to the guest: the
rewritten head, the body) and `ingress_sent_bytes` (delivered to the
client from the guest: the rewritten answer head and the body); not the
ingress's own answers, nor TLS or TCP framing. The guest cannot change
them (they are not reported by anything in the sandbox, its kernel
process included), and a node cannot either (a node's report of them is
ignored). Once a second they are added to the sandbox's counters (in its
`usage`, in `GET /v1/sandboxes[/{id}]`), its tenant's totals (`GET
/v1/usage`) and the usage log's records like the other counters. There is
no per-period ingress budget.

*Why in the API process, and how it scales.* The API already knows which
node runs each sandbox, whose it is and whether the node answers, and it
already meters: ingress there needs no new service, configuration or
channel, and its bytes are counted where they are added up. With several
nodes one listener reaches all of them (it connects to the sandbox's node
for each connection, tested with two); the bytes pass through the API
host, which is the cost. To scale past one API host, the ingress part can
run as a separate process of the same binary next to it (it needs the
store's sandbox-to-node map and the nodes' tokens), or move to each node
with the reverse proxy routing by sandbox, once the store is shared
(several API instances are not supported yet, see **Scheduling**).
Rejected: *a separate `ingress` binary now* (a second copy of the store
and of the nodes' health, kept in step over a new channel, for one host);
*`noded` relaying the bytes itself* (two copies on the node and two
threads per connection there, where the fd hand-over costs none);
*a Unix socket in the filesystem per sandbox for its kernel process to
accept on* (a path every kernel process of the node could see, or a
directory per sandbox mounted into its namespace: the ingress channel is
an fd passed with the clone request, reachable by nothing else);
*passing the client's connection into the sandbox without the API in
between* (the API could not check the token, count the bytes or rewrite
the head); *a loopback peer address in the guest* (`127.0.0.1` would
make every outside client look local to servers that trust local
clients); *the token in the path* (it would be forwarded and logged by
the guest's server); *a cookie for the whole domain* (any sandbox's
guest would get every sandbox's tokens).

*Configuration.* In the API's file, `ingress`: `listen`, `domain`,
`scheme` (`https` or `http`, default `https`), `url_port` (the port in
the URLs answered, when not the scheme's own), `behind_proxy` (default
`false`), the limits and deadlines above. Per tenant:
`max_ingress_connections`. Without `ingress` nothing listens and the
ingress endpoints answer `404 ingress_disabled`; `noded` always keeps the
state (it costs a token and one socket pair per sandbox).

*Not done:* HTTP/2 and HTTP/3 (the reverse proxy can speak them to
clients and HTTP/1.1 here), raw TCP or UDP ingress, a port bound to
`127.0.0.1` only in the guest (it must listen on `0.0.0.0`), TLS between
the API and the nodes (see above), a per-period ingress budget, ingress
through an API that restarted while a sandbox's node is unreachable (it
does not know that sandbox until the node answers).

**Resource limits.** All clones of a template run in the template's
cgroup: a clone runs before whoever asked for it learns its pid. What
is enforced without root:

| Limit | How | Past it |
|---|---|---|
| Writable layer (`fs_limit_mb`) | the kernel process (`hellovm --fs-limit`, kernel state every clone inherits) | `ENOSPC` |
| Memory (`memory_limit_mb`) | `noded` sums the private memory (`RssAnon` + `RssShmem`) of the clone's kernel process and every process below it once a second, each address space once (`kcmp`), and removes the sandbox | the sandbox is removed; `410` with the reason |
| Processes and threads (`max_processes`, default and at most 4096) | the same scan counts the host processes below the clone's kernel process (a guest process or thread is one each) | the sandbox is removed; `410` with the reason |
| Time | per-exec `timeout`, idle timeout, lifetime | killed or removed |
| Tasks, sockets, outbound flows | the kernel (2048 tasks, 4096 sockets) and the egress proxy (64 flows per sandbox) | `EAGAIN` and the like |
| Inbound connections | the kernel process (256 open, 64 waiting to be taken) and the API's ingress (per sandbox, per tenant, in all: see **Ingress**) | refused (`502`, `503`) |
| Sandboxes | per tenant (API) and per node (`max_sandboxes`) | `429`, `503` |
| Memory of a tenant's sandboxes, requests, CPU time and egress per period | per tenant (API: see **Quotas and metering**) | `429` |

The scan runs on a thread of its own (idle timeouts and lifetimes do not
wait for it) and costs a binary search per process, `kcmp` ordering the
address spaces, so a sandbox with thousands of processes does not slow
it for the others. The memory measurement is a poll, not a limit: a sandbox can go over it
for up to a second (and so can the host's memory). It counts the
template's snapshot pages a clone has read but not written as its own,
so it overestimates by up to the snapshot's size (about 30 MiB) per
address space. The writable layer is in the kernel process's memory, so
it counts too. Not done, because it needs cgroup delegation (a cgroup v2
subtree the service user may write, e.g. from systemd's `Delegate=yes`):
hard memory limits, CPU shares and quotas, a pids limit per sandbox and
I/O limits. The way in is a step in the warm-clone protocol where the
clone's kernel process reports its pid and waits until `noded` has
moved it into the sandbox's cgroup before it rebuilds the app processes
(or `clone3` with `CLONE_INTO_CGROUP` in the template, given a cgroup fd
with the request).

**Shared templates or one per tenant.** A template is trusted more
than its clones: every clone starts from its kernel process's memory.
`noded`'s templates are the operator's (the agent, an image the
operator controls, modules named in the configuration), so one template
is shared by all tenants by default. That is safe only because each
clone's kernel process gets a Landlock domain of its own (see **Warm
clones**), so a shared template (no `tenant` in its configuration)
always runs with `--sandbox require`, which refuses to start it on a
host without Landlock. On such a host, or for a template built from a
tenant's own image or code, give the template a `tenant`: only that
tenant's sandboxes are made from it (the API shows it to no one else,
and `noded` refuses other tenants), and it may run with `"sandbox":
"best-effort"`. Per-tenant templates cost a template process and its
snapshot per tenant and template, and for real separation each tenant's
`noded` and templates should run as a uid of their own.

**Hardening of the services.** Every byte from a caller or a sandbox is
untrusted. HTTP: a request head of at most 16 KiB in 10 s, at most 64
headers, CRLF only, no folded headers, `Content-Length` only (no
`Transfer-Encoding`), bodies limited per route (4 MiB of JSON, 16 MiB
for a file) and to 256 MiB across all connections being read at once,
read within 60 s, at most 256 connections (one thread each; the next
gets `503`), 30 s idle between keep-alive requests. A connection takes
its slot before anyone has authenticated, so the API serves at most
`max_connections_per_client` (default 128: following an exec holds a
connection per sandbox) from one IP address at once
(`429` past it; behind a reverse proxy, raise it and limit there), and a
response must be taken within 30 s plus its length at 64 KiB/s, or the
connection is closed. Both services check at start that their open-file
limit covers what their configuration can use (`noded`: five per sandbox
of `max_sandboxes`, plus connections and templates), raise the soft
limit if that is enough, and refuse to start otherwise. JSON with unknown
fields is refused. The agent channel: see above. Logged text from a
sandbox is bounded per line and per sandbox. An exec's held output is
bounded by its `max_output` (at most 1 MiB): the result's two streams
and the stream read with a cursor hold 4 × `max_output` at most, and a
sandbox keeps one exec, so a node holds at most 4 MiB per sandbox for
output (256 MiB with 64 sandboxes all at the largest `max_output`).
Polls wait at most 30 s, cancels 5 s. Neither service dials an
address a sandbox chose: `noded` connects only to its templates'
sockets, the API only to its configured nodes; ingress reaches a guest
only as an inbound connection to the sandbox its validated `Host` names,
over that sandbox's ingress channel, never through a host socket of the
guest's choosing. The ingress listener's own bounds are in **Ingress**.
`noded`'s HTTP server may hand a connection over after its answer (the
ingress hand-over), only when the client sent nothing past its request.

**Dependencies.** `serde` and `serde_json` (with their derive macro's
`syn`, `quote`, `proc-macro2`, `unicode-ident`, and `itoa`, `memchr`,
`ryu`): the JSON of both APIs. Nothing else: the HTTP server and client
are about 800 lines of strict, bounded code in `hellovm-control`, and
one thread per connection (at most 256) is enough at this scale. Streamed
execs and the stateful interpreter add no dependency (the agent uses
only Python's standard library).
Rejected for now: `tokio` with `hyper` or `axum` (dozens of crates and
an async runtime for what a thread pool does), a hand-written JSON
parser.

**Tests.** `kernel/api/tests/control_plane.rs` runs the whole plane on
the host: an egress proxy in the test process whose test name table
points `web.test` at a local HTTP server, `hellovm-noded` with a CPython
template of the host's `/` (shared when the host has Landlock, else one
per tenant, with a note), and `hellovm-api` with two tenants, all
talking HTTP on loopback. It covers authentication, create, `exec`
(exit codes, stderr, stdin, cwd, env, timeouts, truncation, Python in the
warm interpreter), streamed execs (output before the end, stdout and
stderr told apart and in order, a cancel from another connection while a
poll waits, which kills the exec's background children and leaves the
sandbox usable, a client gone mid-poll, a late reader of far more output
than is held, a timeout while streaming, a request/response exec
cancelled from another connection, bad polls and unknown execs, tenant
isolation of every new route, a delete under a running exec), the
stateful interpreter (variables and imports kept, values, tracebacks,
stdin, interrupted on cancel and on timeout with its state kept, killed
when it cannot be interrupted, ending by itself, reset, separate per
sandbox and tenant and from the fresh-fork mode, its memory counted),
state between execs, read, write and edit (binary
data, missing files, directories, ambiguous and missing edits), the
writable layer's limit, outbound HTTP through the proxy with the
sandbox's id in the audit line and a refused name, one request at a
time, tenant isolation for every endpoint, the tenant limit, delete,
idle timeout, lifetime, the memory limit, a template killed and
restarted, `noded` killed and restarted with stale sockets, the API
restarted with sandboxes running, and a clean shutdown.
`kernel/api/tests/scheduling.rs` runs three `noded`: creates spread by
load, a full node skipped, draining and undraining (sandboxes on a
draining node used and deleted), templates that only one node has, the
tenant limit under 20 concurrent creates, a killed node marked
unreachable (its sandboxes' `502`, which names nothing of the node,
another tenant's `404`, creates elsewhere), the API restarted with all
nodes up and with one down, the node back and the state converged, the
admin API refusing no token, tenant, node and wrong tokens (and absent
from the tenants' listener), and fake nodes answering garbage, a
terabyte `Content-Length`, an endless body, another node's name,
absurd numbers, nothing at all, or nonsense refusals of every create,
with the API's memory under 64 MiB after. `kernel/api/tests/quotas.rs`
(8 tests, about 30 s, its plane's periods 15 s long): CPU and egress budgets used
up by real work and refused at create and exec (with `Retry-After`)
while reads, polls, cancels, files, resets and deletes work and a
running exec ends normally, another tenant untouched, and both back at
the next period; the memory quota under 12 concurrent creates (exactly
three made); the rate limit (a burst refused, another tenant's 50
requests all answered at once, 90 requests without a valid token taking
nothing from the bucket); the usage log while its directory is missing
and once it exists, its records of a sandbox that ran, fetched through
the proxy and ended (the deltas adding up to the final counters, CPU,
memory and egress counted), and an API restart mid-period (the totals
unchanged, nothing counted twice); a fake node reporting absurd,
decreasing and out-of-range counters, a sandbox claimed for another
tenant and an ended one listed again; a fake node that restarts (its
ended sandboxes asked for from the first again); the delete of a sandbox on a
stopped (`SIGSTOP`) node, its slot used at once, an API restart before
the node is back, and the delete done then, the sandbox never listed
again; and a node configured to start drained, undrained and restarted.
`kernel/api/tests/ingress.rs` (4 tests, about 30 s; a Python HTTP
server in each sandbox, real `noded` processes): the token required by
default (missing, wrong, another sandbox's, in the header, the cookie and
the query parameter's redirect, all refusals the same `404` as an unknown
sandbox, an unexposed port, a bad name), a public port, an exposed port
nothing listens on (`502`), another tenant's sandbox at both the
listener and the API, what reaches the guest (no token, no hellovm
cookie or `Authorization`, no hop-by-hop header, the forwarding headers)
and what reaches the client (no forged token cookie), 8 MiB up chunked
and by length (checked by SHA-256 in the guest) and 32 MiB down, an
upgrade with bytes both ways and its half-close, a `101` to a plain
request, hostile heads (conflicting `Content-Length` and
`Transfer-Encoding`, two lengths, two encodings, two `Host`s, folded
lines, bare LFs, an absolute target, 40 KiB of head, bad `Host`s) and a
request smuggled after a chunked body or pipelined after a body, none of
which reach the guest (its request log is read back), a head that
arrives in pieces, rotation and unexposing taking effect at once, the
port limit, ingress bytes metered for the sandbox and the tenant (and not
the other tenant); a sandbox kept from its idle timeout by bytes on one
upgraded connection and removed when they stop; the deadlines (a slow
head `408`, a silent client closed, a guest that does not answer `504`,
a client that stops in its body, `max_duration`) and the limits (per
sandbox, per tenant, another tenant unaffected, the node still healthy);
and two nodes behind one listener, one stopped (`SIGSTOP`): its
sandboxes `502` with the token and `404` without, the other node's
served, and back when it is. `quotas.rs` also covers months
(`period.start` and `end` on the first of two months, `Retry-After` to
the month's end, the month's log file, totals after a restart) and the
delete of a sandbox on a stopped node charging nothing of what it burns
afterwards (it fails, charging 14 s of CPU, without the change).
`kernel/hellovm/tests/warm.rs` runs a clone serving TCP through its
ingress channel: refused for no listener, a loopback-only one and port 0,
both ways with the opener's FIN and the guest's half-close, the peer
`192.0.2.1`, a megabyte to a slow reader, twenty at once, a connection
queued when its listener closes, and one open when the sandbox ends. The
kernel's unit tests (`hellovm-core`, against the mock host) cover the
same and the limits: backlog, listener closed, 256 open at once, the
sandbox's end; `hellovm-host` the verdict bytes, half-close and the
queue's bound. `kernel/api` has unit tests
for the host names, the strict parsing of request and response heads
(smuggling attempts among them), the rewriting of both, tokens in the
header, cookies and query, chunked bodies in any pieces and their bounds,
the ingress counters in the meter, calendar months (leap years, the
year's end) and a deleted sandbox charged nothing more (across a rebuild
from the log), for the health state machine, the placement rule (order, ties, spread of
creations in flight, full, draining, unreachable and foreign
templates), checking reports, its configuration, the meter (counters
that go down or jump, tenants and nodes that change, period roll-over
and carry, sandboxes first seen, lost and ended, rebuilding from the
log), the log (rotation by size, bounded reads, cut and long lines, a
log that cannot be written and its bounded backlog), the rate limiter,
and the store's memory reservations and deletes to do. `kernel/egress`
tests the per-process counters (bounded table) and the stats socket's
token; `kernel/noded` parsing `/proc/PID/stat` and CPU time.
`kernel/noded` has unit tests for the agent protocol (against the
host's Python: execs, output frames, cancel, the stateful interpreter's
state, interrupt, kill, end and reset), the frame parser (frames in any
pieces, lengths over the bounds, frames when none may come), checking
exec answers, the output buffers (head and tail, cursor reads, what a
late reader is told, UTF-8 characters not split between reads),
configurations, memory measurement and stale sockets; `kernel/control`
for HTTP parsing and limits, exec requests and poll queries.

**Measurements.** `cargo test --release -p hellovm-api --test
control_plane bench_create_and_exec -- --ignored --nocapture`: the plane
above, 30 sandboxes one after another, each created, used and deleted
through the API over loopback HTTP. Same machine and setup as the
**Warm clones** numbers (release build, Apple M3 Max, Docker Desktop
aarch64, default seccomp profile), medians with the range:

| | Debian bookworm (CPython 3.11) | Ubuntu 26.04 (CPython 3.14) |
|---|---|---|
| **Create, request to ready** (through the API) | **9.7 ms** (5.1–12.7) | **9.8 ms** (7.9–12.9) |
| of that, on the node (clone request to the agent's greeting) | 9.3 ms | 9.4 ms |
| `exec` of `echo hi` (`/bin/sh -c`) | 11.4 ms (7.6–16.0) | 14.5 ms (11.8–17.7) |
| Create and first `exec`, together | 21.0 ms (12.8–28.3) | 24.8 ms (19.7–29.1) |
| `exec` of Python (`json.dumps`, in a fork of the warm interpreter) | 5.6 ms (3.8–7.0) | 4.7 ms (3.8–5.6) |
| **Streamed exec, request to first output** (`echo hi`: start, then a poll) | **9.5 ms** (5.7–12.3) | **10.4 ms** (8.9–11.7) |
| Stateful Python, first call (starts the interpreter) | 11.5 ms (5.7–20.5) | 7.8 ms (4.5–9.3) |
| **Stateful Python, a call** (`x += 1; x`, round trip) | **1.5 ms** (0.9–2.3) | **2.0 ms** (1.7–2.8) |
| `write_file` / `read_file`, 5 bytes | 1.1 / 1.1 ms | 1.3 / 0.8 ms |
| `delete` | 0.3 ms | 0.3 ms |
| For comparison: a cold `hellovm --root / python3 -c 'import json; ...'`, start to exit | 60.5 ms | 48.2 ms |

These were measured with streaming in place (every exec's output now
goes from the agent to `noded` as it comes, and the watch thread hands
answers to the request's thread), on a host under some load (a load
average of 3): the earlier numbers of this table (8.3 / 7.1 ms to
ready, 10.6 / 12.9 ms for `echo hi`, 4.9 / 3.7 ms for Python, 0.8 ms
for a small file) are inside these ranges, and repeated runs differ by
up to a third; what is new costs at most a few tenths of a millisecond
per request (the hand-off between threads). A streamed exec's first
output comes sooner than a request/response `exec` answers, which waits
for the end. A stateful call is the fastest way to run Python: no fork,
only the call's frames.

The template preloads `json`, `decimal`, `hashlib`, `sqlite3` and
`urllib.request`. A shell `exec` costs more than a Python one because
`/bin/sh` is forked from the agent (a CPython process of about 30 MiB
of mappings) and then executed, both emulated; a Python `exec` is only
the fork.

*Request to ready* is from sending `POST /v1/sandboxes` to the API until
its `201`: the API's checks and placement, the node's clone request,
the clone's start, and the agent's greeting from inside the sandbox. The
first exec right after it is the earliest point a client sees its own
command's output.

## SDKs and MCP server

Programs drive sandboxes through the SDKs; models drive them through
the MCP server, which is built on the TypeScript SDK. All three use only
the public API above.

| Package | Path | |
|---|---|---|
| `hellovm` (Python) | `sdk/python` | Python 3.10+, standard library only, typed |
| `hellovm` (TypeScript) | `sdk/ts` | Node.js 20+, ESM with declarations, built-in `fetch`, no runtime dependencies |
| `hellovm-mcp` | `sdk/mcp` | MCP server on stdio, Node.js 20+ |

Version 0.0.1 each, not published. Each has a README with its whole
surface.

```python
from hellovm import Client

client = Client("http://127.0.0.1:7070", token)
with client.create() as sandbox:                       # deleted at the end of the block
    print(sandbox.exec("uname -a", timeout=10).stdout)
    sandbox.run("x = 21")                              # the stateful interpreter
    print(sandbox.run("x * 2").value)                  # '42'
    for event in sandbox.stream("make test", timeout=600):
        print(event)                                   # stdout/stderr as it comes, then the result
```

```ts
import { Client } from "hellovm";

const client = new Client({ baseUrl: "http://127.0.0.1:7070", token });
await client.withSandbox({}, async (sandbox) => {
  console.log((await sandbox.exec("uname -a", { timeout: 10 })).stdout);
  for await (const event of await sandbox.stream("make test", { timeout: 600 })) console.log(event);
});
```

The two SDKs have the same surface (snake_case in Python, camelCase in
TypeScript): a client from a base URL and a token; `create()` (a context
manager in Python, `withSandbox` or `await using` in TypeScript, both
deleting the sandbox however the block ends), `list`, `get`, `delete`;
`exec(command, timeout=...)`, `python(code)` (a fresh fork) and `run(code)`
(the stateful interpreter) returning a result with stdout, stderr, exit
code, signal, `timed_out`, `cancelled`, the truncation flags and byte
counts, and for stateful calls `value`, `error` (type, message,
traceback) and `state_lost`; `stream(...)` yielding output events as they
come and ending with the result, cancellable (from another thread in
Python, by `cancel()` or an `AbortSignal` in TypeScript); `read_file`,
`write_file`, `edit_file`; `reset_python`; for ingress `ingress()` (the
token and the exposed ports with their URLs), `expose(port, public=...)`
(the port with its URL), `unexpose(port)` and `rotate_ingress_token()`
(`rotateIngressToken` in TypeScript), with ports checked before anything
is sent and `409 too_many_ports` a `LimitError`. Errors carry the API's
status, code and message (`BusyError`, `SandboxEndedError` with its
reason, ...).

**Behaviour shared by both.** Every request has a deadline for the whole
exchange and a bound on the answer (32 MiB by default; heads 16 KiB), so
a server that stalls, trickles or sends too much costs a bounded wait and
buffer; the Python SDK has its own small HTTP/1.1 client for that
(`http.client` times out per socket operation, so a trickling server
holds it forever), the TypeScript SDK wraps `fetch` with an abort timer
and a capped body reader, and refuses redirects. A `409 busy` is waited
out with backoff until `busy_timeout` (120 s) by default, or raised at
once with `busy="raise"`. Requests are retried only where that cannot do
something twice: any request whose connection could not be made; after
a failure without an answer only idempotent ones (`GET`s, `DELETE`,
cancel), never create, exec, starting a stream, write, edit or reset,
which raise a transport error with `maybe_sent` instead; `503` until the
busy deadline; `429 too_many_polls` for polls; `429 rate_limited` after
its `Retry-After`, until the busy deadline. `429 budget_exceeded` is
raised at once as `BudgetExceededError` (with `retry_after`, the end of
the period), `rate_limited` past the deadline as `RateLimitError`; a
`DELETE` accepted for later (`202`) is a success; `client.usage()` reads
`GET /v1/usage`, and a sandbox's description has its `usage`. Streams are long polls
with the byte cursor: a dropped connection or a stalled poll resumes from
the cursor and loses nothing. The SDKs keep no exec id but the one they
started and are following (a sandbox keeps only its latest exec).

**The MCP server.** `sdk/mcp` (`node sdk/mcp/dist/server.js`, after
`npm ci && npm run build` in `sdk/ts` and then `sdk/mcp`) speaks MCP on
stdio. Configuration is by environment: `HELLOVM_URL` and `HELLOVM_TOKEN`
(required), `HELLOVM_TEMPLATE` (default `python`), `HELLOVM_IDLE_TIMEOUT`
and `HELLOVM_LIFETIME` (seconds; the API's defaults otherwise),
`HELLOVM_SANDBOX` (use an existing sandbox, never deleted by the server),
`HELLOVM_MCP_TIMEOUT` and `HELLOVM_MCP_MAX_TIMEOUT` (a call's default and
largest timeout, 60 and 600 s), `HELLOVM_MCP_MAX_OUTPUT` (bytes of each
stream and of a file shown to the model, 16384). The token is never
written to a tool result or the log (stderr); tool output is also
scrubbed of it. A client configuration:

```json
{"mcpServers": {"hellovm": {"command": "node", "args": ["/path/to/hellovm/sdk/mcp/dist/server.js"],
  "env": {"HELLOVM_URL": "http://127.0.0.1:7070", "HELLOVM_TOKEN": "..."}}}}
```

| Tool | Inputs | Result |
|---|---|---|
| `exec` | `command`, `timeout?` (s), `cwd?` | `Exit code: N` (or `Timed out after T s: the command was killed (signal 9).`), then stdout and stderr |
| `python` | `code`, `timeout?`, `restart?` | `Value: ...` or `Raised Type: message` with the traceback, printed output, and a note when the interpreter's state was lost |
| `read_file` | `path` | the text; a binary file is described, not shown |
| `write_file` | `path`, `content` | bytes written |
| `edit_file` | `path`, `old_text`, `new_text`, `replace_all?` | replacements made |
| `expose_port` | `port`, `public?` | the port's URL, and for a port that is not public how to send the ingress token (the header, or the URL with `?hellovm_ingress_token=` once in a browser) |
| `unexpose_port` | `port` | the port is not reachable any more |
| `reset_sandbox` | | a new, empty sandbox for the next call |

Output longer than `HELLOVM_MCP_MAX_OUTPUT` is cut by the API's own rule
(the first and last half, `[... N bytes omitted ...]` between) with a
line saying so; a file read follows the same rule. A non-zero exit code
or a Python exception is a result, not an error; a failure of the API
(no such file, an ambiguous edit, busy past the deadline, a sandbox that
could not be made) is a tool error (`isError`) with the API's code and
message; for a quota it adds what to do next (`budget_exceeded`: nothing
can be run until the period ends, in N s, files still work, do not
retry; `rate_limited`: wait N s; `tenant_limit`, `memory_limit`: another
sandbox must be deleted first). A cancelled MCP request cancels its command in the sandbox.

Decisions, and what was rejected:

* *One implicit sandbox per server process*, made on the first call that
  needs it and deleted when the server exits (stdin closes, `SIGTERM`);
  if the server is killed, the sandbox's idle timeout reclaims it. A
  model never handles ids, and one conversation's work stays in one
  place. If the sandbox ended (idle timeout, lifetime, memory), the next
  call gets a new one and its result starts with a note saying the old
  files and state are gone; `reset_sandbox` starts over on purpose.
  Rejected: *explicit create and delete tools with ids*, which a model
  must thread through every call and forgets to delete, for a use (many
  sandboxes in one conversation) that a program does better with the SDK.
* *The stateful interpreter for `python`*, not a fresh fork: a model
  works like in a notebook, building on earlier cells; `exec python3 -c`
  remains for a fresh process.
* *The official MCP TypeScript SDK* (`@modelcontextprotocol/server`
  2.4.0, with `@modelcontextprotocol/core` and `zod`: three packages). It
  implements the current revision (2026-07-28: stateless requests with
  their version and capabilities in `_meta`, `server/discover`) and
  still serves clients that open with the 2025 `initialize` handshake,
  which most clients do today; the tests speak both by hand. Rejected:
  implementing the protocol in the server (smaller, but two protocol
  eras and their error codes would be ours to keep right); the Python
  SDK's `mcp` package (pydantic, starlette, uvicorn, httpx and about
  twenty more packages, several with native code, for a stdio server).
  TypeScript is also where the server is shortest: tool schemas are
  `zod` objects and results come straight from the TypeScript SDK.
* *Text results*, the outcome first: what a model reads. No
  `outputSchema`/`structuredContent`: programs that want structure use
  an SDK.
* *Timeouts*: 60 s by default, 600 s at most per call (configurable up
  to the API's 3600 s), so a stuck command cannot hold the model;
  longer work goes to the background (`nohup ... &`) and is checked on.

Rejected for the SDKs: *server-sent events or a streamed response* (the
API has none; see **Why long polling for streams**); *depending on older
exec ids* (a sandbox keeps one); *an asyncio Python client* (it would
need its own HTTP layer or a dependency to keep the deadline and size
bounds; a thread per blocking call is enough for now); *`requests`,
`httpx`, `undici` or `axios`* (the standard library and `fetch` suffice
once bounded).

**Dependencies.** Python SDK: none. TypeScript SDK: none at run time;
`typescript` and `@types/node` to build. MCP server: the three packages
above, and the TypeScript SDK. The dev image (`kernel/dev/Dockerfile`)
adds Node.js 24 (the official build, checked against its SHA-256; Debian
bookworm's own is too old) for these tests.

**Tests.** `kernel/dev/run-sdk-e2e.sh` (from the repository root, after
`run-e2e.sh`) type-checks the SDKs (`mypy --strict` when mypy is found,
`tsc --strict` as the build), then runs `kernel/api/tests/sdk.rs`, whose
three tests each start a whole plane (the one `control_plane.rs` uses:
the real `hellovm`, `hellovm-noded` and `hellovm-api` with a warm CPython
template and two tenants) and run one suite against it. They are
`#[ignore]`d in a plain `cargo test`, which must not need Node.js. A
missing Python 3.10+ or Node.js 20+ skips its part with a `SKIPPING`
line, a failure with `HELLOVM_REQUIRE_E2E=1` (as CI sets: the native job
runs it as the runner's user, the dev-image job as root). Covered, in
both SDKs: every call's happy path; exit codes, stderr, stdin, cwd, env,
timeouts and truncation; streams (output arriving before the command
ends, in order across stdout and stderr, resumed after the connection is
cut by a proxy, cancelled from another thread or task, an `AbortSignal`,
leaving a stream early cancelling it, omitted output); the stateful
interpreter (state kept, values, exceptions with tracebacks, stdin,
reset, state lost, a timeout); files (binary round trips, text, edits,
missing files, directories, non-text edits, the size limit); busy
handling both ways; authentication failure; an ended sandbox (`410` with
its reason); a second tenant seeing nothing; the context manager
deleting the sandbox when the block raises; ingress (a `python3 -m
http.server` in the sandbox exposed, reached through the listener with
the token and without it, made public, the token rotated, the port
unexposed, its bytes metered). Unit tests without a plane:
parsing, the retry rules, and a local fake server that stalls, trickles a
head or a body, sends an endless or oversized body, drops connections
(an exec or a write is never repeated, a read is), answers busy, `503`
or `429`, or moves a cursor backwards. The MCP server: the handshake in
both eras, the tool list and schemas, bad arguments, configuration
errors, each tool's success and failure against a real plane (the
ingress tools too),
truncation, a timeout, a cancelled request, a sandbox that ended, the
sandbox deleted at exit, and the token absent from everything the server
wrote (also when a fake API echoes it).

## Fuzzing

`kernel/fuzz` holds a fuzz target for everything that parses guest- or
network-controlled bytes. It is its own Cargo workspace, excluded from
`kernel/`'s, so the pinned stable toolchain and CI never build it.

| Target | What it feeds | Property beyond "no panic, bounded time and memory" |
|---|---|---|
| `elf` | `elf::parse` and `elf::load` (both architectures, as program and as interpreter) | |
| `dns` | the virtual DNS responder, with and without an egress proxy | a reply has the query's id, never grows past the query plus one answer, and a repeated query gets the same reply |
| `wire` | the egress flow header (`Request::read_from`) and the verdict | a parsed header re-encodes to the same request |
| `sniff` | the TLS ClientHello / HTTP `Host` sniffer, and prefixes of the input | a returned name appears in the input |
| `policy` | the policy file and rule parser, then lookups | |
| `vfs_path` | `resolve`, `resolve_parent`, `resolve_for_create`, `lookup` over an image with symlink loops, `..` above the root, absolute and empty targets | |
| `shebang` | the `#!` line parser | the interpreter is non-empty and comes from the first line |
| `sigreturn` | `rt_sigreturn` frame restore on both architectures | |
| `syscalls` | arbitrary syscall numbers and arguments, faults and interrupts, for up to four tasks, with arbitrary guest memory, through the dispatcher and the mock platform (`hellovm_core::testutil`, feature `testutil`) | |

With nightly and `cargo-fuzz` (libFuzzer):

```sh
cd kernel/fuzz
cargo +nightly fuzz run syscalls --features libfuzzer -- -rss_limit_mb=1024 -malloc_limit_mb=256 -timeout=10
```

On the stable toolchain, `tests/corpus.rs` runs every target over its
corpus (`corpus/<target>/`: the seeds written by `tests/seeds.rs`, and
the minimized input of every crash found) and then over seeded
mutations of it, with at most 2 s and 256 MiB per input
(`HELLOVM_FUZZ_ITERS`, default 2000 per target; `HELLOVM_FUZZ_TARGET`
picks one; `HELLOVM_FUZZ_REPLAY=target:FILE` replays one input with a
backtrace):

```sh
cd kernel/fuzz
cargo test --release
```

Last run (aarch64, nightly libFuzzer, 1 GiB RSS / 256 MiB single
allocation / 10 s per input): every target 20 minutes, `syscalls` 30
and then another 10 with four workers, after a first 9-minute round on
the code before the U3 review fixes; and the stable runner with 200,000
mutations per target. From 18 million (`sigreturn`) to 152 million
(`shebang`) executions per target, and 6.2 million for `syscalls`. The
only finding: one `truncate` grows an in-memory file to the writable
layer's limit (2 GiB by default) in a single allocation. That is bounded
by design (the growth is charged to the limit, and `ENOSPC` past it),
but above the fuzzers' bound, so the `syscalls` target runs its sandbox
with a 64 MiB layer limit; its input is in the corpus as
`oom-truncate-past-the-fuzz-memory-bound`.

The `syscalls` target only reports the faults the seccomp platform can
report (`SIGILL`, `SIGTRAP`, `SIGBUS`, `SIGFPE`, `SIGSEGV`, `SIGSYS`):
the platform is trusted, the guest only chooses which fault it causes.

## Building and testing

Running sandboxed programs needs a **Linux** host: kernel 5.5 or newer on
x86_64 or aarch64. Rust **1.99.1** is required; `rust-toolchain.toml` at the
repository root makes rustup install it (with clippy and rustfmt). The dev
image is `rust:1.99.1-bookworm`, the same pin. The workspace `rust-version`
is `1.99`, deliberately stricter than the language MSRV (about 1.88). A C
compiler with a static libc (`cc`, used to build the test guests) is also
required. No root or extra capabilities are required, and it works inside a
container with the default Docker seccomp profile (ptrace of one's own
child is allowed there). On macOS on Apple silicon `hellovm` runs
aarch64 Linux programs on the HVF platform (see **The HVF
platform (macOS)** for signing and its own tests); there the Linux
end-to-end tests are compiled out. On other hosts the workspace builds,
but `hellovm` cannot run programs.

`kernel/dev/run-e2e.sh`, run from the repository root, is the one-shot
path on the machine it runs on (a native host, or the dev container on
either architecture). It checks that rustc is 1.99.1, that a C compiler
exists, that busybox is present and statically linked, and that `/usr/bin/python3` has
its standard library at `/usr/lib/python3.X`. It then runs `cargo check`,
`cargo test`, clippy and rustfmt. The script exports `HELLOVM_REQUIRE_E2E=1`
and fails if the test log contains `SKIPPING` or `skipping:`.

Only the value `1` for `HELLOVM_REQUIRE_E2E` requires those end-to-end
tests to run. Any other value (unset, empty, `0`, `false`, or another
string) keeps the skip-and-return behaviour, so a machine without busybox
can still run the unit tests. With `HELLOVM_REQUIRE_E2E=1`, a missing
busybox, CPython or native test guest fails the test and names what to
install.

```sh
cd kernel
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The busybox tests need Debian or Ubuntu **`busybox-static`**: a statically
linked busybox at `/bin/busybox`, or at the path in `HELLOVM_BUSYBOX`. A
musl binary from busybox.net is not a supported image. Without a distro
static busybox the tests are skipped, unless `HELLOVM_REQUIRE_E2E=1`. The
CPython tests need `/usr/bin/python3` and its standard library on the host
(the dev image has them); they copy the interpreter, its libraries and the
standard library into a temporary image.
The dynamic-linking test builds a C program against the host's glibc and
runs it with the host's libraries the same way.
The egress tests (`kernel/hellovm/tests/egress.rs`) need `openssl`, `git`
and `python3-pip` on the host and no internet: they start a local TLS
server and a plain HTTP server as the outside, run the proxy in the test
process, and use the host's `/` as the sandbox image, covering allowed,
denied, SNI-mismatch, Host-mismatch, private and metadata cases, a proxy
that is down, the audit lines, `pip install` from a local index and
`git clone` from a local server. The warm-clone tests (`kernel/hellovm/tests/warm.rs`) also use the host's
`/` with its CPython and busybox; `tests/warm_bench.rs` is the ignored
benchmark of **Warm clones**. The control plane's test
(`kernel/api/tests/control_plane.rs`, see **Control plane**) runs the
`hellovm`, `hellovm-noded` and `hellovm-api` binaries it finds next to
itself, so run it as part of `cargo test --workspace` (as `run-e2e.sh`
does) or after `cargo build --workspace`.
`HELLOVM_NET_E2E=1` also runs
`live_pip_and_git`, a real `pip install` and `git clone` over the internet
with an allowlist of `pypi.org`, `files.pythonhosted.org` and
`github.com`; `run-e2e.sh` and CI never set it.

Run a program in a sandbox whose root is an image directory. The program path
is a path inside the sandbox; `--trace` lists every syscall the kernel
handled, `--egress SOCKET` lets the sandbox reach the network through the
egress proxy (see **Egress**), and `--timeout SECONDS` kills every process of a sandbox that runs
longer (hellovm then exits with 124). `--sandbox require|best-effort|off` picks how strictly
hellovm hardens its own process (see **Hardening**; default
`best-effort`). When hellovm's stdin and stdout are a
terminal, the sandbox gets a terminal console (`--tty`/`--no-tty` override
this), so an interactive shell works:

```sh
mkdir -p /tmp/image/bin && cp /bin/busybox /tmp/image/bin/
cargo run -p hellovm -- --root /tmp/image --trace /bin/busybox ls -l /
cargo run -p hellovm -- --root /tmp/image /bin/busybox sh -i
```

The container's own root works as an image too, e.g. for CPython:
`hellovm --root / /usr/bin/python3 -c 'print(42)'`.

For everything beyond the HVF platform on macOS, use a Linux container. `kernel/dev/Dockerfile` starts from
`rust:1.99.1-bookworm` (matching `rust-toolchain.toml`) and adds clippy,
rustfmt, `busybox-static` and an x86_64 cross toolchain. The base image
already has `python3`, its standard library and `ldd`:

```sh
docker build -t hellovm-dev kernel/dev
docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/target \
  hellovm-dev kernel/dev/run-e2e.sh
```

`cargo test` from `kernel/` still works in that image:

```sh
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  hellovm-dev cargo test
```

On an aarch64 machine, the x86_64 build can be type-checked and linted (not
run) in the same container:

```sh
docker run --rm -v "$PWD":/src -w /src/kernel -e CARGO_TARGET_DIR=/tmp/target \
  -e HELLOVM_GUEST_CC=x86_64-linux-gnu-gcc \
  hellovm-dev cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```
