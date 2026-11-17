# hellovm

A sandbox for AI models.

## The kernel

The kernel lives in `kernel/`, a Rust workspace:

| Crate | Path | Role |
|---|---|---|
| `hellovm-core` | `kernel/core` | Syscall emulation: processes, threads, signals, pipes, ELF loading, memory map, filesystem, terminal, `/proc`, IPv4 sockets; independent of the host OS |
| `hellovm-host` | `kernel/host` | Host interface implementations: console, image directory, random bytes, clocks, outbound streams to the egress proxy |
| `hellovm-platform-seccomp` | `kernel/platform-seccomp` | Linux platform: ptrace and `SECCOMP_RET_TRACE` (see below) |
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
per proxy) and no rate or byte quota.

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
`SCM_RIGHTS`, answers `R` (ready), `S` (the clone runs: its sandbox id and
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
```

They live in `kernel/` because `noded` uses the warm-clone client of the
`hellovm` crate and the whole repository has one workspace and one CI
gate. When the API is deployed apart from the nodes (U6), `api` and
`control` would move to a top-level `services/` workspace, with `noded`
staying next to the kernel it drives.

**Running it.** One egress proxy, one `noded` and one `api` per host here:

```sh
hellovm-egress --listen /run/hellovm/egress/egress.sock --policy /etc/hellovm/egress.policy &
hellovm-noded --config /etc/hellovm/noded.json &
hellovm-api --config /etc/hellovm/api.json &
```

```json
{"node": "node-1", "listen": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token",
 "hellovm": "/usr/local/bin/hellovm", "state_dir": "/run/hellovm-noded",
 "egress": "/run/hellovm/egress/egress.sock", "max_sandboxes": 64,
 "templates": [{"name": "python", "root": "/", "python": "/usr/bin/python3",
                "preload": ["json", "decimal", "sqlite3"], "memory_limit_mb": 1024,
                "fs_limit_mb": 1024}]}
```

```json
{"listen": "0.0.0.0:7070",
 "tenants": [{"name": "acme", "token_file": "/etc/hellovm/acme.token", "max_sandboxes": 10}],
 "nodes": [{"name": "node-1", "addr": "127.0.0.1:7071", "token_file": "/etc/hellovm/node.token"}],
 "default_idle_timeout": 600, "max_idle_timeout": 86400,
 "default_lifetime": 3600, "max_lifetime": 86400}
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
| `GET /v1/templates` | | `{"templates": [{"name", "ready", "starts", "tenant", "pid"}]}` |
| `POST /v1/sandboxes` | `{"template", "idle_timeout"?, "lifetime"?}` (seconds) | `201`, the sandbox |
| `GET /v1/sandboxes` | | `{"sandboxes": [...]}`, the caller's |
| `GET /v1/sandboxes/{id}` | | `{"id", "tenant", "template", "node", "egress_id", "created_at", "last_used_at", "expires_at", "idle_timeout", "memory_bytes", "memory_limit_bytes", "ready_ms"}` |
| `DELETE /v1/sandboxes/{id}` | | `204` |
| `POST /v1/sandboxes/{id}/exec` | `{"command"` or `"python", "timeout"?, "cwd"?, "env"?, "stdin"?, "max_output"?}` | `{"exit_code", "signal", "timed_out", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "stdout_bytes", "stderr_bytes", "duration_ms"}` |
| `GET /v1/sandboxes/{id}/files?path=P` | | the file's bytes |
| `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `{"bytes"}` |
| `POST /v1/sandboxes/{id}/files/edit` | `{"path", "old", "new", "replace_all"?}` | `{"replacements"}` |

| Status | Code | When |
|---|---|---|
| 400 | `bad_request`, `is_directory`, `not_regular`, `not_text` | malformed request; not a file; not UTF-8 (edit) |
| 401 | `unauthorized` | no or unknown token |
| 404 | `sandbox_not_found` | no such sandbox, **or another tenant's** (the same answer) |
| 404 | `not_found`, `template_not_found` | no such file or working directory; no such template |
| 409 | `busy` | the sandbox is running another request (one at a time) |
| 410 | `sandbox_ended` | the node removed it and still remembers why (idle, lifetime, memory, its agent ended) |
| 413 | `too_large` | a body or file over 16 MiB |
| 422 | `no_match`, `ambiguous` | edit: `old` does not occur, or occurs more than once without `replace_all` |
| 429 | `tenant_limit` | the tenant has `max_sandboxes` already |
| 502 | `sandbox_failed`, `node_unreachable` | the sandbox's agent broke (the sandbox is removed); the node does not answer |
| 503 | `template_not_ready`, `node_full` | try again |
| 507 | `no_space` | the writable layer is full |

*exec.* `command` runs as `/bin/sh -c COMMAND`; `python` runs the
source in a fork of the sandbox's warm interpreter, so the template's
modules are already imported (`SystemExit` sets the exit code, an
uncaught exception prints its traceback and exits 1). The working
directory is `/root` unless `cwd` says otherwise (relative paths in file
operations are relative to it too); `env` adds variables; `stdin` is
the command's input (otherwise it reads end of file). `timeout` (default
60 s, at most 3600 s) kills the command's whole process group with
`SIGKILL`: `timed_out` is `true` and `signal` 9. Output is decoded as
UTF-8 with invalid bytes replaced; each stream keeps at most
`max_output` bytes (default 64 KiB, at most 1 MiB): the first and the
last half, with `[... N bytes omitted ...]` between them, and
`stdout_bytes` says how much there was. Limits: command, Python source
and stdin 1 MiB each, 256 environment variables in 64 KiB.

*State between requests.* Kept: the filesystem (the writable layer),
processes started in the background that hold none of the command's
pipes (`nohup server >log 2>&1 &`; output written to the pipes after
the command ended is dropped, 100 ms after it ended), and everything the
template set up. Not kept: the shell's working directory, variables and
functions (each `command` is a new shell), and the variables of a
`python` run (each is a new fork). An interactive interpreter whose
namespace survives between calls is a later step (SDK and MCP server).

*Files.* `read_file` and `write_file` take any path (`write_file`
creates the parent directories); only regular files are read or written
(a FIFO or device is refused, never opened for blocking I/O); at most
16 MiB. `edit_file` replaces exactly one occurrence of `old` by `new` in
a UTF-8 file (all of them with `replace_all`) and says how many it
replaced.

*Life cycle.* A sandbox is removed by `DELETE`, after `idle_timeout`
seconds without a request (a running request is not idle), at the end
of its `lifetime` however busy it is (both default and capped by the API
configuration, at most a week), when its processes' private memory goes
over the template's `memory_limit_mb`, or when its agent ends. Its node
answers `410` with the reason for a while (4096 ended sandboxes), then
`404`.

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
greets with its version once the clone runs, and each answer carries
its request's id. The agent is the sandbox's first process, so it also
reaps orphans. Its frames are untrusted: anything in the sandbox can
write to `/dev/console`, so `noded` bounds every length before
allocating (a 64 KiB header; a body no longer than the request can
produce), has a deadline on every read and write, checks every field,
and on any violation removes the sandbox (it can only have broken
itself). Rejected:

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

**How `api` and `noded` talk.** HTTP/1.1 with JSON, the same shapes as
the public API (the node API is listed in `kernel/noded/src/server.rs`):
`POST /v1/sandboxes` carries the id, tenant, template and the resolved
timeouts the API chose. Each node has its own bearer token, which the
API presents; every request about a sandbox also names its tenant. With
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

**Restarts.** The API: nothing is lost; it rebuilds its store from the
nodes before serving and running sandboxes keep their state (tested).
`noded`: its templates die with it (`PR_SET_PDEATHSIG`) and their clones
with them, so its sandboxes are gone; the next `noded` removes the
stale sockets, starts the templates again, and the API drops the lost
sandboxes at its next reconciliation (tested). A template that dies is
started again at once (if it had run a minute; otherwise after a delay
that doubles up to 30 s), and its sandboxes are gone (tested). Keeping
sandboxes across a `noded` restart would need the templates and the
clones' control connections to outlive it (an fd store, re-adoption):
not done.

**Resource limits.** All clones of a template run in the template's
cgroup: a clone runs before whoever asked for it learns its pid. What
is enforced without root:

| Limit | How | Past it |
|---|---|---|
| Writable layer (`fs_limit_mb`) | the kernel process (`hellovm --fs-limit`, kernel state every clone inherits) | `ENOSPC` |
| Memory (`memory_limit_mb`) | `noded` sums the private memory (`RssAnon` + `RssShmem`) of the clone's kernel process and every process below it once a second, each address space once (`kcmp`), and removes the sandbox | the sandbox is removed; `410` with the reason |
| Time | per-exec `timeout`, idle timeout, lifetime | killed or removed |
| Tasks, sockets, outbound flows | the kernel (2048 tasks, 4096 sockets) and the egress proxy (64 flows per sandbox) | `EAGAIN` and the like |
| Sandboxes | per tenant (API) and per node (`max_sandboxes`) | `429`, `503` |

The memory measurement is a poll, not a limit: a sandbox can go over it
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
gets `503`), 30 s idle between keep-alive requests. JSON with unknown
fields is refused. The agent channel: see above. Logged text from a
sandbox is bounded per line and per sandbox. Neither service dials an
address a sandbox chose: `noded` connects only to its templates'
sockets, the API only to its configured nodes.

**Dependencies.** `serde` and `serde_json` (with their derive macro's
`syn`, `quote`, `proc-macro2`, `unicode-ident`, and `itoa`, `memchr`,
`ryu`): the JSON of both APIs. Nothing else: the HTTP server and client
are about 800 lines of strict, bounded code in `hellovm-control`, and
one thread per connection (at most 256) is enough at this scale.
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
warm interpreter), state between execs, read, write and edit (binary
data, missing files, directories, ambiguous and missing edits), the
writable layer's limit, outbound HTTP through the proxy with the
sandbox's id in the audit line and a refused name, one request at a
time, tenant isolation for every endpoint, the tenant limit, delete,
idle timeout, lifetime, the memory limit, a template killed and
restarted, `noded` killed and restarted with stale sockets, the API
restarted with sandboxes running, and a clean shutdown.
`kernel/noded` has unit tests for the agent protocol (against the
host's Python), garbage from a sandbox, configurations, memory
measurement and stale sockets; `kernel/control` for HTTP parsing and
limits.

**Measurements.** `cargo test --release -p hellovm-api --test
control_plane bench_create_and_exec -- --ignored --nocapture`: the plane
above, 30 sandboxes one after another, each created, used and deleted
through the API over loopback HTTP. Same machine and setup as the
**Warm clones** numbers (release build, Apple M3 Max, Docker Desktop
aarch64, default seccomp profile), medians with the range:

| | Debian bookworm (CPython 3.11) | Ubuntu 26.04 (CPython 3.14) |
|---|---|---|
| **Create, request to ready** (through the API) | **8.3 ms** (5.8–8.7) | **7.1 ms** (4.1–7.9) |
| of that, on the node (clone request to the agent's greeting) | 8.0 ms | 6.8 ms |
| `exec` of `echo hi` (`/bin/sh -c`) | 10.6 ms (8.3–11.4) | 12.9 ms (9.9–23.4) |
| Create and first `exec`, together | 18.9 ms (14.3–20.1) | 19.9 ms (14.2–30.4) |
| `exec` of Python (`json.dumps`, in a fork of the warm interpreter) | 4.9 ms (3.8–5.5) | 3.7 ms (2.6–4.1) |
| `write_file` / `read_file`, 5 bytes | 0.8 / 1.0 ms | 0.8 / 0.6 ms |
| `delete` | 0.3 ms | 0.2 ms |
| For comparison: a cold `hellovm --root / python3 -c 'import json; ...'`, start to exit | 60.6 ms | 51.4 ms |

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
child is allowed there). On other hosts the workspace builds, but the
end-to-end tests are skipped and `hellovm` cannot run programs yet.

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

On macOS, use a Linux container. `kernel/dev/Dockerfile` starts from
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
