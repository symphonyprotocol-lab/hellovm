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
| `hellovm` | `kernel/hellovm` | Command-line launcher |
| `hellovm-egress` | `kernel/egress` | The egress proxy (`hellovm-egress` binary): default-deny domain allowlist, one per host |
| `hellovm-egress-wire` | `kernel/egress-wire` | The flow header and hostname rule the kernel and the proxy share |
| `hellovm-test-guest` | `kernel/test-guest` | Small test programs built at build time |

Syscall interception on Linux is ptrace plus `SECCOMP_RET_TRACE`, not
seccomp user notification. Every app thread is a host process. Its filter
returns `SECCOMP_RET_TRACE` for every native-ABI syscall, and one
event-loop thread is the ptrace tracer of those processes: it emulates the
syscall and skips it, so the host kernel does not run it. Changes to an
address space, and new tasks, are injected `mmap`, `munmap`, `mprotect` and
`clone` through a trusted stub page, with arguments the tracer wrote.
`kernel/platform-seccomp/src/spawn.rs` is the full argument, including why
an in-app stub plus user notification was rejected.

What runs today (milestone U4): x86_64 and aarch64 Linux programs,
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
created with the proxy's umask; put it in a directory only the sandbox
host processes can reach. `--sandbox-id` (16 hex digits or a decimal
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
| Namespaces | `unshare` of a user, mount, network and IPC namespace. The root becomes an empty read-only tmpfs (the old root is detached, so no host path can be named); the egress socket is bind-mounted in as `/egress.sock` (the socket that exists at start-up: a proxy restarted later is reached only by kernel processes started after it); the network namespace has only a loopback that is down; every capability is dropped afterwards. Uid and gid are mapped to themselves. A failure after `unshare` succeeded stops hellovm in every mode (exit 125): it never runs guest code half-confined. | `unshare(CLONE_NEWUSER)` is refused: Docker's default seccomp profile, unprivileged user namespaces disabled (`kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0`), AppArmor's `restrict_unprivileged_userns` (Ubuntu 24.04) | no |
| Resource limits | `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 4096, `RLIMIT_AS` 32 GiB, `RLIMIT_MEMLOCK` 0, `RLIMIT_MSGQUEUE` 0 (lowered only, never raised) | `setrlimit` fails | yes |
| `no_new_privs` | `PR_SET_NO_NEW_PRIVS` | never in practice | yes |
| Landlock | Reading files and directories beneath the image directory is the only filesystem right; TCP bind and connect are denied (ABI 4+); signals and abstract Unix sockets are scoped to the kernel process's own domain, i.e. its app processes (ABI 6+). Landlock also stops ptrace and `process_vm_*` of processes outside the domain. | no Landlock in the host kernel (before 5.13, or not in `lsm=`), or the syscalls are refused | no, but one of Landlock and the namespaces is |
| Not dumpable | `PR_SET_DUMPABLE` 0: no core dump, no ptrace attach and no `/proc/<pid>/mem` of the kernel process by other processes of the same user | never in practice | yes |
| Seccomp | An allowlist of the syscalls the kernel process makes, with argument checks; anything else kills the process | `seccomp` refused or the code ranges cannot be read from `/proc/self/maps` at start-up | yes |

`--sandbox best-effort` (the default) uses every layer the host allows
and logs each skipped one, with the reason, at info level;
`--sandbox require` refuses to start (exit 125, listing the layers) when
a required one is unavailable; `--sandbox off` uses none.
`HELLOVM_LOG=debug` lists the active layers:

```text
hellovm: debug: sandbox: inherited fds closed: active (0 closed)
hellovm: debug: sandbox: user/mount/network/IPC namespaces: active (user, mount, network, IPC)
hellovm: debug: sandbox: resource limits: active (core 0, nofile 4096, as 32 GiB)
hellovm: debug: sandbox: no_new_privs: active ()
hellovm: debug: sandbox: Landlock: active (ABI 8: image read-only, no TCP, signals and abstract sockets scoped)
hellovm: debug: sandbox: not dumpable: active ()
hellovm: debug: sandbox: seccomp allowlist: active (57 syscalls, 277 instructions, 5 code ranges)
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
never runs there. The allowlist (57 calls on aarch64) was measured with
`HELLOVM_SECCOMP_LEARN=FILE` (a test-hooks build), which records every
syscall the kernel process makes and lets it continue, over the whole
test suite; `kernel/sandbox/learn-summary.py FILE` condenses the log.
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
threads and 2048 tasks); `RLIMIT_AS` bounds virtual size, not memory in
use, so run each sandbox in a memory cgroup for that. Tenants that share
a host uid can still signal or `ptrace` each other's processes where
Landlock is unavailable; give each tenant its own uid.

*Image directory.* The image is opened once and every lookup walks from
that directory fd with `openat(O_NOFOLLOW | O_DIRECTORY)` per component,
then `fstatat`/`readlinkat`/`openat` of the last one without following
it. No symlink in the image, pointing inside or outside it, is ever
followed on the host (the core resolves symlinks itself), FIFOs and
device nodes are never opened, and a host-side change to the directory
cannot make a lookup leave it.

*The egress proxy.* `hellovm-egress` is not hardened yet. It parses the
flow header and the first bytes of every flow (SNI, `Host`), so it would
benefit from the same treatment: `no_new_privs`, not dumpable, no core
dumps and an fd limit are trivial; Landlock would allow reading the
policy file, writing the audit file and creating the listening socket
(or take it already bound); a seccomp allowlist is possible but must
cover the host resolver (`getaddrinfo` reads `/etc/resolv.conf`,
`/etc/hosts`, `/etc/nsswitch.conf` and may load NSS modules, so those
files must stay readable and its socket calls allowed); it needs the host
network, so no network namespace.

*Testing.* Every end-to-end test runs in a hardened kernel process: the
in-process scenarios go through `hellovm --insecure-test-session` (a
test hook that applies the same hardening, then runs programs on
request), the rest run the binary. `kernel/hellovm/tests/hardening.rs`
makes the hardened kernel process itself (`--insecure-fence-test`, a test
hook) open `/etc/passwd`, connect a TCP socket, connect to a host
abstract Unix socket, call `setns` and `PTRACE_ATTACH` its parent, and
asserts each is refused or kills it; with `--sandbox off` each succeeds,
as a control. In the dev container (Docker's default seccomp profile)
the namespaces are skipped and every other layer is active; with
`--security-opt seccomp=unconfined` all seven are.

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
`git clone` from a local server. `HELLOVM_NET_E2E=1` also runs
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
