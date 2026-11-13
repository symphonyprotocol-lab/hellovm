// Guest socket checks for spec 002a. The Rust test matches the printed lines.
//
//   netcheck check
//   netcheck splice <ipv4>
//   netcheck epipe
//
// `check` stays in-process (plus one fork for the loopback pair). `splice`
// connects to an issued fake IP; the host splices that flow to a local
// server and echoes the payload. `epipe` is killed by SIGPIPE.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>

static int fails;

static void expect_ok(const char *name, int cond) {
    if (cond) {
        printf("ok %s\n", name);
    } else {
        printf("FAIL %s errno=%d\n", name, errno);
        fails++;
    }
}

static void expect_err(const char *name, int rc, int want) {
    expect_ok(name, rc < 0 && errno == want);
}

static int tcp(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

static struct sockaddr_in v4(const char *ip, int port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static void check_errors(void) {
    int s = tcp();
    expect_ok("tcp socket", s >= 0);
    struct sockaddr_in a;
    a = v4("169.254.169.254", 80);
    expect_err("metadata", connect(s, (void *)&a, sizeof a), ENETUNREACH);
    a = v4("10.1.2.3", 80);
    expect_err("rfc1918", connect(s, (void *)&a, sizeof a), ENETUNREACH);
    a = v4("151.101.64.223", 443);
    expect_err("off-list", connect(s, (void *)&a, sizeof a), ENETUNREACH);
    a = v4("192.0.2.99", 80);
    expect_err("nic-other", connect(s, (void *)&a, sizeof a), EHOSTUNREACH);
    a = v4("192.0.2.1", 80);
    expect_err("gateway-http", connect(s, (void *)&a, sizeof a), ECONNREFUSED);
    a = v4("192.0.2.1", 9);
    expect_err("bind-gateway", bind(s, (void *)&a, sizeof a), EADDRNOTAVAIL);
    a = v4("198.51.100.9", 9);
    expect_err("bind-fake", bind(s, (void *)&a, sizeof a), EADDRNOTAVAIL);
    a = v4("10.0.0.1", 9);
    expect_err("bind-private", bind(s, (void *)&a, sizeof a), EADDRNOTAVAIL);
    a = v4("127.0.0.1", 1);
    expect_err("no-listener", connect(s, (void *)&a, sizeof a), ECONNREFUSED);
    close(s);

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    a = v4("8.8.8.8", 53);
    expect_err("udp-send", sendto(u, "q", 1, 0, (void *)&a, sizeof a), ENETUNREACH);
    expect_err("udp-connect", connect(u, (void *)&a, sizeof a), ENETUNREACH);
    close(u);

    expect_err("ipv6", socket(AF_INET6, SOCK_STREAM, 0), EAFNOSUPPORT);
    expect_err("netlink", socket(AF_NETLINK, SOCK_RAW, 0), EAFNOSUPPORT);
    expect_err("unix", socket(AF_UNIX, SOCK_STREAM, 0), EAFNOSUPPORT);

    int sp[2];
    expect_ok("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    expect_ok("pair-send", send(sp[0], "pair", 4, 0) == 4);
    char tmp[8];
    expect_ok("pair-recv", recv(sp[1], tmp, sizeof tmp, 0) == 4 && memcmp(tmp, "pair", 4) == 0);
    close(sp[0]);
    close(sp[1]);
}

static void check_loopback(void) {
    int srv = tcp();
    struct sockaddr_in a = v4("127.0.0.1", 0);
    expect_ok("lb-bind", bind(srv, (void *)&a, sizeof a) == 0);
    expect_ok("lb-listen", listen(srv, 1) == 0);
    socklen_t alen = sizeof a;
    expect_ok("lb-name", getsockname(srv, (void *)&a, &alen) == 0);
    int port = ntohs(a.sin_port);
    expect_ok("ephemeral", port >= 32768 && port <= 60999);

    pid_t kid = fork();
    if (kid == 0) {
        int c = tcp();
        struct sockaddr_in dst = v4("127.0.0.1", port);
        if (connect(c, (void *)&dst, sizeof dst) != 0) {
            _exit(2);
        }
        if (send(c, "hello-loopback", 14, 0) != 14) {
            _exit(3);
        }
        if (shutdown(c, SHUT_WR) != 0) {
            _exit(4);
        }
        char buf[32];
        int n = recv(c, buf, sizeof buf, 0);
        if (n != 14 || memcmp(buf, "hello-loopback", 14) != 0) {
            _exit(5);
        }
        _exit(0);
    }
    expect_ok("fork", kid > 0);
    int conn = accept(srv, NULL, NULL);
    expect_ok("accept", conn >= 0);
    char buf[32];
    int n = recv(conn, buf, sizeof buf, 0);
    expect_ok("lb-recv", n == 14 && memcmp(buf, "hello-loopback", 14) == 0);
    n = recv(conn, buf, sizeof buf, 0);
    expect_ok("half-close", n == 0);
    expect_ok("lb-reply", send(conn, "hello-loopback", 14, 0) == 14);
    int status = 1;
    waitpid(kid, &status, 0);
    expect_ok("child", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    // Peer close, then a write that must not raise SIGPIPE.
    close(conn);
    int c = tcp();
    struct sockaddr_in dst = v4("127.0.0.1", port);
    expect_ok("again", connect(c, (void *)&dst, sizeof dst) == 0);
    int extra = accept(srv, NULL, NULL);
    close(extra);
    /* Clean close: the first write is accepted, the second is EPIPE. */
    expect_ok("write-after-close", send(c, "x", 1, MSG_NOSIGNAL) == 1);
    expect_err("nosignal", send(c, "x", 1, MSG_NOSIGNAL), EPIPE);
    close(c);
    close(srv);
}

static void check_nonblock(void) {
    int srv = tcp();
    struct sockaddr_in a = v4("127.0.0.1", 0);
    bind(srv, (void *)&a, sizeof a);
    listen(srv, 4);
    socklen_t alen = sizeof a;
    getsockname(srv, (void *)&a, &alen);
    int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int rc = connect(c, (void *)&a, sizeof a);
    expect_err("einprogress", rc, EINPROGRESS);
    struct pollfd p = {.fd = c, .events = POLLOUT};
    expect_ok("pollout", poll(&p, 1, 0) == 1 && (p.revents & POLLOUT));
    int err = 1;
    socklen_t len = sizeof err;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len);
    expect_ok("so-error-ok", err == 0);
    close(c);
    close(srv);

    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    a = v4("127.0.0.1", 1);
    expect_err("nb-refused", connect(c, (void *)&a, sizeof a), EINPROGRESS);
    err = 0;
    len = sizeof err;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len);
    expect_ok("so-error-refused", err == ECONNREFUSED);
    close(c);
}

static void check_udp(void) {
    int a = socket(AF_INET, SOCK_DGRAM, 0);
    int b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = v4("127.0.0.1", 0);
    bind(a, (void *)&addr, sizeof addr);
    socklen_t alen = sizeof addr;
    getsockname(a, (void *)&addr, &alen);
    expect_ok("udp-send", sendto(b, "ping", 4, 0, (void *)&addr, sizeof addr) == 4);
    char buf[8];
    struct sockaddr_in src;
    socklen_t sl = sizeof src;
    int n = recvfrom(a, buf, sizeof buf, 0, (void *)&src, &sl);
    expect_ok("udp-echo", n == 4 && memcmp(buf, "ping", 4) == 0);
    close(a);
    close(b);
}

static void check_backlog(void) {
    int srv = tcp();
    struct sockaddr_in a = v4("127.0.0.1", 0);
    bind(srv, (void *)&a, sizeof a);
    listen(srv, 1);
    socklen_t alen = sizeof a;
    getsockname(srv, (void *)&a, &alen);
    int c1 = tcp();
    expect_ok("q1", connect(c1, (void *)&a, sizeof a) == 0);
    int c2 = tcp();
    expect_err("qfull", connect(c2, (void *)&a, sizeof a), ECONNREFUSED);
    close(c1);
    close(c2);
    close(srv);
}

static void check_iface(void) {
    int s = tcp();
    // Keep a loopback listener open so /proc/net/tcp has a row to show.
    struct sockaddr_in live = v4("127.0.0.1", 0);
    bind(s, (void *)&live, sizeof live);
    listen(s, 1);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    memcpy(ifr.ifr_name, "eth0", 4);
    expect_ok("ifaddr", ioctl(s, SIOCGIFADDR, &ifr) == 0);
    struct sockaddr_in *in = (struct sockaddr_in *)&ifr.ifr_addr;
    char text[32];
    inet_ntop(AF_INET, &in->sin_addr, text, sizeof text);
    expect_ok("nic-addr", strcmp(text, "192.0.2.2") == 0);

    char buf[256];
    struct ifconf ifc;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = buf;
    expect_ok("ifconf", ioctl(s, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len >= (int)sizeof(struct ifreq));

    FILE *f = fopen("/proc/net/tcp", "r");
    expect_ok("proc-tcp-open", f != NULL);
    char line[256];
    expect_ok("proc-tcp-hdr", f && fgets(line, sizeof line, f) && strstr(line, "local_address"));
    int saw = 0;
    while (f && fgets(line, sizeof line, f)) {
        if (strstr(line, "0100007F")) {
            saw = 1;
        }
    }
    if (f) {
        fclose(f);
    }
    expect_ok("proc-tcp-loop", saw);
    f = fopen("/proc/net/udp", "r");
    expect_ok("proc-udp", f != NULL);
    if (f) {
        fclose(f);
    }
    close(s);
}

static void check_dns(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    // Minimal query: id 0x1234, RD, one question "hi" A IN.
    unsigned char q[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
                         2, 'h', 'i', 0, 0, 1, 0, 1};
    struct sockaddr_in dns = v4("192.0.2.1", 53);
    expect_ok("dns-send", sendto(u, q, sizeof q, 0, (void *)&dns, sizeof dns) == (ssize_t)sizeof q);
    unsigned char resp[512];
    struct timeval tv = {.tv_sec = 2};
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int n = recv(u, resp, sizeof resp, 0);
    expect_ok("dns-nx", n >= 12 && (resp[3] & 0x0f) == 3);
    close(u);
}

static void check_addrinfo(void) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo("127.0.0.1", "80", &hints, &res);
    int family = res ? res->ai_family : -1;
    printf("getaddrinfo-numeric rc=%d family=%d\n", rc, family);
    if (res) {
        freeaddrinfo(res);
    }
    res = NULL;
    rc = getaddrinfo("localhost", NULL, &hints, &res);
    printf("getaddrinfo-localhost rc=%d family=%d\n", rc, res ? res->ai_family : -1);
    if (res) {
        freeaddrinfo(res);
    }
    struct ifaddrs *ifa = NULL;
    errno = 0;
    rc = getifaddrs(&ifa);
    printf("getifaddrs rc=%d errno=%d\n", rc, rc < 0 ? errno : 0);
    if (ifa) {
        freeifaddrs(ifa);
    }
}

// A loopback listener on an ephemeral port; its address goes to `a`.
static int listener(struct sockaddr_in *a) {
    int srv = tcp();
    *a = v4("127.0.0.1", 0);
    socklen_t len = sizeof *a;
    bind(srv, (void *)a, sizeof *a);
    listen(srv, 4);
    getsockname(srv, (void *)a, &len);
    return srv;
}

// One blocking write() larger than the socket buffer, read by a child:
// every byte arrives exactly once, in order.
static void check_big_write(void) {
    enum { N = 200000 };
    static unsigned char out[N];
    static unsigned char in[N + 1];
    for (int i = 0; i < N; i++) {
        out[i] = (unsigned char)(i % 251);
    }
    struct sockaddr_in a;
    int srv = listener(&a);
    int c = tcp();
    connect(c, (void *)&a, sizeof a);
    int s = accept(srv, NULL, NULL);
    pid_t pid = fork();
    if (pid == 0) {
        close(c);
        size_t got = 0;
        for (;;) {
            ssize_t n = read(s, in + got, sizeof in - got);
            if (n <= 0) {
                break;
            }
            got += (size_t)n;
        }
        _exit(got == N && memcmp(in, out, N) == 0 ? 0 : 1);
    }
    close(s);
    expect_ok("big-write", write(c, out, N) == N);
    close(c);
    int st = 0;
    waitpid(pid, &st, 0);
    expect_ok("big-write-arrives-once", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(srv);
}

// The client sends and closes before the server accepts.
static void check_close_before_accept(void) {
    struct sockaddr_in a;
    int srv = listener(&a);
    int c = tcp();
    connect(c, (void *)&a, sizeof a);
    send(c, "early", 5, 0);
    close(c);
    int s = accept(srv, NULL, NULL);
    char buf[8];
    int n = s >= 0 ? (int)recv(s, buf, sizeof buf, 0) : -1;
    expect_ok("close-before-accept", n == 5 && memcmp(buf, "early", 5) == 0);
    expect_ok("close-before-accept-eof", s >= 0 && recv(s, buf, sizeof buf, 0) == 0);
    close(s);
    close(srv);
}

static int do_check(void) {
    check_errors();
    check_loopback();
    check_nonblock();
    check_udp();
    check_backlog();
    check_iface();
    check_dns();
    check_addrinfo();
    check_big_write();
    check_close_before_accept();
    if (fails) {
        printf("fails %d\n", fails);
        return 1;
    }
    printf("check-ok\n");
    return 0;
}

static int do_splice(const char *ip) {
    int c = tcp();
    struct sockaddr_in a = v4(ip, 443);
    if (connect(c, (void *)&a, sizeof a) != 0) {
        printf("splice-connect errno=%d\n", errno);
        return 1;
    }
    if (send(c, "splice-ping", 11, 0) != 11) {
        printf("splice-send errno=%d\n", errno);
        return 1;
    }
    if (shutdown(c, SHUT_WR) != 0) {
        printf("splice-shut errno=%d\n", errno);
        return 1;
    }
    // An event loop's view: the echo must show up to poll and FIONREAD
    // before any recv, and a zero-length recv must not look like EOF.
    struct pollfd p = {.fd = c, .events = POLLIN};
    if (poll(&p, 1, 5000) != 1 || !(p.revents & POLLIN)) {
        printf("splice-poll revents=%#x errno=%d\n", p.revents, errno);
        return 1;
    }
    int avail = -1;
    if (ioctl(c, FIONREAD, &avail) != 0 || avail <= 0) {
        printf("splice-fionread avail=%d errno=%d\n", avail, errno);
        return 1;
    }
    char buf[32];
    if (recv(c, buf, 0, 0) != 0) {
        printf("splice-recv0 errno=%d\n", errno);
        return 1;
    }
    int n = 0;
    while (n < 11) {
        int got = (int)recv(c, buf + n, sizeof buf - (size_t)n, 0);
        if (got <= 0) {
            break;
        }
        n += got;
    }
    if (n != 11 || memcmp(buf, "splice-ping", 11) != 0) {
        printf("splice-recv n=%d errno=%d\n", n, errno);
        return 1;
    }
    printf("splice-ok\n");
    return 0;
}

static int do_epipe(void) {
    int srv = tcp();
    struct sockaddr_in a = v4("127.0.0.1", 0);
    bind(srv, (void *)&a, sizeof a);
    listen(srv, 1);
    socklen_t alen = sizeof a;
    getsockname(srv, (void *)&a, &alen);
    int c = tcp();
    connect(c, (void *)&a, sizeof a);
    int conn = accept(srv, NULL, NULL);
    close(conn);
    /* The first write after a clean close succeeds. The second raises SIGPIPE. */
    if (send(c, "x", 1, 0) != 1) {
        printf("epipe-first errno=%d\n", errno);
        return 1;
    }
    send(c, "x", 1, 0);
    printf("epipe-survived\n");
    return 1;
}

int main(int argc, char **argv) {
    const char *cmd = argc > 1 ? argv[1] : "check";
    if (strcmp(cmd, "check") == 0) {
        return do_check();
    }
    if (strcmp(cmd, "splice") == 0 && argc > 2) {
        return do_splice(argv[2]);
    }
    if ((strcmp(cmd, "bulk") == 0 || strcmp(cmd, "bulk-exit") == 0 ||
         strcmp(cmd, "slowbulk") == 0 || strcmp(cmd, "slowbulk-exit") == 0) &&
        argc > 2) {
        int c = tcp();
        struct sockaddr_in a = v4(argv[2], 9);
        if (connect(c, (void *)&a, sizeof a) != 0) {
            printf("bulk-connect errno=%d\n", errno);
            return 1;
        }
        char block[4096];
        memset(block, 0x5a, sizeof block);
        int slow = strcmp(cmd, "slowbulk") == 0 || strcmp(cmd, "slowbulk-exit") == 0;
        size_t left = slow ? (size_t)8 << 20 : 200000;
        size_t total = 0;
        while (left > 0) {
            size_t n = left < sizeof block ? left : sizeof block;
            ssize_t w = send(c, block, n, 0);
            if (w <= 0) {
                printf("bulk-send errno=%d\n", errno);
                return 1;
            }
            left -= (size_t)w;
            total += (size_t)w;
        }
        if (slow) {
            /* Stop the reader, wait until it is parked, then fill until the
             * host socket is full too. One EAGAIN only means the in-kernel
             * queue is full; the host buffer may still be taking bytes. */
            int ctl = tcp();
            char go = 0;
            if (connect(ctl, (void *)&a, sizeof a) != 0 || send(ctl, "D", 1, 0) != 1 ||
                recv(ctl, &go, 1, 0) != 1) {
                printf("ctl errno=%d\n", errno);
                return 1;
            }
            close(ctl);
            int fl = fcntl(c, F_GETFL);
            if (fl < 0 || fcntl(c, F_SETFL, fl | O_NONBLOCK) < 0) {
                printf("fcntl errno=%d\n", errno);
                return 1;
            }
            int stalls = 0;
            while (stalls < 20) {
                ssize_t w = send(c, block, sizeof block, 0);
                if (w > 0) {
                    total += (size_t)w;
                    stalls = 0;
                    continue;
                }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    stalls++;
                    usleep(10000);
                    continue;
                }
                printf("fill errno=%d\n", errno);
                return 1;
            }
        }
        if (strcmp(cmd, "bulk") == 0 || strcmp(cmd, "slowbulk") == 0) {
            close(c);
        }
        printf("bulk-sent %zu\n", total);
        return 0;
    }
    if (strcmp(cmd, "epipe") == 0) {
        return do_epipe();
    }
    fprintf(stderr, "usage: netcheck check|splice IP|epipe\n");
    return 2;
}
