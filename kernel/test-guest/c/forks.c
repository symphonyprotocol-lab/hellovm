// Processes end to end: fork and wait, copy-on-write in both directions,
// shared anonymous memory, fork then execve, vfork, posix_spawn, a fork of
// a fork, a large address space copied, many children at once, a pipe
// between two children, and a busy loop that must not keep its parent
// from running. Prints one line per check; keep in sync with
// hellovm/tests/forks.rs and platform-hvf/tests/hvf.rs.
//
// Other modes:
//   forks exec-child WORD   prints "exec: child WORD", exits 7
//   forks bomb SECONDS      a fork bomb (see bomb())
//   forks bench N MIB       times N fork+exit+wait round trips, one fork
//                           of a process with MIB MiB touched, and N
//                           round trips of a byte between two processes
//                           that each read 64 pages in between
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static volatile int data_word = 1;
static char bss_page[4096];

static const char *self;

static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAILED: %s (errno %d)\n", what, errno);
        exit(1);
    }
}

static int status_of(pid_t pid) {
    int status;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    check(got == pid, "waitpid");
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 1000 + WTERMSIG(status);
    return -1;
}

static void send_byte(int fd) {
    char c = 'x';
    check(write(fd, &c, 1) == 1, "write to pipe");
}

static void wait_byte(int fd) {
    char c;
    check(read(fd, &c, 1) == 1, "read from pipe");
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void fork_and_wait(void) {
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) _exit(42);
    printf("fork: child exited %d\n", status_of(pid));
}

// Private memory of every kind (.data, .bss, heap, stack) is copied: what
// the child writes, the parent does not see, and the other way round,
// also after the child wrote first (its copy) and the parent second (the
// original, whose frame has one user again).
static void copy_on_write(void) {
    char stack_buf[256];
    char *heap = malloc(1 << 20);
    check(heap != NULL, "malloc");
    memset(heap, 'p', 1 << 20);
    memset(stack_buf, 'p', sizeof stack_buf);
    bss_page[0] = 'p';
    data_word = 1;
    int to_child[2], to_parent[2];
    check(pipe(to_child) == 0 && pipe(to_parent) == 0, "pipe");
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        data_word = 2;
        heap[12345] = 'c';
        stack_buf[7] = 'c';
        bss_page[0] = 'c';
        send_byte(to_parent[1]);
        wait_byte(to_child[0]);
        // The parent wrote everything by now.
        int ok = data_word == 2 && heap[12345] == 'c' && heap[0] == 'p' &&
                 stack_buf[7] == 'c' && bss_page[0] == 'c';
        _exit(ok ? 0 : 1);
    }
    wait_byte(to_parent[0]);
    char seen[5] = {(char)('0' + data_word), heap[12345], stack_buf[7], bss_page[0], 0};
    data_word = 3;
    heap[12345] = 'P';
    heap[0] = 'P';
    stack_buf[7] = 'P';
    bss_page[0] = 'P';
    send_byte(to_child[1]);
    int child = status_of(pid);
    printf("cow: parent-saw=%s child-kept-its-own=%s\n", seen, child == 0 ? "yes" : "no");
    free(heap);
    close(to_child[0]);
    close(to_child[1]);
    close(to_parent[0]);
    close(to_parent[1]);
}

// MAP_SHARED memory stays shared: a page written before the fork, and two
// that nobody touched before it, written by one side and read by the
// other. A private mapping nobody touched is copied all the same.
static void shared_memory(void) {
    char *shared = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    char *private = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(shared != MAP_FAILED && private != MAP_FAILED, "mmap");
    shared[0] = 'a';
    int to_child[2], to_parent[2];
    check(pipe(to_child) == 0 && pipe(to_parent) == 0, "pipe");
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        shared[0] = 'C';
        shared[2 * 4096 + 100] = 'D';
        private[0] = 'X';
        send_byte(to_parent[1]);
        wait_byte(to_child[0]);
        _exit(shared[4096 + 5]);
    }
    wait_byte(to_parent[0]);
    printf("shared: parent-sees=%c%c private-untouched=%d\n", shared[0], shared[2 * 4096 + 100],
           private[0]);
    shared[4096 + 5] = 'P';
    send_byte(to_child[1]);
    printf("shared: child-sees=%c\n", status_of(pid));
    munmap(shared, 3 * 4096);
    munmap(private, 4096);
    close(to_child[0]);
    close(to_child[1]);
    close(to_parent[0]);
    close(to_parent[1]);
}

static void exec_child(const char *word) {
    char *argv[] = {(char *)self, "exec-child", (char *)word, NULL};
    execve(self, argv, environ);
    _exit(127);
}

static void fork_exec_vfork_spawn(void) {
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) exec_child("forked");
    printf("fork+exec: status %d\n", status_of(pid));

    pid = vfork();
    check(pid >= 0, "vfork");
    if (pid == 0) exec_child("vforked");
    printf("vfork+exec: status %d\n", status_of(pid));

    pid = vfork();
    check(pid >= 0, "vfork");
    if (pid == 0) _exit(5);
    printf("vfork+_exit: status %d\n", status_of(pid));

    char *argv[] = {(char *)self, "exec-child", "spawned", NULL};
    check(posix_spawn(&pid, self, NULL, NULL, argv, environ) == 0, "posix_spawn");
    printf("posix_spawn: status %d\n", status_of(pid));
}

static void fork_of_fork(void) {
    data_word = 10;
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        pid_t grandchild = fork();
        check(grandchild >= 0, "fork");
        if (grandchild == 0) {
            data_word = 99;
            _exit(3);
        }
        int status = status_of(grandchild);
        _exit(data_word + status);
    }
    printf("fork of fork: %d, parent still %d\n", status_of(pid), data_word);
}

// A large private address space: every page is shared after the fork and
// copied by whichever side writes it.
static void big(void) {
    size_t len = 64 << 20;
    unsigned char *mem = malloc(len);
    check(mem != NULL, "malloc");
    for (size_t i = 0; i < len; i += 4096) mem[i] = (unsigned char)(i >> 12);
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        int ok = 1;
        for (size_t i = 0; i < len; i += 4096) {
            ok &= mem[i] == (unsigned char)(i >> 12);
            mem[i] = 0xee;
        }
        _exit(ok ? 0 : 1);
    }
    int child = status_of(pid);
    int ok = 1;
    for (size_t i = 0; i < len; i += 4096) ok &= mem[i] == (unsigned char)(i >> 12);
    printf("big: 64 MiB child=%s parent=%s\n", child == 0 ? "ok" : "bad", ok ? "ok" : "bad");
    free(mem);
}

static void many_children(void) {
    pid_t pids[5];
    for (int i = 0; i < 5; i++) {
        pids[i] = fork();
        check(pids[i] >= 0, "fork");
        if (pids[i] == 0) {
            usleep(1000 * (5 - i));
            _exit(i + 1);
        }
    }
    int sum = 0, n = 0, status;
    pid_t got;
    while ((got = wait(&status)) > 0) {
        n++;
        sum += WEXITSTATUS(status);
    }
    check(errno == ECHILD, "wait until ECHILD");
    printf("wait: %d children, sum %d\n", n, sum);
}

static void pipe_between_children(void) {
    int fds[2];
    check(pipe(fds) == 0, "pipe");
    pid_t writer = fork();
    check(writer >= 0, "fork");
    if (writer == 0) {
        close(fds[0]);
        char buf[4096];
        memset(buf, 'w', sizeof buf);
        for (int i = 0; i < 25; i++) check(write(fds[1], buf, sizeof buf) == sizeof buf, "write");
        _exit(0);
    }
    pid_t reader = fork();
    check(reader >= 0, "fork");
    if (reader == 0) {
        close(fds[1]);
        char buf[1000];
        long total = 0;
        ssize_t n;
        while ((n = read(fds[0], buf, sizeof buf)) > 0) total += n;
        _exit(total == 25 * 4096 ? 0 : 1);
    }
    close(fds[0]);
    close(fds[1]);
    int w = status_of(writer), r = status_of(reader);
    printf("pipe: writer %d reader %d\n", w, r);
}

// A child that never makes a system call must not keep its parent from
// running: the parent makes system calls and sleeps, then kills it.
static void busy_child(void) {
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        volatile unsigned long spin = 0;
        for (;;) spin++;
    }
    double start = now();
    for (int i = 0; i < 200; i++) getppid();
    for (int i = 0; i < 10; i++) usleep(1000);
    double took = now() - start;
    kill(pid, SIGKILL);
    printf("busy child: parent ran, child ended by %d\n", status_of(pid) - 1000);
    fprintf(stderr, "busy child: the parent's work took %.1f ms\n", took * 1e3);
}

// Every process forks as fast as it can, children too, until 200 forks
// have failed in all or `seconds` have passed, then exits; pid 1 (this
// program) reaps everything, orphans included. Forks must start failing
// (EAGAIN or ENOMEM) when the sandbox's limits are reached, and
// everything must end. A shared page counts.
static int bomb(double seconds) {
    struct counts {
        long forks, eagain, enomem, other;
    };
    struct counts *c =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check(c != MAP_FAILED, "mmap");
    double end = now() + seconds;
    pid_t root = fork();
    check(root >= 0, "fork");
    if (root == 0) {
        char touched[8192];
        while (now() < end && __atomic_load_n(&c->eagain, __ATOMIC_RELAXED) +
                                      __atomic_load_n(&c->enomem, __ATOMIC_RELAXED) +
                                      __atomic_load_n(&c->other, __ATOMIC_RELAXED) <
                                  200) {
            pid_t pid = fork();
            if (pid == 0) {
                // A new process: write some of its stack (copies).
                memset(touched, 1, sizeof touched);
                continue;
            }
            if (pid > 0) {
                __atomic_add_fetch(&c->forks, 1, __ATOMIC_RELAXED);
            } else if (errno == EAGAIN) {
                __atomic_add_fetch(&c->eagain, 1, __ATOMIC_RELAXED);
                usleep(1000);
            } else if (errno == ENOMEM) {
                __atomic_add_fetch(&c->enomem, 1, __ATOMIC_RELAXED);
                usleep(1000);
            } else {
                __atomic_add_fetch(&c->other, 1, __ATOMIC_RELAXED);
                usleep(1000);
            }
        }
        _exit(0);
    }
    int status;
    long reaped = 0, killed = 0;
    for (;;) {
        pid_t got = wait(&status);
        if (got > 0) {
            reaped++;
            if (WIFSIGNALED(status)) killed++;
            continue;
        }
        if (errno == EINTR) continue;
        break;
    }
    printf("bomb: ended, forks failed: %s, other errors: %ld\n",
           c->eagain + c->enomem > 0 ? "yes" : "no", c->other);
    fprintf(stderr, "bomb: %ld forks, %ld EAGAIN, %ld ENOMEM, %ld reaped, %ld killed\n",
            c->forks, c->eagain, c->enomem, reaped, killed);
    return 0;
}

static int bench(int rounds, int mib) {
    double start = now();
    for (int i = 0; i < rounds; i++) {
        pid_t pid = fork();
        if (pid == 0) _exit(0);
        check(status_of(pid) == 0, "child");
    }
    double round_trip = (now() - start) / rounds;
    size_t len = (size_t)mib << 20;
    unsigned char *mem = malloc(len);
    check(mem != NULL, "malloc");
    for (size_t i = 0; i < len; i += 4096) mem[i] = 1;
    start = now();
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    double forked = now() - start;
    check(status_of(pid) == 0, "child");
    double whole = now() - start;
    // The child writes every page: each one is copied.
    start = now();
    pid = fork();
    if (pid == 0) {
        for (size_t i = 0; i < len; i += 4096) mem[i] = 2;
        _exit(0);
    }
    check(status_of(pid) == 0, "child");
    double copied = now() - start;
    // Ping-pong: every round trip switches address spaces twice, and each
    // side then touches its working set of 64 pages again.
    int ping[2], pong[2];
    check(pipe(ping) == 0 && pipe(pong) == 0, "pipe");
    volatile unsigned char *set = malloc(64 * 4096);
    check(set != NULL, "malloc");
    for (int i = 0; i < 64; i++) set[i * 4096] = 1;
    pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        for (int i = 0; i < rounds; i++) {
            wait_byte(ping[0]);
            unsigned sum = 0;
            for (int j = 0; j < 64; j++) sum += set[j * 4096];
            (void)sum;
            send_byte(pong[1]);
        }
        _exit(0);
    }
    start = now();
    for (int i = 0; i < rounds; i++) {
        send_byte(ping[1]);
        unsigned sum = 0;
        for (int j = 0; j < 64; j++) sum += set[j * 4096];
        (void)sum;
        wait_byte(pong[0]);
    }
    double ping_pong = (now() - start) / rounds;
    check(status_of(pid) == 0, "child");
    printf("bench: fork+exit+wait %.1f us; with %d MiB touched: fork %.3f ms, "
           "fork+exit+wait %.3f ms, child writing every page %.1f ms; "
           "pipe round trip %.1f us\n",
           round_trip * 1e6, mib, forked * 1e3, whole * 1e3, copied * 1e3, ping_pong * 1e6);
    return 0;
}

int main(int argc, char **argv) {
    self = argv[0];
    if (argc == 3 && strcmp(argv[1], "exec-child") == 0) {
        printf("exec: child %s\n", argv[2]);
        return 7;
    }
    if (argc == 3 && strcmp(argv[1], "bomb") == 0) return bomb(atof(argv[2]));
    if (argc == 4 && strcmp(argv[1], "bench") == 0) return bench(atoi(argv[2]), atoi(argv[3]));
    // Line buffered even into a pipe, so no child inherits unwritten
    // output.
    setvbuf(stdout, NULL, _IOLBF, 0);
    fork_and_wait();
    copy_on_write();
    shared_memory();
    fork_exec_vfork_spawn();
    fork_of_fork();
    big();
    many_children();
    pipe_between_children();
    busy_child();
    return 0;
}
