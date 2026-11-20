// Threads that run at the same time: CPU work that scales with the
// number of CPUs, and the cases where the kernel must keep every CPU's
// view of an address space right while other threads of it run: fork
// (write protection of the parent), mprotect, munmap, copy-on-write
// with concurrent writers, futex ping-pong, a signal to a thread that
// never makes a system call, exit_group and execve while other threads
// spin, and a process that makes system calls next to many spinners.
//
//   smp scale THREADS ITERS   CPU work; prints the sum and the time
//   smp syscalls THREADS N    N getppid calls in each thread; prints the
//                             time per call
//   smp all                   every other check, one line each
//   smp CHECK                 one of them (see main)
//
// Keep in sync with platform-hvf/tests/guests.rs and hellovm/tests/smp.rs.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096

static long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000L + ts.tv_nsec / 1000;
}

static void fail(const char *check, const char *why) {
    printf("%s: FAILED: %s\n", check, why);
    exit(1);
}

#ifdef __aarch64__
static void load_relaxed_spin(void) { __asm__ volatile("yield" ::: "memory"); }
#else
static void load_relaxed_spin(void) { __asm__ volatile("pause" ::: "memory"); }
#endif

// Waits until *flag is set, or fails after `ms` milliseconds.
static void wait_set(volatile int *flag, int ms, const char *check, const char *what) {
    long deadline = now_us() + ms * 1000L;
    while (!__atomic_load_n(flag, __ATOMIC_ACQUIRE)) {
        if (now_us() > deadline) fail(check, what);
        usleep(100);
    }
}

// ---- scale ----------------------------------------------------------

// The same function as `scale_sum` in the tests that run this.
static uint64_t work(uint64_t seed, long iters) {
    uint64_t x = seed * 0x9e3779b97f4a7c15ull + 1;
    uint64_t acc = 0;
    for (long i = 0; i < iters; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        acc += x >> 3;
    }
    return acc;
}

struct scale_arg {
    long id, iters;
    uint64_t out;
};

static void *scale_thread(void *p) {
    struct scale_arg *a = p;
    a->out = work((uint64_t)a->id, a->iters);
    return NULL;
}

static int scale(int threads, long iters) {
    if (threads < 1 || threads > 64) return 2;
    struct scale_arg args[64];
    pthread_t t[64];
    long start = now_us();
    for (int i = 0; i < threads; i++) {
        args[i] = (struct scale_arg){.id = i, .iters = iters};
        pthread_create(&t[i], NULL, scale_thread, &args[i]);
    }
    uint64_t sum = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(t[i], NULL);
        sum += args[i].out;
    }
    printf("scale: threads=%d sum=%016llx ms=%ld\n", threads, (unsigned long long)sum,
           (now_us() - start) / 1000);
    return 0;
}

// ---- system calls from several threads at once -------------------------

static long syscall_count;

static void *syscall_thread(void *p) {
    (void)p;
    for (long i = 0; i < syscall_count; i++) getppid();
    return NULL;
}

static int syscalls(int threads, long n) {
    if (threads < 1 || threads > 64) return 2;
    syscall_count = n;
    pthread_t t[64];
    long start = now_us();
    for (int i = 0; i < threads; i++) pthread_create(&t[i], NULL, syscall_thread, NULL);
    for (int i = 0; i < threads; i++) pthread_join(t[i], NULL);
    long us = now_us() - start;
    printf("syscalls: threads=%d calls=%ld ns-per-call=%ld\n", threads, threads * n,
           us * 1000 / (threads * n));
    return 0;
}

// ---- fork while other threads write ----------------------------------

#define WRITERS 3
static volatile int fw_stop;
static char *fw_pages;

static void *fw_writer(void *p) {
    volatile long *mine = (volatile long *)(fw_pages + (long)p * PAGE);
    while (!fw_stop) (*mine)++;
    return NULL;
}

// The child's copy must not change after the fork: the parent's writers,
// running on other CPUs, write their own copies from the fork on.
static void fork_while_writing(void) {
    const char *check = "fork-while-writing";
    fw_pages = mmap(NULL, WRITERS * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pthread_t t[WRITERS];
    for (long i = 0; i < WRITERS; i++) pthread_create(&t[i], NULL, fw_writer, (void *)i);
    for (int i = 0; i < WRITERS; i++)
        while (*(volatile long *)(fw_pages + i * PAGE) < 1000) usleep(100);
    for (int round = 0; round < 20; round++) {
        pid_t child = fork();
        if (child == 0) {
            long before[WRITERS], after[WRITERS];
            for (int i = 0; i < WRITERS; i++) before[i] = *(volatile long *)(fw_pages + i * PAGE);
            usleep(3000);
            for (int i = 0; i < WRITERS; i++) after[i] = *(volatile long *)(fw_pages + i * PAGE);
            _exit(memcmp(before, after, sizeof before) == 0 ? 0 : 1);
        }
        long seen[WRITERS];
        for (int i = 0; i < WRITERS; i++) seen[i] = *(volatile long *)(fw_pages + i * PAGE);
        int status;
        if (waitpid(child, &status, 0) != child) fail(check, "waitpid");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            fail(check, "the child's copy changed after the fork");
        // The writers go on, with copies of their own.
        long deadline = now_us() + 5000000;
        for (int i = 0; i < WRITERS; i++)
            while (*(volatile long *)(fw_pages + i * PAGE) <= seen[i]) {
                if (now_us() > deadline) fail(check, "a writer stopped");
                usleep(100);
            }
    }
    fw_stop = 1;
    for (int i = 0; i < WRITERS; i++) pthread_join(t[i], NULL);
    puts("fork-while-writing: ok");
}

// ---- mprotect and munmap reach a thread that is running ---------------

static __thread sigjmp_buf fault_jmp;
static __thread volatile int fault_armed;
// Rounds: the writer writes in round `writing`, faults once (`faults`),
// and waits for `go` before it writes again.
static volatile int writing, faults, go, quit;

static void on_segv(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    if (!fault_armed) _exit(99);
    fault_armed = 0;
    __atomic_add_fetch(&faults, 1, __ATOMIC_ACQ_REL);
    siglongjmp(fault_jmp, 1);
}

static void catch_segv(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
}

static volatile long *mp_word;

// Round r: writes *mp_word until a write faults, then waits for go > r.
static void *mp_writer(void *p) {
    long signature = (long)p;
    // Volatile: it lives across siglongjmp.
    for (volatile int round = 0;; round++) {
        while (__atomic_load_n(&go, __ATOMIC_ACQUIRE) < round)
            if (quit) return NULL;
        if (quit) return NULL;
        if (sigsetjmp(fault_jmp, 1) == 0) {
            fault_armed = 1;
            __atomic_store_n(&writing, round + 1, __ATOMIC_RELEASE);
            for (long i = 0;; i++) *mp_word = signature + (i & 0xffff);
        }
    }
}

static void wait_count(volatile int *count, int want, const char *check, const char *what) {
    long deadline = now_us() + 5000000L;
    while (__atomic_load_n(count, __ATOMIC_ACQUIRE) < want) {
        if (now_us() > deadline) fail(check, what);
        usleep(100);
    }
}

static void start_writer(pthread_t *t, long signature) {
    catch_segv();
    writing = faults = go = quit = 0;
    pthread_create(t, NULL, mp_writer, (void *)signature);
}

// The writer may be writing again: without the page its next write
// faults, and then it sees `quit`.
static void stop_writer(pthread_t t, int rounds, char *page) {
    quit = 1;
    __atomic_store_n(&go, rounds + 1, __ATOMIC_RELEASE);
    mprotect(page, PAGE, PROT_NONE);
    pthread_join(t, NULL);
}

// After mprotect(PROT_READ) returns, no write of the running thread may
// land, and its next write faults.
static void mprotect_while_writing(void) {
    const char *check = "mprotect-while-writing";
    char *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mp_word = (volatile long *)page;
    pthread_t t;
    start_writer(&t, 0x5100000000L);
    for (int round = 0; round < 20; round++) {
        wait_count(&writing, round + 1, check, "the writer did not start");
        usleep(2000);
        mprotect(page, PAGE, PROT_READ);
        long first = *mp_word;
        usleep(5000);
        if (*mp_word != first) fail(check, "a write landed after mprotect returned");
        wait_count(&faults, round + 1, check, "the writer did not fault");
        mprotect(page, PAGE, PROT_READ | PROT_WRITE);
        __atomic_store_n(&go, round + 1, __ATOMIC_RELEASE);
    }
    stop_writer(t, 20, page);
    munmap(page, PAGE);
    puts("mprotect-while-writing: ok rounds=20");
}

// After munmap returns, the running thread faults, and none of its
// writes reach the memory mapped next (where the frame may be reused).
static void munmap_while_writing(void) {
    const char *check = "munmap-while-writing";
    const long signature = 0x7700000000L;
    // Two pages: the second keeps the first's address from being
    // reused by the mapping below while the first is unmapped.
    char *page = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(page + PAGE, PAGE, PROT_NONE);
    mp_word = (volatile long *)page;
    pthread_t t;
    start_writer(&t, signature);
    for (int round = 0; round < 20; round++) {
        wait_count(&writing, round + 1, check, "the writer did not start");
        usleep(2000);
        munmap(page, PAGE);
        // The address stays unmapped: a placeholder that is never valid.
        if (mmap(page, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != page)
            fail(check, "mmap PROT_NONE");
        // Memory mapped now may get the frame the page had.
        char *fresh = mmap(NULL, 256 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 256; i++) fresh[i * PAGE + 8] = 1;
        wait_count(&faults, round + 1, check, "the writer did not fault");
        usleep(2000);
        for (long i = 0; i < 256 * PAGE / 8; i++) {
            long v = ((volatile long *)fresh)[i];
            if ((v & ~0xffffL) == signature) fail(check, "a write reached a frame after munmap");
        }
        munmap(fresh, 256 * PAGE);
        if (mmap(page, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != page)
            fail(check, "mmap");
        if (*(volatile long *)page != 0) fail(check, "the new page is not zero");
        __atomic_store_n(&go, round + 1, __ATOMIC_RELEASE);
    }
    stop_writer(t, 20, page);
    munmap(page, 2 * PAGE);
    puts("munmap-while-writing: ok rounds=20");
}

// ---- copy-on-write with concurrent writers ----------------------------

#define COW_THREADS 4
#define COW_PAGES 64
static char *cow_data, *cow_flags;
static volatile int cow_go, cow_round;
static volatile int cow_bad;

static void *cow_thread(void *p) {
    long id = (long)p;
    for (int round = 1; round <= 10; round++) {
        while (__atomic_load_n(&cow_go, __ATOMIC_ACQUIRE) < round) load_relaxed_spin();
        // Every thread writes its own word of every page, at once.
        for (int i = 0; i < COW_PAGES; i++)
            ((volatile long *)(cow_data + i * PAGE))[id + 8] = round * 100 + id;
        if (id == 0) {
            // Data then flag, each on a copy-on-write page; thread 1 must
            // see the data once it sees the flag.
            for (int i = 0; i < COW_PAGES; i++) {
                ((volatile long *)(cow_data + i * PAGE))[0] = round;
                __atomic_store_n((long *)(cow_flags + i * PAGE), round, __ATOMIC_RELEASE);
            }
        } else if (id == 1) {
            for (int i = 0; i < COW_PAGES; i++) {
                long deadline = now_us() + 5000000;
                while (__atomic_load_n((long *)(cow_flags + i * PAGE), __ATOMIC_ACQUIRE) != round)
                    if (now_us() > deadline) {
                        cow_bad = 1;
                        break;
                    }
                if (((volatile long *)(cow_data + i * PAGE))[0] != round) cow_bad = 2;
            }
        }
        __atomic_add_fetch(&cow_round, 1, __ATOMIC_ACQ_REL);
    }
    return NULL;
}

// Before each round the process forks: every page is copy-on-write
// again, and the threads write it at the same time. No write is lost,
// the child's copy keeps what it had, and data written before a flag is
// seen with it.
static void cow_concurrent_writers(void) {
    const char *check = "cow-concurrent-writers";
    cow_data = mmap(NULL, COW_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    cow_flags = mmap(NULL, COW_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(cow_data, 0x11, COW_PAGES * PAGE);
    memset(cow_flags, 0, COW_PAGES * PAGE);
    pthread_t t[COW_THREADS];
    for (long i = 0; i < COW_THREADS; i++) pthread_create(&t[i], NULL, cow_thread, (void *)i);
    for (int round = 1; round <= 10; round++) {
        pid_t child = fork();
        if (child == 0) {
            long first = ((volatile long *)cow_data)[8];
            usleep(20000);
            int same = ((volatile long *)cow_data)[8] == first;
            _exit(same ? 0 : 1);
        }
        __atomic_store_n(&cow_go, round, __ATOMIC_RELEASE);
        while (__atomic_load_n(&cow_round, __ATOMIC_ACQUIRE) < round * COW_THREADS) usleep(100);
        if (cow_bad == 1) fail(check, "a flag was never seen");
        if (cow_bad == 2) fail(check, "data written before a flag was not seen with it");
        for (int i = 0; i < COW_PAGES; i++)
            for (long id = 0; id < COW_THREADS; id++)
                if (((long *)(cow_data + i * PAGE))[id + 8] != round * 100 + id)
                    fail(check, "a write was lost");
        int status;
        waitpid(child, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) fail(check, "the child's copy changed");
    }
    for (int i = 0; i < COW_THREADS; i++) pthread_join(t[i], NULL);
    puts("cow-concurrent-writers: ok rounds=10");
}

// ---- futex ping-pong --------------------------------------------------

static int ping, pong;

static long futex(int *addr, int op, int val) {
    return syscall(SYS_futex, addr, op | FUTEX_PRIVATE_FLAG, val, NULL, NULL, 0);
}

#define PINGS 20000

static void *ponger(void *p) {
    (void)p;
    for (int i = 1; i <= PINGS; i++) {
        while (__atomic_load_n(&ping, __ATOMIC_ACQUIRE) < i) futex(&ping, FUTEX_WAIT, i - 1);
        __atomic_store_n(&pong, i, __ATOMIC_RELEASE);
        futex(&pong, FUTEX_WAKE, 1);
    }
    return NULL;
}

static void futex_ping_pong(void) {
    pthread_t t;
    pthread_create(&t, NULL, ponger, NULL);
    long start = now_us();
    for (int i = 1; i <= PINGS; i++) {
        __atomic_store_n(&ping, i, __ATOMIC_RELEASE);
        futex(&ping, FUTEX_WAKE, 1);
        while (__atomic_load_n(&pong, __ATOMIC_ACQUIRE) < i) futex(&pong, FUTEX_WAIT, i - 1);
    }
    long us = now_us() - start;
    pthread_join(t, NULL);
    printf("futex-ping-pong: ok rounds=%d\n", PINGS);
    fprintf(stderr, "futex-ping-pong: %ld ns per round trip\n", us * 1000 / PINGS);
}

// ---- a signal to a thread that never makes a system call ---------------

static volatile int sig_seen;
static volatile int spin_ready;

static void on_usr1(int sig) {
    (void)sig;
    sig_seen = 1;
}

static void *spin_until_signal(void *p) {
    (void)p;
    __atomic_store_n(&spin_ready, 1, __ATOMIC_RELEASE);
    while (!sig_seen) {
    }
    return NULL;
}

static void signal_to_running_thread(void) {
    const char *check = "signal-to-running-thread";
    signal(SIGUSR1, on_usr1);
    for (int round = 0; round < 20; round++) {
        sig_seen = 0;
        spin_ready = 0;
        pthread_t t;
        pthread_create(&t, NULL, spin_until_signal, NULL);
        wait_set(&spin_ready, 5000, check, "the thread did not start");
        usleep(2000);
        pthread_kill(t, SIGUSR1);
        wait_set(&sig_seen, 5000, check, "the signal was not handled");
        pthread_join(t, NULL);
    }
    puts("signal-to-running-thread: ok rounds=20");
}

// ---- a process that makes system calls next to spinners ---------------

static volatile int spinners_stop;

static void *spinner(void *p) {
    (void)p;
    while (!spinners_stop) {
    }
    return NULL;
}

static void syscalls_next_to_spinners(void) {
    const char *check = "syscalls-next-to-spinners";
    pthread_t t[16];
    for (int i = 0; i < 16; i++) pthread_create(&t[i], NULL, spinner, NULL);
    long start = now_us();
    for (int i = 0; i < 300; i++) getppid();
    long ms = (now_us() - start) / 1000;
    spinners_stop = 1;
    for (int i = 0; i < 16; i++) pthread_join(t[i], NULL);
    // One slice (5 ms) per call at most would be 1.5 s.
    if (ms > 3000) fail(check, "the system calls waited behind the spinners");
    puts("syscalls-next-to-spinners: ok");
    fprintf(stderr, "syscalls-next-to-spinners: 300 calls in %ld ms\n", ms);
}

// ---- exit_group and execve while other threads spin ----------------------

static void *spin_forever(void *p) {
    (void)p;
    for (;;) {
    }
    return NULL;
}

static int exit_while_spinning(void) {
    pthread_t t[8];
    for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, spin_forever, NULL);
    usleep(20000);
    puts("exit-group: exiting");
    syscall(SYS_exit_group, 7);
    return 1;
}

static void *exit_group_thread(void *p) {
    (void)p;
    usleep(20000);
    puts("exit-group-from-thread: exiting");
    syscall(SYS_exit_group, 8);
    return NULL;
}

static int exit_from_thread(void) {
    pthread_t t[8], last;
    for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, spin_forever, NULL);
    pthread_create(&last, NULL, exit_group_thread, NULL);
    spin_forever(NULL);
    return 1;
}

static int exec_while_spinning(const char *self) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, spin_forever, NULL);
    usleep(20000);
    execl(self, self, "exec-done", (char *)NULL);
    puts("exec-while-spinning: FAILED: execl");
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *what = argc > 1 ? argv[1] : "all";
    if (!strcmp(what, "scale") && argc == 4) return scale(atoi(argv[2]), atol(argv[3]));
    if (!strcmp(what, "syscalls") && argc == 4) return syscalls(atoi(argv[2]), atol(argv[3]));
    if (!strcmp(what, "exit-group")) return exit_while_spinning();
    if (!strcmp(what, "exit-group-from-thread")) return exit_from_thread();
    if (!strcmp(what, "exec")) return exec_while_spinning(argv[0]);
    if (!strcmp(what, "exec-done")) {
        puts("exec-while-spinning: ok");
        return 0;
    }
    int all = !strcmp(what, "all");
    if (all || !strcmp(what, "fork-while-writing")) fork_while_writing();
    if (all || !strcmp(what, "mprotect-while-writing")) mprotect_while_writing();
    if (all || !strcmp(what, "munmap-while-writing")) munmap_while_writing();
    if (all || !strcmp(what, "cow-concurrent-writers")) cow_concurrent_writers();
    if (all || !strcmp(what, "futex-ping-pong")) futex_ping_pong();
    if (all || !strcmp(what, "signal-to-running-thread")) signal_to_running_thread();
    if (all || !strcmp(what, "syscalls-next-to-spinners")) syscalls_next_to_spinners();
    return 0;
}
