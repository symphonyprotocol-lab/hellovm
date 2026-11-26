// System-call round-trip timings (see hellovm/tests/syscall_bench.rs).
// Usage: syscall_bench [ITERS]. Prints one line per case:
//   <case> <ns per call>
// The cases are the calls an interpreter makes most: a call that only
// returns a value (getppid), small writes and reads that move bytes
// through the kernel (/dev/null, a pipe), a time query, and the memory
// calls an allocator makes (64 KiB mmap + munmap pairs, mprotect of a page,
// brk growing and shrinking by a page).
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void report(const char *name, double start, long iters) {
    printf("%s %.0f\n", name, (now_ns() - start) / (double)iters);
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    char byte = 'x';
    double start;

    start = now_ns();
    for (long i = 0; i < iters; i++) {
        syscall(SYS_getppid);
    }
    report("getppid", start, iters);

    int null = open("/dev/null", O_WRONLY);
    if (null < 0) {
        perror("open /dev/null");
        return 1;
    }
    start = now_ns();
    for (long i = 0; i < iters; i++) {
        if (write(null, &byte, 1) != 1) {
            perror("write /dev/null");
            return 1;
        }
    }
    report("write-devnull", start, iters);

    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    start = now_ns();
    for (long i = 0; i < iters; i++) {
        if (write(fds[1], &byte, 1) != 1 || read(fds[0], &byte, 1) != 1) {
            perror("pipe round trip");
            return 1;
        }
    }
    // Two calls per iteration.
    report("pipe-write-read", start, 2 * iters);

    struct timespec ts;
    start = now_ns();
    for (long i = 0; i < iters; i++) {
        syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    }
    report("clock_gettime", start, iters);

    // Fewer rounds: each is far slower in the sandbox.
    long mem_iters = iters / 10 > 0 ? iters / 10 : 1;
    start = now_ns();
    for (long i = 0; i < mem_iters; i++) {
        void *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED || munmap(p, 65536) != 0) {
            perror("mmap/munmap");
            return 1;
        }
    }
    report("mmap+munmap", start, mem_iters);

    char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    start = now_ns();
    for (long i = 0; i < mem_iters; i++) {
        if (mprotect(page, 4096, (i & 1) ? PROT_READ | PROT_WRITE : PROT_READ) != 0) {
            perror("mprotect");
            return 1;
        }
    }
    report("mprotect", start, mem_iters);

    char *base = (char *)syscall(SYS_brk, 0);
    start = now_ns();
    for (long i = 0; i < mem_iters; i++) {
        syscall(SYS_brk, base + 4096);
        syscall(SYS_brk, base);
    }
    // Two calls per iteration.
    report("brk", start, 2 * mem_iters);
    return 0;
}
