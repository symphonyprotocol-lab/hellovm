// System-call round-trip timings (see hellovm/tests/syscall_bench.rs).
// Usage: syscall_bench [ITERS]. Prints one line per case:
//   <case> <ns per call>
// The cases are the calls an interpreter makes most: a call that only
// returns a value (getppid), small writes and reads that move bytes
// through the kernel (/dev/null, a pipe), and a time query.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
    return 0;
}
