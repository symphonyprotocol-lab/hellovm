// A static-PIE glibc program: exercises self-relocation, TLS, brk (the small
// malloc), mmap/munmap, stdio and the auxiliary vector. Keep the output
// format in sync with the test in hellovm/tests/sandbox.rs.
//
// The large region is an explicit mmap/munmap so the sandbox trace
// contains Mmap and Munmap independent of malloc's allocation strategy
// and of compiler optimisation. A large malloc was deleted at -O2 with
// GCC 13.2 and glibc 2.39 (no mmap in the trace); that is not assumed
// for every toolchain.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>

static __thread int tls_counter = 41;

int main(int argc, char **argv) {
    tls_counter++;
    char *big = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (big == MAP_FAILED) {
        return 2;
    }
    memset(big, 'x', 1 << 20);
    char *small = malloc(100);
    if (small == NULL) {
        return 3;
    }
    strcpy(small, "small");
    unsigned char *random = (unsigned char *)getauxval(AT_RANDOM);
    printf("main=%p argc=%d argv1=%s tls=%d big=%c %s pagesz=%lu random=%s\n",
           (void *)main, argc, argc > 1 ? argv[1] : "-", tls_counter,
           big[12345], small, getauxval(AT_PAGESZ),
           random != NULL ? "yes" : "no");
    munmap(big, 1 << 20);
    free(small);
    return 0;
}
