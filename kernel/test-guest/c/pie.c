// A static-PIE glibc program: exercises self-relocation, TLS, brk and mmap
// (a large malloc), stdio and the auxiliary vector. Keep the output format
// in sync with the test in hellovm/tests/sandbox.rs.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

static __thread int tls_counter = 41;

int main(int argc, char **argv) {
    tls_counter++;
    char *big = malloc(1 << 20);
    memset(big, 'x', 1 << 20);
    char *small = malloc(100);
    strcpy(small, "small");
    unsigned char *random = (unsigned char *)getauxval(AT_RANDOM);
    printf("main=%p argc=%d argv1=%s tls=%d big=%c %s pagesz=%lu random=%s\n",
           (void *)main, argc, argc > 1 ? argv[1] : "-", tls_counter,
           big[12345], small, getauxval(AT_PAGESZ),
           random != NULL ? "yes" : "no");
    free(big);
    free(small);
    return 0;
}
