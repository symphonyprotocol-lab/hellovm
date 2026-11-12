// A dynamically linked glibc program (libc and libm from the build host):
// the kernel loads it and its program interpreter, and the interpreter maps
// the libraries. Prints one line; keep in sync with hellovm/tests/dynamic.rs.
#include <dlfcn.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char exe[256] = "";
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) exe[n] = 0;
    // AT_BASE is where the kernel put the interpreter.
    unsigned long base = getauxval(AT_BASE);
    printf("dynamic: arg=%s sqrt2=%.4f interp=%s exe=%s\n", argc > 1 ? argv[1] : "-",
           sqrt(2.0), base != 0 ? "yes" : "no", exe);
    return 0;
}
