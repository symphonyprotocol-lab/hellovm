// A static glibc program for the HVF platform's prototype (built in the
// Linux dev container by kernel/platform-hvf/build-c-guest.sh, not by
// build.rs): prints its arguments, reads a file, allocates memory with
// malloc (brk) and mmap, and exits with status 3. Keep the output in sync
// with c_program in kernel/platform-hvf/tests/hvf.rs.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]=%s\n", i, argv[i]);
    }
    char buf[128] = {0};
    int fd = open("/greeting.txt", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    printf("read %zd bytes: %s", n, buf);
    char *small = malloc(100);
    strcpy(small, "malloc ok");
    size_t big_len = 8 << 20;
    char *big = mmap(NULL, big_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (big == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memset(big, 'z', big_len);
    printf("%s, mmap ok: %c%c, pid %d\n", small, big[0], big[big_len - 1],
           (int)getpid());
    munmap(big, big_len);
    free(small);
    return 3;
}
