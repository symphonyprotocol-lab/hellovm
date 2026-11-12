// Signal delivery end to end: fault handlers, masks, timers, the alternate
// stack, restarts, child status and FP state across asynchronous handlers.
// Prints one line per check; keep in sync with hellovm/tests/signals.rs.
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static sigjmp_buf jump;
static volatile sig_atomic_t got;
static volatile sig_atomic_t ticks;
static void *volatile fault_addr;
static char altstack[65536];
static volatile int on_altstack;

static void on_segv(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)uc;
    fault_addr = info->si_addr;
    siglongjmp(jump, 1);
}

static void on_signal(int sig) { got = sig; }

static void on_tick(int sig) {
    (void)sig;
    // Clobber FP registers; the interrupted code must not notice.
    volatile double x = 1.5;
    for (int i = 0; i < 20; i++) x = x * 3.25 + 0.5;
    ticks++;
}

static void on_usr2(int sig) {
    (void)sig;
    char local;
    on_altstack = &local >= altstack && &local < altstack + sizeof altstack;
}

static void set_handler(int sig, void (*handler)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

static void interval(long usec) {
    struct itimerval it = {{0, usec}, {0, usec}};
    setitimer(ITIMER_REAL, &it, NULL);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// A read of a pipe that gets data from a child after 300 ms, with a
// SIGALRM after 100 ms.
static void interrupted_read(int flags) {
    int fds[2];
    pipe(fds);
    pid_t child = fork();
    if (child == 0) {
        usleep(300000);
        write(fds[1], "x", 1);
        _exit(0);
    }
    set_handler(SIGALRM, on_signal, flags);
    struct itimerval it = {{0, 0}, {0, 100000}};
    setitimer(ITIMER_REAL, &it, NULL);
    char c;
    ssize_t n = read(fds[0], &c, 1);
    int err = errno;
    printf("read %s: %zd %s\n", flags & SA_RESTART ? "restart" : "eintr", n,
           n < 0 ? strerror(err) : "data");
    waitpid(child, NULL, 0);
    close(fds[0]);
    close(fds[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    // A fault becomes a signal the program handles.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    if (sigsetjmp(jump, 1) == 0) {
        *(volatile int *)0x10 = 1;
        puts("segv: not caught");
    } else {
        printf("segv: caught at %p\n", fault_addr);
    }

    set_handler(SIGUSR1, on_signal, 0);
    raise(SIGUSR1);
    printf("raise: %d\n", got);

    // A blocked signal stays pending until it is unblocked.
    sigset_t set, old, pending;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);
    got = 0;
    kill(getpid(), SIGUSR1);
    sigpending(&pending);
    printf("blocked: pending=%d got=%d\n", sigismember(&pending, SIGUSR1), got);
    sigprocmask(SIG_SETMASK, &old, NULL);
    printf("unblocked: got=%d\n", got);

    // alarm and pause.
    set_handler(SIGALRM, on_signal, 0);
    got = 0;
    alarm(1);
    pause();
    printf("alarm: %d\n", got);

    // sigsuspend with the signal blocked outside of it.
    sigprocmask(SIG_BLOCK, &set, &old);
    kill(getpid(), SIGUSR1);
    got = 0;
    sigset_t during;
    sigemptyset(&during);
    int r = sigsuspend(&during);
    sigset_t after;
    sigprocmask(SIG_SETMASK, NULL, &after);
    printf("sigsuspend: %d %s got=%d still-blocked=%d\n", r, strerror(errno), got,
           sigismember(&after, SIGUSR1));
    sigprocmask(SIG_SETMASK, &old, NULL);

    // The alternate signal stack.
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    set_handler(SIGUSR2, on_usr2, SA_ONSTACK);
    raise(SIGUSR2);
    printf("altstack: %d\n", on_altstack);

    // Asynchronous signals interrupt a loop that makes no syscalls, and
    // the loop's floating-point state survives the handlers.
    set_handler(SIGALRM, on_tick, SA_RESTART);
    interval(2000);
    double sum = 0, start = now();
    long rounds = 0;
    while (ticks < 20 && now() - start < 10) {
        for (int i = 1; i <= 1000; i++) sum += 1.0 / i;
        rounds++;
    }
    interval(0);
    double expected = 0;
    for (long k = 0; k < rounds; k++)
        for (int i = 1; i <= 1000; i++) expected += 1.0 / i;
    printf("ticks: %s fp: %s\n", ticks >= 20 ? "ok" : "missing",
           sum == expected ? "ok" : "corrupted");

    interrupted_read(SA_RESTART);
    interrupted_read(0);
    set_handler(SIGALRM, SIG_DFL, 0);

    // How children end.
    pid_t child = fork();
    if (child == 0) {
        raise(SIGTERM);
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);
    printf("child term: signaled=%d sig=%d core=%d\n", WIFSIGNALED(status),
           WTERMSIG(status), !!WCOREDUMP(status));
    child = fork();
    if (child == 0) {
        signal(SIGSEGV, SIG_DFL);
        *(volatile int *)0x10 = 1;
        _exit(1);
    }
    waitpid(child, &status, 0);
    printf("child segv: signaled=%d sig=%d core=%d\n", WIFSIGNALED(status),
           WTERMSIG(status), !!WCOREDUMP(status));

    // SIGCHLD reaches a handler, and a stopped child is reported.
    set_handler(SIGCHLD, on_signal, SA_RESTART);
    got = 0;
    child = fork();
    if (child == 0) {
        raise(SIGSTOP);
        _exit(5);
    }
    waitpid(child, &status, WUNTRACED);
    printf("stopped: %d sig=%d\n", WIFSTOPPED(status), WSTOPSIG(status));
    kill(child, SIGCONT);
    waitpid(child, &status, 0);
    printf("continued and exited: %d sigchld=%d\n", WEXITSTATUS(status), got == SIGCHLD);
    set_handler(SIGCHLD, SIG_DFL, 0);

    // One blocking write to a pipe is complete, even when it is bigger
    // than the pipe and the reader is slow.
    int fds[2];
    if (pipe(fds) != 0) return 1;
    child = fork();
    if (child == 0) {
        close(fds[1]);
        usleep(100000);
        char buf[4096];
        long total = 0;
        ssize_t n;
        while ((n = read(fds[0], buf, sizeof buf)) > 0) total += n;
        _exit(total == 300000 ? 0 : 1);
    }
    close(fds[0]);
    static char big[300000];
    ssize_t wrote = write(fds[1], big, sizeof big);
    close(fds[1]);
    waitpid(child, &status, 0);
    printf("pipe write: %zd reader=%d\n", wrote, WEXITSTATUS(status));

    // A signal that runs no handler (SIGCONT of a process that is not
    // stopped) does not make a sleep start over.
    child = fork();
    if (child == 0) {
        double start = now();
        struct timespec ts = {1, 0};
        int r = nanosleep(&ts, NULL);
        double took = now() - start;
        _exit(r == 0 && took > 0.9 && took < 1.4 ? 0 : 1);
    }
    usleep(700000);
    kill(child, SIGCONT);
    waitpid(child, &status, 0);
    printf("sleep keeps its deadline: %d\n", WEXITSTATUS(status) == 0);

    // A handler interrupts a sleep, which reports the time left.
    set_handler(SIGALRM, on_signal, 0);
    struct itimerval once = {{0, 0}, {0, 300000}};
    setitimer(ITIMER_REAL, &once, NULL);
    struct timespec req = {1, 0}, rem = {9, 9};
    errno = 0;
    int slept = nanosleep(&req, &rem);
    double left = rem.tv_sec + rem.tv_nsec / 1e9;
    printf("sleep eintr: %d rem-ok=%d\n", slept, errno == EINTR && left > 0.4 && left < 0.75);
    set_handler(SIGALRM, SIG_DFL, 0);

    // SIGKILL ends a process that waits for its vfork child.
    child = fork();
    if (child == 0) {
        if (vfork() == 0) {
            struct timespec ts = {5, 0};
            nanosleep(&ts, NULL);
            _exit(0);
        }
        _exit(0);
    }
    usleep(200000);
    double killed_at = now();
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    printf("vfork parent killed: %d fast=%d\n",
           WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, now() - killed_at < 2.0);

    // Sharing the kernel cannot provide is refused, not silently dropped.
    errno = 0;
    long cloned = syscall(SYS_clone, CLONE_VM | CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if (cloned == 0) _exit(0);
    printf("clone sharing refused: %ld %d\n", cloned, errno == EINVAL);
    return 0;
}
