// Threads end to end: creation and join (CLONE_CHILD_CLEARTID), TLS,
// mutexes and condition variables under contention (futex wait, wake and
// requeue), timed waits, signals to one thread with per-thread masks,
// robust mutexes, fork from a threaded process and exit_group from a
// thread. Prints one line per check; keep in sync with
// hellovm/tests/threads.rs.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define THREADS 8
#define ROUNDS 2000

static __thread int tls_value;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static long counter;
static int ready;
static pid_t tids[THREADS];

static void *work(void *arg) {
    long id = (long)arg;
    tls_value = (int)id * 10;
    tids[id] = (pid_t)syscall(SYS_gettid);
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
        if (i % 500 == 0) sched_yield();
    }
    return (void *)(long)(tls_value + 1);
}

static void *waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    while (!ready) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    return NULL;
}

static volatile pid_t handled_by;
static void on_usr1(int sig) {
    (void)sig;
    handled_by = (pid_t)syscall(SYS_gettid);
}

static volatile int target_ready, target_go;
static pid_t target_tid;
static void *signal_target(void *arg) {
    (void)arg;
    target_tid = (pid_t)syscall(SYS_gettid);
    target_ready = 1;
    while (!target_go) usleep(1000);
    // The pending SIGUSR1 is delivered here, as soon as it is unblocked.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    return NULL;
}

static pthread_mutex_t robust;
static void *die_holding(void *arg) {
    (void)arg;
    pthread_mutex_lock(&robust);
    return NULL; // exits holding it
}

static void *exit_all(void *arg) {
    (void)arg;
    usleep(50000);
    exit(7);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    pthread_t threads[THREADS];
    for (long i = 0; i < THREADS; i++) pthread_create(&threads[i], NULL, work, (void *)i);
    long sum = 0;
    for (int i = 0; i < THREADS; i++) {
        void *ret;
        pthread_join(threads[i], &ret);
        sum += (long)ret;
    }
    int distinct = 1;
    for (int i = 0; i < THREADS; i++)
        for (int j = 0; j < i; j++)
            if (tids[i] == tids[j] || tids[i] == getpid()) distinct = 0;
    printf("join: counter=%ld tls-sum=%ld distinct-tids=%d\n", counter, sum, distinct);

    // Many waiters on one condition variable, woken by a broadcast.
    pthread_t waiters[4];
    for (int i = 0; i < 4; i++) pthread_create(&waiters[i], NULL, waiter, NULL);
    usleep(20000);
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < 4; i++) pthread_join(waiters[i], NULL);
    puts("broadcast: all woke");

    // A timed wait that times out.
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 50 * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000;
    }
    pthread_mutex_lock(&lock);
    ready = 0;
    int r = pthread_cond_timedwait(&cond, &lock, &deadline);
    pthread_mutex_unlock(&lock);
    printf("timedwait: %s\n", r == ETIMEDOUT ? "timed out" : strerror(r));

    // A signal to one thread runs its handler there; the main thread
    // blocks it.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    pthread_t target;
    pthread_create(&target, NULL, signal_target, NULL); // inherits the mask
    while (!target_ready) usleep(1000);
    pthread_kill(target, SIGUSR1); // blocked there too: stays pending
    usleep(20000);
    int pending_while_blocked = handled_by == 0;
    target_go = 1;
    pthread_join(target, NULL);
    printf("pthread_kill: pending-while-blocked=%d handled-by-target=%d\n", pending_while_blocked,
           handled_by == target_tid);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    // A robust mutex whose owner died.
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&robust, &attr);
    pthread_t dier;
    pthread_create(&dier, NULL, die_holding, NULL);
    pthread_join(dier, NULL);
    r = pthread_mutex_lock(&robust);
    printf("robust: %s\n", r == EOWNERDEAD ? "owner died" : strerror(r));
    pthread_mutex_consistent(&robust);
    pthread_mutex_unlock(&robust);

    // fork from a threaded process: the child has only the forking thread.
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, waiter, NULL);
    pid_t child = fork();
    if (child == 0) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/status", getpid());
        FILE *f = fopen(path, "r");
        char line[128];
        int threads = -1;
        while (f && fgets(line, sizeof line, f))
            if (sscanf(line, "Threads: %d", &threads) == 1) break;
        _exit(threads);
    }
    int status;
    waitpid(child, &status, 0);
    printf("fork: child-threads=%d\n", WEXITSTATUS(status));
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    pthread_join(sleeper, NULL);

    // exit() from a thread ends the whole process, the main thread too.
    pthread_t ender;
    pthread_create(&ender, NULL, exit_all, NULL);
    for (;;) pause();
}
