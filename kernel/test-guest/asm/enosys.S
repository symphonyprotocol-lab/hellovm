// Calls getpid and exits with the negated result. The kernel emulates
// getpid (sandbox pid 1, exit status 255); a getpid forwarded to the host
// would return the app process's host pid instead.

#if defined(__x86_64__)

        .text
        .globl  _start
_start:
        mov     $39, %eax               // getpid()
        syscall
        neg     %rax
        mov     %eax, %edi
        mov     $231, %eax              // exit_group(-ret)
        syscall
        hlt

#elif defined(__aarch64__)

        .text
        .globl  _start
_start:
        mov     x8, #172                // getpid()
        svc     #0
        neg     x0, x0
        mov     x8, #94                 // exit_group(-ret)
        svc     #0
        udf     #0

#else
#error "unsupported architecture"
#endif

        .section .note.GNU-stack, "", %progbits
