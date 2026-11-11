// Calls getpid and exits with the negated result: 38 (ENOSYS) when the
// kernel refuses it; a forwarded getpid would return a positive pid.

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
