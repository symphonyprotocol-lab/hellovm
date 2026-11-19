// aarch64 only (HVF platform tests): sets PSTATE.DIT (data-independent
// timing), makes a system call, and exits with 0 if DIT is still set, 1 if
// the round trip through the kernel lost it.

        .arch   armv8.4-a
        .text
        .globl  _start
_start:
        msr     dit, #1
        mov     x8, #172                // getpid()
        svc     #0
        mrs     x1, dit
        lsr     x1, x1, #24
        and     x1, x1, #1
        eor     x0, x1, #1
        mov     x8, #94                 // exit_group
        svc     #0
        udf     #0

        .section .note.GNU-stack, "", %progbits
