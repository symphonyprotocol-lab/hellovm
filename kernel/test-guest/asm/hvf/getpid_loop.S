// aarch64 only (HVF platform tests): calls getpid N times, N the decimal
// argv[1] (default 1), checking every result is 1 (the sandbox's pid),
// then exit_group(0); exit_group(1) on a wrong result.

        .text
        .globl  _start
_start:
        ldr     x1, [sp]                // argc
        mov     x19, #1                 // N
        cmp     x1, #2
        b.lt    loop_start
        ldr     x2, [sp, #16]           // argv[1]
        mov     x19, #0
parse:
        ldrb    w3, [x2], #1
        sub     w3, w3, #'0'
        cmp     w3, #9
        b.hi    loop_start              // not a digit (or the NUL): done
        mov     x4, #10
        madd    x19, x19, x4, x3
        b       parse
loop_start:
        cbz     x19, done
loop:
        mov     x8, #172                // getpid()
        svc     #0
        cmp     x0, #1
        b.ne    fail
        subs    x19, x19, #1
        b.ne    loop
done:
        mov     x0, #0                  // exit_group(0)
        mov     x8, #94
        svc     #0
        udf     #0
fail:
        mov     x0, #1                  // exit_group(1)
        mov     x8, #94
        svc     #0
        udf     #0

        .section .note.GNU-stack, "", %progbits
