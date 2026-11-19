// aarch64 only (HVF platform tests): cache maintenance over read-only,
// executable memory that was never touched, as `__clear_cache` does after
// a loader or JIT made code executable. On Linux that is no fault.
// exit_group(0), or 1 if the mapping failed.

        .text
        .globl  _start
_start:
        mov     x0, #0                  // mmap(0, 12 KiB, PROT_READ | PROT_EXEC,
        mov     x1, #0x3000             //      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        mov     x2, #5
        mov     x3, #0x22
        mov     x4, #-1
        mov     x5, #0
        mov     x8, #222
        svc     #0
        cmn     x0, #4095
        b.hi    fail
        mov     x19, x0
        add     x1, x19, #0x1000
        dc      cvau, x1                // clean the data cache line,
        ic      ivau, x1                // invalidate the instruction's
        add     x1, x19, #0x2000
        ic      ivau, x1
        dc      cvau, x1
        dsb     ish
        isb
        ldr     x2, [x19]               // and a plain read of the first page
        mov     x0, #0                  // exit_group(0)
        mov     x8, #94
        svc     #0
        udf     #0
fail:
        mov     x0, #1
        mov     x8, #94
        svc     #0
        udf     #0

        .section .note.GNU-stack, "", %progbits
