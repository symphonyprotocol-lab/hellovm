// aarch64 only (HVF platform tests): loads from address 0x10, where
// nothing is mapped. The kernel kills it with SIGSEGV.

        .text
        .globl  _start
_start:
        mov     x1, #0x10
        ldr     x0, [x1]
        mov     x0, #0                  // not reached: exit_group(0)
        mov     x8, #94
        svc     #0
        udf     #0

        .section .note.GNU-stack, "", %progbits
