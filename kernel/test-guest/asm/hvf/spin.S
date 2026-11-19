// aarch64 only (HVF platform tests): spins forever without a system call.

        .text
        .globl  _start
_start:
        b       _start

        .section .note.GNU-stack, "", %progbits
