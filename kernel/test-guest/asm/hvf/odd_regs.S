// aarch64 only (HVF platform tests): makes system calls with odd register
// values, which the kernel must answer with errors, prints "survived\n",
// then calls rt_sigreturn with the stack pointer at an unmapped address,
// which the kernel answers with SIGSEGV.

        .text
        .globl  _start
_start:
        mov     x0, #-1                 // every argument and the number all ones
        mov     x1, x0
        mov     x2, x0
        mov     x3, x0
        mov     x4, x0
        mov     x5, x0
        mov     x8, x0
        svc     #0                      // syscall -1: ENOSYS
        mov     x8, #0x7fffffff
        svc     #0                      // a huge number: ENOSYS
        mov     x0, #1                  // write(1, top of the address space, ~0)
        movz    x1, #0xffff, lsl #48
        mov     x2, #-1
        mov     x8, #64
        svc     #0
        mov     x0, #1                  // write(1, 0x10, 1 << 40)
        mov     x1, #0x10
        mov     x2, #1
        lsl     x2, x2, #40
        mov     x8, #64
        svc     #0
        mov     x0, #0                  // mmap(0, ~0, RW, private|anon, -1, 0)
        mov     x1, #-1
        mov     x2, #3
        mov     x3, #0x22
        mov     x4, #-1
        mov     x5, #0
        mov     x8, #222
        svc     #0
        movz    x0, #0xffff, lsl #48    // munmap(top, 1 << 47)
        mov     x1, #1
        lsl     x1, x1, #47
        mov     x8, #215
        svc     #0

        mov     x0, #1                  // write(1, "survived\n", 9)
        adrp    x1, msg
        add     x1, x1, :lo12:msg
        mov     x2, #9
        mov     x8, #64
        svc     #0

        movz    x9, #0xdead, lsl #16    // rt_sigreturn with sp unmapped
        mov     sp, x9
        mov     x8, #139
        svc     #0
        mov     x0, #3                  // not reached: exit_group(3)
        mov     x8, #94
        svc     #0
        udf     #0

        .section .rodata
msg:    .ascii  "survived\n"

        .section .note.GNU-stack, "", %progbits
