// aarch64 only (HVF platform tests): what runtimes do with address space.
// Reserves 64 GiB with PROT_NONE, makes a few pages in the middle
// writable and uses one, unmaps it all; then maps, touches and unmaps one
// page at 2000 places a gigabyte apart. exit_group(0), or the number of
// the step that failed.

        .text
        .globl  _start
_start:
        mov     x0, #0                  // mmap(0, 64 GiB, PROT_NONE,
        mov     x1, #0x10               //      MAP_PRIVATE | MAP_ANONYMOUS |
        lsl     x1, x1, #32             //      MAP_NORESERVE, -1, 0)
        mov     x2, #0
        mov     x3, #0x4022
        mov     x4, #-1
        mov     x5, #0
        mov     x8, #222
        svc     #0
        mov     x20, #1
        cmn     x0, #4095
        b.hi    fail
        mov     x19, x0

        mov     x9, #1                  // mprotect(base + 1 GiB, 16 KiB,
        add     x0, x19, x9, lsl #30    //          PROT_READ | PROT_WRITE)
        mov     x21, x0
        mov     x1, #0x4000
        mov     x2, #3
        mov     x8, #226
        svc     #0
        mov     x20, #2
        cbnz    x0, fail

        mov     w9, #0x5a               // use a page of it
        add     x11, x21, #0x1000
        strb    w9, [x11]
        ldrb    w10, [x11]
        mov     x20, #3
        cmp     w10, #0x5a
        b.ne    fail

        mov     x0, x19                 // munmap(base, 64 GiB)
        mov     x1, #0x10
        lsl     x1, x1, #32
        mov     x8, #215
        svc     #0
        mov     x20, #4
        cbnz    x0, fail

        mov     x22, #2000              // one page at many places
        mov     x23, #0x20
        lsl     x23, x23, #32           // from 128 GiB up
churn:
        mov     x0, x23                 // mmap(at, 4096, PROT_READ | PROT_WRITE,
        mov     x1, #0x1000             //      MAP_PRIVATE | MAP_ANONYMOUS |
        mov     x2, #3                  //      MAP_FIXED, -1, 0)
        mov     x3, #0x32
        mov     x4, #-1
        mov     x5, #0
        mov     x8, #222
        svc     #0
        mov     x20, #5
        cmp     x0, x23
        b.ne    fail
        strb    w9, [x23]
        mov     x0, x23                 // munmap(at, 4096)
        mov     x1, #0x1000
        mov     x8, #215
        svc     #0
        mov     x20, #6
        cbnz    x0, fail
        mov     x10, #1
        add     x23, x23, x10, lsl #30
        subs    x22, x22, #1
        b.ne    churn

        mov     x0, #0                  // exit_group(0)
        mov     x8, #94
        svc     #0
        udf     #0
fail:
        mov     x0, x20                 // exit_group(step)
        mov     x8, #94
        svc     #0
        udf     #0

        .section .note.GNU-stack, "", %progbits
