// A libc-free hello world: write(1), write(2), exit_group(42).
// Keep the strings in sync with HELLO_* in src/lib.rs.

#if defined(__x86_64__)

        .text
        .globl  _start
_start:
        mov     $1, %eax                // write(1, out, out_len)
        mov     $1, %edi
        lea     out(%rip), %rsi
        mov     $out_len, %edx
        syscall
        cmp     $out_len, %rax
        jne     fail

        mov     $1, %eax                // write(2, err, err_len)
        mov     $2, %edi
        lea     err(%rip), %rsi
        mov     $err_len, %edx
        syscall
        cmp     $err_len, %rax
        jne     fail

        mov     $231, %eax              // exit_group(42)
        mov     $42, %edi
        syscall
        hlt
fail:
        mov     $231, %eax              // exit_group(1)
        mov     $1, %edi
        syscall
        hlt

#elif defined(__aarch64__)

        .text
        .globl  _start
_start:
        mov     x0, #1                  // write(1, out, out_len)
        adrp    x1, out
        add     x1, x1, :lo12:out
        mov     x2, #out_len
        mov     x8, #64
        svc     #0
        cmp     x0, #out_len
        b.ne    fail

        mov     x0, #2                  // write(2, err, err_len)
        adrp    x1, err
        add     x1, x1, :lo12:err
        mov     x2, #err_len
        mov     x8, #64
        svc     #0
        cmp     x0, #err_len
        b.ne    fail

        mov     x0, #42                 // exit_group(42)
        mov     x8, #94
        svc     #0
        udf     #0
fail:
        mov     x0, #1                  // exit_group(1)
        mov     x8, #94
        svc     #0
        udf     #0

#else
#error "unsupported architecture"
#endif

        .section .rodata
out:    .ascii  "Hello from inside the hellovm sandbox!\n"
        .set    out_len, . - out
err:    .ascii  "This line went to stderr.\n"
        .set    err_len, . - err

        .section .note.GNU-stack, "", %progbits
