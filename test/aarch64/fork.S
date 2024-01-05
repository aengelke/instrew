    .text
    .global _start
_start:
    mov x0, #17 // flags = SIGCHLD
    mov x1, xzr // stack
    mov x2, xzr // parent_tid
    mov x3, xzr // tls
    mov x4, xzr // child_tid
    mov x8, #220 // __NR_clone
    svc #0
    tst x0, x0
    b.mi .Lexit
    b.eq .Lchild

    mov x9, x0 // save pid to x9
    // x0 is pid
    sub x1, sp, #8 // wstatus
    mov x2, xzr // options
    mov x3, xzr // rusage
    mov x8, #260 // __NR_wait4
    svc #0
    tst x0, x0
    b.mi .Lexit
    cmp x0, x9
    mov x0, #1
    b.ne .Lexit

    ldr w1, [x1]
    mov w2, #0x4200 // W_EXITCODE(0x42, 0)
    cmp w1, w2
    b.ne .Lexit
    mov x0, #0

.Lexit:
    mov x8, #94 // __NR_exit_group
    svc #0
    udf #0

.Lchild:
    mov x0, #0x42
    mov x8, #94 // __NR_exit_group
    svc #0
    udf #0
