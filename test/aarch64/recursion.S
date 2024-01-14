    .text
    .global _start
_start:
    mov x0, #38
    bl fib
    ldr x1, .Lexpected
    cmp x0, x1
    cset x0, ne
    mov x8, #94
    svc #0
    udf #0


fib:
    cmp x0, #1
    b.ls 1f
    stp x19, lr, [sp, #-16]!
    sub x19, x0, 2
    sub x0, x0, 1
    bl fib
    mov x1, x19
    mov x19, x0
    mov x0, x1
    bl fib
    add x0, x0, x19
    ldp x19, lr, [sp], #16
1:  ret

    .section .rodata
.Lexpected:
    .8byte 39088169
    .previous
