    .text
    .global _start
_start:
    mov x0, #0
    mov x8, #94
    svc #0
    udf #0
