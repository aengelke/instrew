    .intel_syntax noprefix
    .text
    .global _start
_start:
    mov byte ptr [rip + data], 0
    // should not be reached
    xor edi, edi
    mov eax, 231
    syscall

    .rodata
data:
    .byte 0xff
