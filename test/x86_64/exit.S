    .intel_syntax noprefix
    .text
    .global _start
_start:
    xor edi, edi
    mov eax, 231
    syscall
    ud2
