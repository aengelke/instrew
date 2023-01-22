    .intel_syntax noprefix
    .text
    .global _start
_start:
    mov eax, 0x1000000
1:  call 2f
2:  pop rcx
    sub eax, 1
    jnz 1b

    xor edi, edi
    mov eax, 231
    syscall
    ud2
