    .intel_syntax noprefix
    .text
    .global _start
_start:
    call foo

    xor edi, edi
    mov eax, 231
    syscall
    ud2

foo:
    push rax
    call bar
    pop rcx
    ret
bar:
    add rsp, 0x10
    ret
