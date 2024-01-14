    .intel_syntax noprefix
    .text
    .global _start
_start:
    mov edi, 38
    call fib
    xor edi, edi
    cmp rax, 39088169
    setne dil
    mov eax, 231
    syscall
    ud2

fib:
    mov rax, rdi
    cmp rax, 1
    jbe 1f
    push rbx
    mov rbx, rax
    sub rdi, 1
    call fib
    mov rdi, rbx
    sub rdi, 2
    mov rbx, rax
    call fib
    add rax, rbx
    pop rbx
1:  ret
