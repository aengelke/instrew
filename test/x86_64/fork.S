    .intel_syntax noprefix
    .text
    .global _start
_start:
    mov edi, 17 // flags = SIGCHLD
    xor esi, esi // stack
    xor edx, edx // parent_tid
    xor r10, r10 // child_tid
    xor r8, r8 // tls
    mov eax, 56 // __NR_clone
    syscall
    test rax, rax
    js .Lexit
    jz .Lchild

    mov rdi, rax // pid
    lea rsi, [rsp - 0x8] // wstatus
    xor edx, edx // options
    xor r10, r10 // rusage
    mov eax, 61 // __NR_wait4
    syscall
    test rax, rax
    js .Lexit // wait4 failed?
    cmp rax, rdi
    mov rax, 1
    jne .Lexit // wait4 should have returned pid

    mov esi, [rsi]
    cmp esi, 0x4200 // W_EXITCODE(0x42, 0)
    jne .Lexit
    xor eax, eax

.Lexit:
    mov rdi, rax
    mov eax, 231 // __NR_exit_group
    syscall
    ud2

.Lchild:
    mov edi, 0x42
    mov eax, 231 // __NR_exit_group
    syscall
    ud2
