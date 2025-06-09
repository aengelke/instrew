.section .data
str2:    .string "01234567012345670123456701234567\n" # 32+1 bytes
#str2:    .string "01234567\n" # 32+1 bytes
NOT_IMPLEMENTED_STR: .string "Not implemented\n\0"
.equ BUFSIZE,32
.globl str2
.text

.global not_implemented
not_implemented:
  li      a7, 64 # write on RISCV linux
  li      a0, 1 # stdout
  la      a1, NOT_IMPLEMENTED_STR
  li      a2, 16
  ecall
  li a0, 1
  li a7, 93
  ecall
  ret

.global memset
memset: # a0 is addr, a1 is byte, a2 is length
memset_loop:
  beq a2, zero, memset_fin
  sb a1, (a0)
  addi a0, a0, 1
  addi a2, a2, -1
  j memset_loop
memset_fin:
  ret

.global strlen
strlen: # a0 is a string, a0 is a result
  li t0, 0
strlen_loop:
  ld t1, (a0)
  bne zero, t1, strlen_fin
  addi a0, a0, 1
  addi t0, t0, 1
  j strlen_loop
strlen_fin:
  mv a0, t0
  ret

.global memcpy
memcpy: # a0 dest, a1 src, a2 size. No intersection
memcpy_loop:
  beq a2, zero, memcpy_fin
  lb t0, (a1)
  sb t0, (a0)
  addi a0, a0, 1
  addi a1, a1, 1
  addi a2, a2, -1
  j memcpy_loop
memcpy_fin:
  ret

.global myitoa
myitoa:
  # t2 is an arg, a0 is current pos, a1 is output len
  li t1, 10     # t1 is basis
  mv t2, a0     # argument
  mv a1, zero   # output length
  la a0, str2
  addi a0, a0, BUFSIZE  # 32 is preallocated space
myitoa_loop:
  #
  remu t4, t2, t1
  addi t4, t4, 0x30   # t4 stores one more char
  addi a1, a1, 1
  addi a0, a0, -1
  sb t4, (a0)
  divu t2, t2, t1
  bne t2, zero, myitoa_loop
  ret

.global trace_variable
trace_variable:
  addi sp, sp, -8*4
  sd ra, 24(sp) # save ra beacuse we do calls IMPORTANT
  sd a0, 16(sp) # a0 is varname
  sd a1, 8(sp)  # a1 is varname length
  sd a2, (sp)  # a2 is a value
  # TODO: varname length

  la a0, str2
  li a1, 0x20 # space
  li a2, BUFSIZE
  call memset

  ld a0, (sp)
  call myitoa

  la a0, str2
  ld a1, 16(sp)
  ld a2, 8(sp)
  call memcpy

  li      a7, 64  # write on RISCV linux
  li      a0, 1
  la      a1, str2
  li      a2, BUFSIZE+1
  ecall
  ld ra, 24(sp)
  addi sp, sp, 8*4
  ret

.global print_int
print_int:
  addi sp, sp, -16
  sd a0, 8(sp)
  sd ra, (sp)
  la a0, str2
  li a1, 0x20 # space
  li a2, BUFSIZE
  call memset

  ld a0, 8(sp)
  call myitoa

  li      a7, 64  # write on RISCV linux
  li      a0, 1
  la      a1, str2
  li      a2, BUFSIZE+1
  ecall

  ld ra, (sp)
  addi sp, sp, 16
  ret
