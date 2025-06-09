#
# a0-a2 - parameters to linux function services
# a7 - linux function number
#

# Provide program starting address to linker
.global _start
_start: li a0, 5
  call fac
  call print_int
  addi a0, x0, 0 # return 0
  #addi    a7, x0, 93  # Service command code 93 terminates
  li  a7, 93 # Service command code 93 terminates
  ecall      # Call linux to terminate the program

fac: # a0 is argument and return value
  li   a1, 1  # 1
  ble  a0, a1, .fac_exit
  mv   a5, a0
  li   a0, 1
.fac_loop:
  mv   a4, a5
  addi a5, a5, -1
  mul  a0, a4, a0
  bne  a5, a1, .fac_loop
.fac_exit:
  ret
