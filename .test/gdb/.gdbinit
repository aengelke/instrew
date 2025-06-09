set history save
set breakpoint pending on
b connection.cc:197
run
del
n
set follow-exec-mode new
# b dispatch.c:55
# # b dispatch.c:77
# c
# # s
# # finish
# # b rtld.c:296
# # del 2
b dispatch.c:128
c
c
c

