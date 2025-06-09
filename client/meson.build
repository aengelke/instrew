sources = [
    'dispatch.c',
    'elf-loader.c',
    'emulate.c',
    'main.c',
    'math.c',
    'memory.c',
    'minilibc.c',
    'rtld.c',
    'translator.c',
]

if host_machine.cpu_family() == 'aarch64'
  sources += [
    'memset-aarch64.S'
  ]
endif

client_c_args = ['-D_GNU_SOURCE', '-nostdlib', '-fno-builtin',
                 '-fno-stack-protector', '-fomit-frame-pointer', '-fPIC']
client_link_args = ['-nostdlib', '-nostartfiles', '-lgcc', '-latomic']

cc = meson.get_compiler('c')
if host_machine.cpu_family() == 'riscv64' and cc.get_id() == 'gcc' and cc.version() == '12'
   client_link_args += ['-static-pie', '-Wl,-static', '-Wl,-pie', '-Wl,--no-dynamic-linker', '-Wl,-z,text']
else
   if cc.has_argument('-static-pie')
      client_link_args += ['-static-pie']
   else
      client_link_args += ['-Wl,-static', '-Wl,-pie', '-Wl,--no-dynamic-linker', '-Wl,-z,text']
   endif
endif

if host_machine.cpu_family() == 'x86_64'
  if cc.has_argument('-mpreferred-stack-boundary=3') # GCC
    client_c_args += ['-mpreferred-stack-boundary=3']
  elif cc.has_argument('-mstack-alignment=3') # Clang
    client_c_args += ['-mstack-alignment=3']
  else
    error('could not lower stack aligment')
  endif
endif

client = executable('instrew-client', sources,
                    include_directories: include_directories('.', '../shared'),
                    c_args: client_c_args,
                    link_args: client_link_args,
                    install: true,
                    override_options: ['b_sanitize=none'])

test('mathlib', executable('test_mathlib', 'math.c', c_args: ['-DTEST', '-fno-builtin']), protocol: 'tap')
# test('rtldlib', executable('test_rtldlib', 
# 	'rtld.c', include_directories: include_directories('.'), 
# 	c_args: client_c_args + '-DTEST', link_args: client_link_args), protocol: 'tap')
