sources = files(
    'elf-loader.c',
    'emulate.c',
    'main.c',
    'memory.c',
    'minilibc.c',
    'rtld.c',
    'translator.c',
)

executable('instrew', sources,
           #pie: true,
           include_directories: include_directories('../shared'),
           c_args: ['-D_GNU_SOURCE', '-nostdlib', '-nostartfiles', '-fno-builtin', '-fno-stack-protector', '-fomit-frame-pointer', '-fPIC'],
           link_args: ['-static-pie', '-nostdlib', '-nostartfiles', '-lgcc'],
           install: true)
