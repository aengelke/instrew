sources = files(
    'dispatch.c',
    'elf-loader.c',
    'emulate.c',
    'main.c',
    'math.c',
    'memory.c',
    'minilibc.c',
    'rtld.c',
    'translator.c',
)

client_c_args = ['-D_GNU_SOURCE', '-nostdlib', '-fno-builtin',
                 '-fno-stack-protector', '-fomit-frame-pointer', '-fPIC']
client_link_args = ['-nostdlib', '-nostartfiles', '-lgcc']

cc = meson.get_compiler('c')
if cc.has_argument('-static-pie')
  client_link_args += ['-static-pie']
else
  client_link_args += ['-Wl,-static', '-Wl,-pie', '-Wl,--no-dynamic-linker', '-Wl,-z,text']
endif

config_data = configuration_data()
config_data.set_quoted('INSTREW_DEFAULT_SERVER', get_option('prefix')/get_option('bindir')/'instrew-server')
configure_file(configuration: config_data, output: 'instrew-client-config.h')

executable('instrew', sources,
           include_directories: include_directories('.', '../shared'),
           c_args: client_c_args,
           link_args: client_link_args,
           install: true)

test('mathlib', executable('test_mathlib', 'math.c', c_args: ['-DTEST']), protocol: 'tap')
