project('instrew', ['c', 'cpp'],
        default_options: [
            'buildtype=debugoptimized',
            'default_library=static',
            'warning_level=3',
            'c_std=c11',
            'cpp_std=c++17',
        ],
        meson_version: '>=0.49')

if host_machine.endian() != 'little'
  error('cannot compile for non-little-endian machine')
endif

add_project_arguments(['-Wmissing-field-initializers',
                       '-Wunused-parameter',
                       '-Wshadow',
                       '-Wpointer-arith',
                       '-Wcast-align',
                       '-Wwrite-strings',
                       '-Winline',
                       '-Wformat-nonliteral',
                       '-Wformat-security',
                       '-Wswitch-default',
                       '-Wundef',
                       '-Werror=incompatible-pointer-types',
                       '-Werror=implicit-function-declaration'],
                      language: 'c')

add_global_arguments(['-fno-rtti'], language: 'cpp')

llvm_version = ['>=8', '<12']
# First, attempt to use the shared library.
libllvm = dependency('llvm', version: llvm_version, static: false,
                     method: 'config-tool', required: false)
if not libllvm.found()
  # Try static libraries.
  libllvm = dependency('llvm', version: llvm_version, static: true,
                       method: 'config-tool',
                       modules: ['x86', 'aarch64', 'riscv', 'analysis', 'passes'])
endif

rellume = subproject('rellume')
librellume = rellume.get_variable('librellume')

subdir('client')

subdir('tool-api')
subdir('server')

subdir('tools-simple')
