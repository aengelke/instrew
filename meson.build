project('instrew', ['c', 'cpp'],
        default_options: [
            'buildtype=debugoptimized',
            'warning_level=3',
            'c_std=c11',
            'cpp_std=c++17',
        ])


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

libllvm = dependency('llvm', version: ['>=8', '<12'])

rellume = subproject('rellume')
librellume = rellume.get_variable('librellume')

subdir('client')

subdir('tool-api')
subdir('server')

subdir('tools-simple')
