project('instrew', ['c', 'cpp'],
        default_options: [
            'buildtype=debugoptimized',
            'warning_level=3',
            'c_std=c11',
            'cpp_std=c++17',
        ])


add_project_arguments(['-Wmissing-field-initializers',
                       '-Wunused-parameter',
                       '-Wold-style-definition',
                       '-Wmissing-declarations',
                       '-Wmissing-prototypes',
                       '-Wmissing-noreturn',
                       '-Wshadow',
                       '-Wpointer-arith',
                       '-Wcast-align',
                       '-Wwrite-strings',
                       '-Winline',
                       '-Wformat-nonliteral',
                       '-Wformat-security',
                       '-Wswitch-default',
                       '-Winit-self',
                       '-Wnested-externs',
                       '-Wstrict-prototypes',
                       '-Wmissing-include-dirs',
                       '-Wundef',
                       # '-Wconversion',
                       '-Werror=incompatible-pointer-types',
                       '-Werror=implicit-function-declaration',
                       '-Wno-sign-conversion',
                       '-Wno-overlength-strings',
                       '-Wmissing-format-attribute'],
                      language: 'c')

add_global_arguments(['-fno-rtti'], language: 'cpp')
add_project_arguments(['-Wno-unused-parameter'], language: 'cpp')

libllvm = dependency('llvm', version: ['>=8', '<10'])

rellume = subproject('rellume')
librellume = rellume.get_variable('librellume')

subdir('client')
subdir('server')
