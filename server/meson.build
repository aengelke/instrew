sources = files(
    'callconv.cc',
    'codegenerator.cc',
    'config.cc',
    'connection.cc',
    'optimizer.cc',
    'rewriteserver.cc',
)

config_data = configuration_data()
config_data.set_quoted('INSTREW_TOOL_PATH', get_option('prefix')/get_option('libdir')/'instrew')
configure_file(configuration: config_data, output: 'instrew-server-config.h')

executable('instrew-server', sources,
           include_directories: include_directories('.', '../shared'),
           dependencies: [librellume, libllvm, instrew_api],
           link_args: ['-ldl'],
           install: true)
