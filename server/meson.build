sources = files(
    'cache.cc',
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

python3 = find_program('python3')
pytobytes = 'import sys;print(repr(list(open(sys.argv[1],"rb").read()))[1:-1])'
client_bytes = custom_target('hex-client', output: 'client.inc', input: client,
                             capture: true,
                             command: [python3, '-c', pytobytes, '@INPUT@'])

instrew = executable('instrew', sources, client_bytes,
                     include_directories: include_directories('.', '../shared'),
                     dependencies: [librellume, libllvm, libcrypto, instrew_api],
                     link_args: ['-ldl'],
                     install: true)
