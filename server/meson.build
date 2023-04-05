sources = files(
    'cache.cc',
    'callconv.cc',
    'codegenerator.cc',
    'config.cc',
    'connection.cc',
    'decode.cc',
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

client_cp = custom_target('cp-client', output: 'instrew-client', input: client,
                             command: ['cp', '@INPUT@', '@OUTPUT@'])

executable('instrew', sources, client_bytes, client_cp,
           include_directories: include_directories('.', '../shared'),
           dependencies: [librellume, fadec, frvdec, farmdec, libllvm, libcrypto, instrew_api],
           link_args: ['-ldl'],
           install: true)