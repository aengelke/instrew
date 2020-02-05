sources = files(
    'codegenerator.cc',
    'config.cc',
    'connection.cc',
    'optimizer.cc',
    'rewriteserver.cc',
)
executable('instrew-server', sources,
           include_directories: include_directories('../shared'),
           dependencies: [librellume, libllvm],
           install: true)
