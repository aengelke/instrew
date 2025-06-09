
clang = find_program('clang', native: true, required: false, disabler: true)
if not clang.found()
  warning('unable to find clang; disabling tests')
endif

# TODO: remove this once non-native page sizes are supported
pagesize_cmd = run_command('getconf', 'PAGESIZE', check: true)
pagesize_flag = []
if pagesize_cmd.returncode() != 0
  warning('unable to get host page size for test binaries')
else
  pagesize = pagesize_cmd.stdout().strip().to_int()
  if pagesize > 4096
    message('compiling tests for host PAGESIZE=@0@'.format(pagesize))
    pagesize_flag = ['-Wl,-z,max-page-size=@0@'.format(pagesize)]
  endif
endif

foreach arch : ['aarch64', 'riscv64', 'x86_64']
  subdir(arch)

  testcc = [clang, '--target=@0@'.format(triple), '-nostdlib', '-static', '-fuse-ld=lld'] + pagesize_flag
  testrun = run_command(testcc + ['-o', '/dev/null', files('empty.s')], check: false)
  if testrun.returncode() != 0
    warning('defunctional @0@ Clang/LLD; disabling tests'.format(arch))
    continue
  endif

  foreach case : cases
    name = '@0@-@1@'.format(arch, case.get('name'))
    exec = custom_target(name,
                         input: case.get('src'),
                         output: name,
                         depfile: name + '.d',
                         command: testcc + ['-MD', '-MF', '@DEPFILE@', '-o', '@OUTPUT@', '@INPUT@'] + case.get('compile_args', []))
    test(name, instrew, suite: [arch],
         args: case.get('instrew_args', []) + ['--stub=' + client.path()] + [exec] + case.get('args', []),
         should_fail: case.get('should_fail', false))
  endforeach
endforeach
