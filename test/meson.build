
clang = find_program('clang', native: true, required: false, disabler: true)
if not clang.found()
  warning('unable to find clang; disabling tests')
endif

foreach arch : ['aarch64', 'x86_64']
  subdir(arch)

  testcc = [clang, '--target=@0@'.format(triple), '-nostdlib', '-static', '-fuse-ld=lld']
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
         args: case.get('instrew_args', []) + [exec] + case.get('args', []),
         should_fail: case.get('should_fail', false))
  endforeach
endforeach
