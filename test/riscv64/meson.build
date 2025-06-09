
triple = 'riscv64-linux-gnu'
cases = [
  {'name': 'exit', 'src': files('exit.S')},
  {'name': 'lrsc-loop', 'src': files('lrsc-loop.S')},
  
  {'name': 'fib_nolc', 'src': files('fib_nolc.c'), 'should_fail' : true},
  {'name': 'rec_nolibc', 'src': files('rec_nolibc.c'), 'should_fail' : true},
  {'name': 'fact_rv64', 'src': files('fact_rv64.S', 'rv64_runtime.S')},
]
