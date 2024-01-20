triple = 'x86_64-linux-gnu'
cases = [
  {'name': 'exit', 'src': files('exit.S')},
  {'name': 'call-pop', 'src': files('call-pop.S')},
  {'name': 'call-ret-mismatch', 'src': files('call-ret-mismatch.S')},
  {'name': 'call-ret-mismatch-callret', 'src': files('call-ret-mismatch.S'), 'instrew_args': ['-callret']},
  {'name': 'nowrite', 'src': files('nowrite.S'), 'should_fail': true},
  {'name': 'fork', 'src': files('fork.S')},
  {'name': 'recursion', 'src': files('recursion.S')},
  {'name': 'recursion-callret', 'src': files('recursion.S'), 'instrew_args': ['-callret']},
]
