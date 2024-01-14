
#include "config.h"

#include <llvm/Support/CommandLine.h>


llvm::cl::OptionCategory InstrewCategory("Instrew Options");
llvm::cl::OptionCategory CodeGenCategory("Instrew Code Generation Options", "Options affecting the translated code.");
