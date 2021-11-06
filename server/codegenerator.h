
#ifndef _INSTREW_SERVER_CODE_GENERATOR_H
#define _INSTREW_SERVER_CODE_GENERATOR_H

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Module.h>


struct ServerConfig;
struct InstrewConfig;

class CodeGenerator {
public:
    CodeGenerator(const ServerConfig& server_config, const InstrewConfig&,
                  llvm::SmallVectorImpl<char> &o);
    ~CodeGenerator();
    void GenerateCode(llvm::Module* mod);

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

#endif
