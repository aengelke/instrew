
#ifndef _INSTREW_SERVER_CONFIG_H
#define _INSTREW_SERVER_CONFIG_H

#include <cstdint>
#include <string>


struct InstrewConfig {
    InstrewConfig() = default;
    InstrewConfig(int argc, const char* const* argv);

    size_t user_argc = 0;
    const char* const* user_args = nullptr;

#define INSTREW_OPT(type, name, def) \
    type name = def;
#include "config.inc"
#undef INSTREW_OPT
};

#endif
