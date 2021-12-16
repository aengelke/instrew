
#ifndef _INSTREW_SERVER_CONFIG_H
#define _INSTREW_SERVER_CONFIG_H

#include <cstdint>
#include <string>


struct InstrewConfig {
    InstrewConfig(int argc, const char* const* argv);

#define INSTREW_OPT(type, name, def) \
    type name = def;
#include "config.inc"
#undef INSTREW_OPT
};

#endif
