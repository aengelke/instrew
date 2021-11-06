
#ifndef _INSTREW_SERVER_CONFIG_H
#define _INSTREW_SERVER_CONFIG_H

#include <cstdint>
#include <string>


class Conn;

struct ServerConfig {
#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
    int32_t tsc_ ## name;
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_INT32
} __attribute__((packed));

struct ClientConfig {
#define INSTREW_CLIENT_CONF
#define INSTREW_CLIENT_CONF_INT32(id, name) \
    int32_t tc_ ## name = 0;
#include "instrew-protocol.inc"
#undef INSTREW_CLIENT_CONF
#undef INSTREW_CLIENT_CONF_INT32
} __attribute__((packed));

struct InstrewConfig {
    InstrewConfig(int argc, const char* const* argv);

#define INSTREW_OPT(type, name, def) \
    type name = def;
#include "config.inc"
#undef INSTREW_OPT
};


#endif
