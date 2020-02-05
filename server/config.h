
#ifndef _INSTREW_SERVER_CONFIG_H
#define _INSTREW_SERVER_CONFIG_H

#include <cstdint>
#include <string>


class Conn;

struct ServerConfig {
#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
    bool name = default;
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
    int32_t name = default;
#define INSTREW_SERVER_CONF_STR(id, name, default) \
    std::string name = default;
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
#undef INSTREW_SERVER_CONF_STR

    void ReadFromConn(Conn& conn);
};

#endif
