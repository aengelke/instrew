
#include "config.h"

#include "connection.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>


static void ReadBool(bool& tgt, Conn& conn) {
    tgt = conn.Read<uint8_t>();
}
static void ReadInt32(int32_t& tgt, Conn& conn) {
    tgt = conn.Read<int32_t>();
}
static void ReadStr(std::string& tgt, Conn& conn) {
    size_t len = conn.Read<uint32_t>();
    tgt.resize(len, '\x7f');
    conn.Read(&tgt[0], len);
}

void ServerConfig::ReadFromConn(Conn& conn) {
    while (conn.Remaining()) {
        uint8_t conf_id = conn.Read<uint8_t>();
        switch (conf_id) {
        case 0: // end-of-config indicator
            return;
        default:
            std::cerr << "unknown configuration " << conf_id << std::endl;
            // TODO: simply discard remaining options?
            abort();

#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
        case id: ReadBool(this->name, conn); break;
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
        case id: ReadInt32(this->name, conn); break;
#define INSTREW_SERVER_CONF_STR(id, name, default) \
        case id: ReadStr(this->name, conn); break;
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
#undef INSTREW_SERVER_CONF_STR
        }
    }
}
