
#ifndef _INSTREW_SERVER_CONNECTION_H
#define _INSTREW_SERVER_CONNECTION_H

#include <cstddef>
#include <cstdio>
#include <cstdint>


struct IWServerConfig {
#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
    int32_t tsc_ ## name;
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_INT32
} __attribute__((packed));

struct IWClientConfig {
#define INSTREW_CLIENT_CONF
#define INSTREW_CLIENT_CONF_INT32(id, name) \
    int32_t tc_ ## name = 0;
#include "instrew-protocol.inc"
#undef INSTREW_CLIENT_CONF
#undef INSTREW_CLIENT_CONF_INT32
} __attribute__((packed));

typedef struct IWConnection IWConnection;

struct IWObject {
    const void* data;
    size_t size;
};

const struct IWServerConfig* iw_get_sc(IWConnection* iwc);
struct IWClientConfig* iw_get_cc(IWConnection* iwc);
void iw_set_dumpobj(IWConnection* iwc, bool dumpobj);
size_t iw_readmem(IWConnection* iwc, uintptr_t addr, size_t len, uint8_t* buf);

typedef struct IWState IWState;

struct IWFunctions {
    struct IWState* (* init)(IWConnection* iwc, unsigned argc,
                             const char* const* argv);
    struct IWObject (* translate)(IWState* state, uintptr_t addr);
    void (* finalize)(IWState* state);
};

int iw_run_server(const struct IWFunctions* fns, int argc, char** argv);

#endif
