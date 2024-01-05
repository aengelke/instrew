
#ifndef _INSTREW_TRANSLATOR_H
#define _INSTREW_TRANSLATOR_H

struct TranslatorServerConfig {
#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
        bool tsc_ ## name;
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
        int32_t tsc_ ## name;
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
};

typedef struct TranslatorMsgHdr TranslatorMsgHdr;
struct TranslatorMsgHdr {
    uint32_t id;
    int32_t sz;
};

struct Translator {
    int socket;

    size_t written_bytes;
    TranslatorMsgHdr last_hdr;

    void* recvbuf;
    size_t recvbuf_sz;
};

typedef struct Translator Translator;

int translator_init(Translator* t, const char* server_config,
                    const struct TranslatorServerConfig* tsc);
int translator_fini(Translator* t);
int translator_get_object(Translator* t, void** out_obj, size_t* out_obj_size);
int translator_get(Translator* t, uintptr_t addr, void** out_obj,
                   size_t* out_obj_size);

struct TranslatorConfig {
#define INSTREW_CLIENT_CONF
#define INSTREW_CLIENT_CONF_INT32(id, name) \
        int32_t tc_ ## name;
#include "instrew-protocol.inc"
#undef INSTREW_CLIENT_CONF
#undef INSTREW_CLIENT_CONF_INT32
} __attribute__((packed));

int translator_config_fetch(Translator* t, struct TranslatorConfig* cfg);

// Fork server process and return new socket fd.
int translator_fork_prepare(Translator* t);
// Client fork succeeded, use forked translator from now on.
int translator_fork_finalize(Translator* t, int fork_fd);

#endif
