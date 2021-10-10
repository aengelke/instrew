
#ifndef _INSTREW_TRANSLATOR_H
#define _INSTREW_TRANSLATOR_H

struct TranslatorServerConfig {
    unsigned sz;
    const char* server;
    char buf[1024];
};

int translator_config_init(struct TranslatorServerConfig* tsc, const char* server);
#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
        int translator_config_ ## name(struct TranslatorServerConfig*, bool);
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
        int translator_config_ ## name(struct TranslatorServerConfig*, int32_t);
#define INSTREW_SERVER_CONF_STR(id, name, default) \
        int translator_config_ ## name(struct TranslatorServerConfig*, const char*);
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
#undef INSTREW_SERVER_CONF_STR

typedef struct TranslatorMsgHdr TranslatorMsgHdr;
struct TranslatorMsgHdr {
    uint32_t id;
    int32_t sz;
};

struct Translator {
    int rd_fd;
    int wr_fd;

    size_t written_bytes;
    TranslatorMsgHdr last_hdr;

    void* recvbuf;
    size_t recvbuf_sz;
};

typedef struct Translator Translator;

int translator_init(Translator* t, const struct TranslatorServerConfig* tsc);
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

#endif
