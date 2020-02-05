
#ifndef _INSTREW_TRANSLATOR_H
#define _INSTREW_TRANSLATOR_H

struct Translator {
    int rd_fd;
    int wr_fd;

    size_t written_bytes;
};

typedef struct Translator Translator;

int translator_init(Translator* t, const char* tool);
int translator_get(Translator* t, uintptr_t addr, void** out_obj,
                   size_t* out_obj_size);


int translator_config_begin(Translator* t);
int translator_config_end(Translator* t);

#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
        int translator_config_ ## name(Translator*, bool);
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
        int translator_config_ ## name(Translator*, int32_t);
#define INSTREW_SERVER_CONF_STR(id, name, default) \
        int translator_config_ ## name(Translator*, const char*);
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
#undef INSTREW_SERVER_CONF_STR

#endif
