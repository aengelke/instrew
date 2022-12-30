
#include <common.h>
#include <asm/signal.h>
#include <linux/fcntl.h>
#include <linux/mman.h>
#include <linux/sched.h>

#include <translator.h>

#include <memory.h>


enum MsgId {
#define INSTREW_MESSAGE_ID(id, name) MSGID_ ## name = id,
#include "instrew-protocol.inc"
#undef INSTREW_MESSAGE_ID
};

static int translator_hdr_send(Translator* t, uint32_t id, int32_t sz) {
    if (t->last_hdr.id != MSGID_UNKNOWN)
        return -EPROTO;
    int ret;
    TranslatorMsgHdr hdr = {id, sz};
    if ((ret = write_full(t->wr_fd, &hdr, sizeof(hdr))) != sizeof(hdr))
        return ret;
    return 0;
}

static int32_t translator_hdr_recv(Translator* t, uint32_t id) {
    if (t->last_hdr.id == MSGID_UNKNOWN) {
        int ret = read_full(t->rd_fd, &t->last_hdr, sizeof(t->last_hdr));
        if (ret != sizeof(t->last_hdr))
            return ret;
    }
    if (t->last_hdr.id != id)
        return -EPROTO;
    int32_t sz = t->last_hdr.sz;
    t->last_hdr = (TranslatorMsgHdr) {MSGID_UNKNOWN, 0};
    return sz;
}

int translator_init(Translator* t, const char* server_config,
                    const struct TranslatorServerConfig* tsc) {
    uint64_t fds_raw = 0;
    for (size_t i = 0; server_config[i]; i++)
        fds_raw |= (uint64_t) ((server_config[i] - '0') & 7) << ((3 * i) & 63);
    t->rd_fd = fds_raw & 0xffffffff;
    t->wr_fd = fds_raw >> 32;

    t->written_bytes = 0;
    t->last_hdr = (TranslatorMsgHdr) {MSGID_UNKNOWN, 0};
    t->recvbuf = NULL;
    t->recvbuf_sz = 0;

    int ret;
    if ((ret = translator_hdr_send(t, MSGID_C_INIT, sizeof *tsc)))
        return ret;
    if ((ret = write_full(t->wr_fd, tsc, sizeof *tsc)) != sizeof *tsc)
        return ret;

    return 0;
}

int translator_fini(Translator* t) {
    close(t->rd_fd);
    close(t->wr_fd);
    return 0;
}

int translator_config_fetch(Translator* t, struct TranslatorConfig* cfg) {
    int32_t sz = translator_hdr_recv(t, MSGID_S_INIT);
    if (sz < 0)
        return sz;
    if (sz != sizeof *cfg)
        return -EPROTO;
    ssize_t ret = read_full(t->rd_fd, cfg, sz);
    if (ret != (ssize_t) sz)
        return ret;
    return 0;
}

int translator_get_object(Translator* t, void** out_obj, size_t* out_obj_size) {
    int32_t sz = translator_hdr_recv(t, MSGID_S_OBJECT);
    if (sz < 0)
        return sz;

    if ((uint32_t) sz >= t->recvbuf_sz) {
        // TODO: free old buffer
        // int ret = mem_free(t->recvbuf);
        // if (ret)
        //     return ret;
        size_t newsz = ALIGN_UP(sz, getpagesize());
        t->recvbuf = mem_alloc_data(newsz, getpagesize());
        if (BAD_ADDR(t->recvbuf))
            return (int) (uintptr_t) t->recvbuf;
        t->recvbuf_sz = newsz;
    }
    int ret = read_full(t->rd_fd, t->recvbuf, sz);
    if (ret != (ssize_t) sz)
        return ret;

    *out_obj = t->recvbuf;
    *out_obj_size = sz;

    return 0;
}

int translator_get(Translator* t, uintptr_t addr, void** out_obj,
                   size_t* out_obj_size) {
    int ret;
    if ((ret = translator_hdr_send(t, MSGID_C_TRANSLATE, 8)) != 0)
        return ret;
    if ((ret = write_full(t->wr_fd, &addr, sizeof(addr))) != sizeof(addr))
        return ret;

    while (true) {
        int32_t sz = translator_hdr_recv(t, MSGID_S_MEMREQ);
        if (sz == -EPROTO) {
            return translator_get_object(t, out_obj, out_obj_size);
        } else if (sz < 0) {
            return sz;
        }

        // handle memory request
        struct { uint64_t addr; size_t buf_sz; } memrq;
        if (sz != sizeof(memrq))
            return -1;
        if ((ret = read_full(t->rd_fd, &memrq, sizeof(memrq))) != sizeof(memrq))
            return ret;
        if (memrq.buf_sz > 0x1000)
            memrq.buf_sz = 0x1000;

        if ((ret = translator_hdr_send(t, MSGID_C_MEMBUF, memrq.buf_sz+1)) < 0)
            return ret;

        uint8_t failed = 0;
        if ((ret = write_full(t->wr_fd, (void*) memrq.addr, memrq.buf_sz)) != (ssize_t) memrq.buf_sz) {
            // Gracefully handle reads from invalid addresses
            if (ret == -EFAULT) {
                failed = 1;
                // Send zero bytes as padding
                for (size_t i = 0; i < memrq.buf_sz; i++)
                    if (write_full(t->wr_fd, "", 1) != 1)
                        return ret;
            } else {
                dprintf(2, "translator_get: failed writing from address 0x%lx\n", memrq.addr);
                return ret;
            }
        }

        if ((ret = write_full(t->wr_fd, &failed, 1)) != 1)
            return ret;

        t->written_bytes += memrq.buf_sz;
    }
}
