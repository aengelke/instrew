
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

struct spawn_args {
    int pipes[6];
    const char* tool;
};

static int translator_init_child(void* args_cp) {
    int ret;

    struct spawn_args* args = args_cp;
    close(args->pipes[0]);
    close(args->pipes[3]);
    close(args->pipes[4]);
    ret = dup2(args->pipes[1], 1);
    if (ret < 0)
        goto fail;
    ret = dup2(args->pipes[2], 0);
    if (ret < 0)
        goto fail;

    const char* exec_args[] = {args->tool, NULL};
    ret = execve(args->tool, exec_args, (const char* const*) environ);
    if (ret < 0)
        goto fail;

fail:
    write(args->pipes[5], &ret, sizeof(ret));
    _exit(127);
}

int translator_init(Translator* t, const char* tool) {
    int ret;
    struct spawn_args args;
    char stack[1024];

    args.tool = tool;

    ret = pipe2(&args.pipes[0], 0);
    if (ret < 0)
        return ret;
    ret = pipe2(&args.pipes[2], 0);
    if (ret < 0) {
        close(args.pipes[0]);
        close(args.pipes[1]);
        return ret;
    }

    // Pipe used for passing an error from the child to the parent
    ret = pipe2(&args.pipes[4], O_CLOEXEC);
    if (ret < 0) {
        close(args.pipes[0]);
        close(args.pipes[1]);
        close(args.pipes[2]);
        close(args.pipes[3]);
        return ret;
    }

    ret = __clone(translator_init_child, stack + sizeof(stack),
                  CLONE_VM|CLONE_VFORK|SIGCHLD, &args);
    close(args.pipes[1]); // write-end of first pipe
    close(args.pipes[2]); // read-end of second pipe
    close(args.pipes[5]); // write-end of error pipe
    if (ret > 0) {
        if (read(args.pipes[4], &ret, sizeof(ret)) != sizeof(ret))
            ret = 0;
    }

    close(args.pipes[4]);
    if (ret == 0) {
        t->rd_fd = args.pipes[0];
        t->wr_fd = args.pipes[3];
    } else {
        close(args.pipes[0]);
        close(args.pipes[3]);
    }

    t->written_bytes = 0;
    t->last_hdr = (TranslatorMsgHdr) {MSGID_UNKNOWN, 0};

    return ret;
}

int translator_fini(Translator* t) {
    close(t->rd_fd);
    close(t->wr_fd);
    return 0;
}

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

int translator_config_begin(Translator* t) {
    return translator_hdr_send(t, MSGID_C_INIT, -1);
}

int translator_config_end(Translator* t) {
    int ret;
    if ((ret = write_full(t->wr_fd, "\0", 1)) != 1)
        return ret;
    return 0;
}

static int translator_config_write_bool(Translator* t, uint8_t id, bool val) {
    int ret;
    if ((ret = write_full(t->wr_fd, &id, sizeof(id))) != sizeof(id))
        return ret;
    if ((ret = write_full(t->wr_fd, &val, sizeof(uint8_t))) != sizeof(uint8_t))
        return ret;
    return 0;
}

static int translator_config_write_int32(Translator* t, uint8_t id, int32_t val) {
    int ret;
    if ((ret = write_full(t->wr_fd, &id, sizeof(id))) != sizeof(id))
        return ret;
    if ((ret = write_full(t->wr_fd, &val, sizeof(int32_t))) != sizeof(int32_t))
        return ret;
    return 0;
}

static int translator_config_write_str(Translator* t, uint8_t id, const char* val) {
    int ret;
    if ((ret = write_full(t->wr_fd, &id, sizeof(id))) != sizeof(id))
        return ret;
    size_t len64 = strlen(val);
    if (len64 > INT32_MAX)
        return -EINVAL;
    int32_t len32 = len64;
    if ((ret = write_full(t->wr_fd, &len32, sizeof(len32))) != sizeof(len32))
        return ret;
    if ((ret = write_full(t->wr_fd, val, len32)) != len32)
        return ret;
    return 0;
}

#define INSTREW_SERVER_CONF
#define INSTREW_SERVER_CONF_BOOL(id, name, default) \
        int translator_config_ ## name(Translator* t, bool val) { \
            return translator_config_write_bool(t, id, val); \
        }
#define INSTREW_SERVER_CONF_INT32(id, name, default) \
        int translator_config_ ## name(Translator* t, int32_t val) { \
            return translator_config_write_int32(t, id, val); \
        }
#define INSTREW_SERVER_CONF_STR(id, name, default) \
        int translator_config_ ## name(Translator* t, const char* val) { \
            return translator_config_write_str(t, id, val); \
        }
#include "instrew-protocol.inc"
#undef INSTREW_SERVER_CONF
#undef INSTREW_SERVER_CONF_BOOL
#undef INSTREW_SERVER_CONF_INT32
#undef INSTREW_SERVER_CONF_STR

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

    void* obj = mem_alloc(sz);
    if (BAD_ADDR(obj))
        return (int) (uintptr_t) obj;
    int ret = read_full(t->rd_fd, obj, sz);
    if (ret != (ssize_t) sz)
        return ret;

    *out_obj = obj;
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
