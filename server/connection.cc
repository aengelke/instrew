
#include "connection.h"

#include "config.h"

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>


namespace {

struct HexBuffer {
    const uint8_t* buf;
    size_t size;
    friend std::ostream& operator<<(std::ostream& os, HexBuffer const& self) {
        os << std::hex << std::setfill('0');
        for (size_t i = 0; i != self.size; i++)
            os << std::setw(2) << static_cast<int>(self.buf[i]);
        return os << std::dec;
    }
};

namespace Msg {
    enum Id {
#define INSTREW_MESSAGE_ID(id, name) name = id,
#include "instrew-protocol.inc"
#undef INSTREW_MESSAGE_ID
    };
    struct Hdr {
        uint32_t id;
        int32_t sz;
    } __attribute__((packed));
}

class Conn {
private:
    std::FILE* file_rd;
    std::FILE* file_wr;
    Msg::Hdr wr_hdr;
    Msg::Hdr recv_hdr;

public:
    Conn() : file_rd(stdin), file_wr(stdout), recv_hdr{} { }

    Msg::Id RecvMsg() {
        assert(recv_hdr.sz == 0 && "unread message parts");
        if (!std::fread(&recv_hdr, sizeof(recv_hdr), 1, file_rd))
            return Msg::C_EXIT; // probably EOF
        return static_cast<Msg::Id>(recv_hdr.id);
    }

    void Read(void* buf, size_t size) {
        if (static_cast<size_t>(recv_hdr.sz) < size)
            assert(false && "message too small");
        if (!std::fread(buf, size, 1, file_rd))
            assert(false && "unable to read msg content");
        recv_hdr.sz -= size;
    }
    template<typename T>
    T Read() {
        T t;
        Read(&t, sizeof(t));
        return t;
    }

    void SendMsgHdr(Msg::Id id, size_t size) {
        assert(size <= INT32_MAX);
        wr_hdr = Msg::Hdr{ id, static_cast<int32_t>(size) };
        if (!std::fwrite(&wr_hdr, sizeof(wr_hdr), 1, file_wr))
            assert(false && "unable to write msg hdr");
    }
    void Write(const void* buf, size_t size) {
        if (size > 0 && !std::fwrite(buf, size, 1, file_wr))
            assert(false && "unable to write msg content");
        wr_hdr.sz -= size;
        if (wr_hdr.sz == 0)
            std::fflush(file_wr);
    }
    template<typename T>
    void SendMsg(Msg::Id id, const T& val) {
        SendMsgHdr(id, sizeof(T));
        Write(&val, sizeof(T));
    }
};

class RemoteMemory {
private:
    const static size_t PAGE_SIZE = 0x1000;
    using Page = std::array<uint8_t, PAGE_SIZE>;
    std::unordered_map<uint64_t, std::unique_ptr<Page>> page_cache;
    Conn& conn;

public:
    RemoteMemory(Conn& c) : conn(c) {}

private:
    Page* GetPage(size_t page_addr) {
        const auto& page_it = page_cache.find(page_addr);
        if (page_it != page_cache.end())
            return page_it->second.get();

        struct { uint64_t addr; size_t buf_sz; } send_buf{page_addr, PAGE_SIZE};
        conn.SendMsg(Msg::S_MEMREQ, send_buf);

        Msg::Id msgid = conn.RecvMsg();
        if (msgid != Msg::C_MEMBUF)
            return nullptr;

        auto page = std::make_unique<Page>();
        conn.Read(page->data(), page->size());
        uint8_t failed = conn.Read<uint8_t>();
        if (failed)
            return nullptr;

        page_cache[page_addr] = std::move(page);

        return page_cache[page_addr].get();
    };

public:
    size_t Get(size_t start, size_t end, uint8_t* buf) {
        size_t start_page = start & ~(PAGE_SIZE - 1);
        size_t end_page = end & ~(PAGE_SIZE - 1);
        size_t bytes_written = 0;
        for (size_t cur = start_page; cur <= end_page; cur += PAGE_SIZE) {
            Page* page = GetPage(cur);
            if (!page)
                break;
            size_t start_off = cur < start ? (start & (PAGE_SIZE - 1)) : 0;
            size_t end_off = cur + PAGE_SIZE > end ? (end & (PAGE_SIZE - 1)) : PAGE_SIZE;
            std::copy(page->data() + start_off, page->data() + end_off, buf + bytes_written);
            bytes_written += end_off - start_off;
        }
        return bytes_written;
    }
};

} // end namespace

struct IWConnection {
    const struct IWFunctions* fns;
    Conn& conn;

    InstrewConfig cfg;
    IWServerConfig iwsc;
    IWClientConfig iwcc;

    RemoteMemory remote_memory;

    IWConnection(const struct IWFunctions* fns, Conn& conn)
            : fns(fns), conn(conn), remote_memory(conn) {}

private:
    FILE* OpenObjDump(uint64_t addr) {
        if (!cfg.dumpobj)
            return nullptr;
        std::stringstream debug_out1_name;
        debug_out1_name << std::hex << "func_" << addr << ".elf";
        return std::fopen(debug_out1_name.str().c_str(), "wb");
    }


public:
    void SendObject(uint64_t addr, const void* data, size_t size) {
        conn.SendMsgHdr(Msg::S_OBJECT, size);
        conn.Write(data, size);
        if (FILE* df = OpenObjDump(addr)) {
            std::fwrite(data, size, 1, df);
            std::fclose(df);
        }
    }

    int Run(int argc, char** argv) {
        if (conn.RecvMsg() != Msg::C_INIT) {
            std::cerr << "error: expected C_INIT message" << std::endl;
            return 1;
        }
        iwsc = conn.Read<IWServerConfig>();

        cfg = InstrewConfig(argc - 1, argv + 1);

        IWState* state = fns->init(this, cfg);
        if (iwsc.tsc_server_mode == 0) {
            conn.SendMsg(Msg::S_INIT, iwcc);
            // TODO: send actual init object.
            SendObject(0, "", 0);
        }

        while (true) {
            Msg::Id msgid = conn.RecvMsg();
            if (msgid == Msg::C_EXIT) {
                fns->finalize(state);
                state = nullptr;
                return 0;
            } else if (msgid == Msg::C_TRANSLATE) {
                auto addr = conn.Read<uint64_t>();
                fns->translate(state, addr);
            } else {
                std::cerr << "unexpected msg " << msgid << std::endl;
                return 1;
            }
        }
    }
};

const struct IWServerConfig* iw_get_sc(IWConnection* iwc) {
    return &iwc->iwsc;
}
struct IWClientConfig* iw_get_cc(IWConnection* iwc) {
    return &iwc->iwcc;
}
size_t iw_readmem(IWConnection* iwc, uintptr_t addr, size_t len, uint8_t* buf) {
    return iwc->remote_memory.Get(addr, len, buf);
}
void iw_sendobj(IWConnection* iwc, uintptr_t addr, const void* data,
                size_t size) {
    iwc->SendObject(addr, data, size);
}

int iw_run_server(const struct IWFunctions* fns, int argc, char** argv) {
    // Set stdio to unbuffered
    std::setbuf(stdin, nullptr);
    Conn conn; // uses stdio

    IWConnection iwc{fns, conn};
    return iwc.Run(argc, argv);
}
