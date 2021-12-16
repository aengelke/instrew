
#include "connection.h"

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>


/* Protocol
 *
 * Client                       Server
 *>
 *   translate{addr}        -->
 *                          <-- memreq{addr, sz}
 *   membuf{addr, sz, buf}  -->
 *                          <-- memreq{addr, sz}
 *   membuf{addr, sz, buf}  -->
 *>
 *                          ...
 *>
 *                          <-- object{addr, objsz, objbuf}
 *
 */

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
    ssize_t remaining_sz;

public:
    Conn() : file_rd(stdin), file_wr(stdout), remaining_sz(0) { }

    Msg::Id RecvMsg();

    std::size_t Remaining() {
        return remaining_sz;
    }

    void Read(void* buf, size_t size);
    template<typename T>
    T Read() {
        T t;
        Read(&t, sizeof(t));
        return t;
    }

    void SendMsg(Msg::Id id, const void* buf, size_t size);
    template<typename T>
    void SendMsg(Msg::Id id, const T& val) {
        SendMsg(id, &val, sizeof(T));
    }
};

Msg::Id Conn::RecvMsg() {
    if (remaining_sz > 0) {
        std::cerr << "previous message too long" << std::endl;
        abort();
    }

    Msg::Hdr hdr;
    if (!std::fread(&hdr, sizeof(hdr), 1, file_rd)) {
        if (std::feof(file_rd)) {
            remaining_sz = 0;
            return Msg::C_EXIT;
        }
        std::cerr << "unable to read msghdr" << std::endl;
        abort();
    }
    remaining_sz = hdr.sz;
    return static_cast<Msg::Id>(hdr.id);
}

void Conn::Read(void* buf, size_t size) {
    if (size == 0)
        return;
    if (remaining_sz >= 0 && (size_t) remaining_sz < size) {
        std::cerr << "tried to read " << size << "; but have " << remaining_sz << std::endl;
        abort();
    }
    if (!std::fread(buf, size, 1, file_rd)) {
        std::cerr << "unable to read msg content" << std::endl;
        abort();
    }
    // std::cerr << "server_read: " << HexBuffer{static_cast<const uint8_t*>(buf), size} << std::endl;
    if (remaining_sz >= 0)
        remaining_sz -= size;
}

void Conn::SendMsg(Msg::Id id, const void* buf, size_t size) {
    if (size > INT32_MAX) {
        std::cerr << "error: message too big" << std::endl;
        abort();
    }
    Msg::Hdr hdr{ id, static_cast<int32_t>(size) };
    if (!std::fwrite(&hdr, sizeof(hdr), 1, file_wr)) {
        std::cerr << "unable to write msghdr" << std::endl;
        abort();
    }
    // std::cerr << "server_write: " << HexBuffer{static_cast<const uint8_t*>(buf), size} << std::endl;
    if (size > 0 && !std::fwrite(buf, size, 1, file_wr)) {
        std::cerr << "unable to write msg content" << std::endl;
        abort();
    }
}

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
        std::size_t msgsz = conn.Remaining();

        // Sanity checks.
        if (msgid != Msg::C_MEMBUF)
            return nullptr;
        if (msgsz != PAGE_SIZE + 1)
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

    IWServerConfig iwsc;
    IWClientConfig iwcc;
    bool dumpobj;
    RemoteMemory remote_memory;

    IWConnection(const struct IWFunctions* fns, Conn& conn)
            : fns(fns), conn(conn), remote_memory(conn) {}

    void SendObject(IWObject obj, uint64_t addr) {
        conn.SendMsg(Msg::S_OBJECT, obj.data, obj.size);

        if (dumpobj) {
            std::stringstream debug_out1_name;
            debug_out1_name << std::hex << "func_" << addr << ".elf";

            std::ofstream debug_out1;
            debug_out1.open(debug_out1_name.str(), std::ios::binary);
            debug_out1.write(static_cast<const char*>(obj.data), obj.size);
            debug_out1.close();
        }
    }

    int Run(int argc, char** argv) {
        if (conn.RecvMsg() != Msg::C_INIT) {
            std::cerr << "error: expected C_INIT message" << std::endl;
            return 1;
        }
        iwsc = conn.Read<IWServerConfig>();

        IWState* state = fns->init(this, argc, argv);
        if (iwsc.tsc_server_mode == 0) {
            conn.SendMsg(Msg::S_INIT, iwcc);
            // TODO: send actual init object.
            SendObject(IWObject{"", 0}, 0);
        }

        while (true) {
            Msg::Id msgid = conn.RecvMsg();
            if (msgid == Msg::C_EXIT) {
                fns->finalize(state);
                state = nullptr;
                return 0;
            } else if (msgid == Msg::C_TRANSLATE) {
                auto addr = conn.Read<uint64_t>();
                SendObject(fns->translate(state, addr), addr);
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
void iw_set_dumpobj(IWConnection* iwc, bool dumpobj) {
    iwc->dumpobj = dumpobj;
}
size_t iw_readmem(IWConnection* iwc, uintptr_t addr, size_t len, uint8_t* buf) {
    return iwc->remote_memory.Get(addr, len, buf);
}

int iw_run_server(const struct IWFunctions* fns, int argc, char** argv) {
    // Set stdio to unbuffered
    std::setbuf(stdin, nullptr);
    std::setbuf(stdout, nullptr);
    Conn conn; // uses stdio

    IWConnection iwc{fns, conn};
    return iwc.Run(argc, argv);
}
