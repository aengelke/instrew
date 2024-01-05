
#include "connection.h"

#include "cache.h"
#include "config.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <unordered_map>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>


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
    std::FILE* file;
    Msg::Hdr wr_hdr;
    Msg::Hdr recv_hdr;

    Conn(const Conn&) = delete;
    void operator=(const Conn& x) = delete;

public:
    Conn(int fd) : file(fdopen(fd, "rb+")), recv_hdr{} {}
    ~Conn() {
        fclose(file);
    }

    Conn& operator=(Conn&& x) {
        if (this != &x)
            std::swap(file, x.file);
        return *this;
    }

    Msg::Id RecvMsg() {
        assert(recv_hdr.sz == 0 && "unread message parts");
        if (!std::fread(&recv_hdr, sizeof(recv_hdr), 1, file))
            return Msg::C_EXIT; // probably EOF
        return static_cast<Msg::Id>(recv_hdr.id);
    }

    void Read(void* buf, size_t size) {
        if (static_cast<size_t>(recv_hdr.sz) < size)
            assert(false && "message too small");
        if (!std::fread(buf, size, 1, file))
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
        if (!std::fwrite(&wr_hdr, sizeof(wr_hdr), 1, file))
            assert(false && "unable to write msg hdr");
    }
    void Write(const void* buf, size_t size) {
        if (size > 0 && !std::fwrite(buf, size, 1, file))
            assert(false && "unable to write msg content");
        wr_hdr.sz -= size;
        if (wr_hdr.sz == 0)
            std::fflush(file);
    }
    void Sendfile(int fd, size_t size) {
        std::fflush(file);
        while (size) {
            ssize_t cnt = sendfile(fileno(file), fd, nullptr, size);
            if (cnt < 0)
                assert(false && "unable to write msg content (sendfile)");
            size -= cnt;
        }
        wr_hdr.sz -= size;
    }
    template<typename T>
    void SendMsg(Msg::Id id, const T& val) {
        SendMsgHdr(id, sizeof(T));
        Write(&val, sizeof(T));
    }

    template<typename T>
    void SendMsgWithFd(Msg::Id id, const T& val, int sendfd) {
        SendMsgHdr(id, sizeof(T));
        std::fflush(file);

        alignas(alignof(struct cmsghdr)) char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr msg{};
        void* vptr = reinterpret_cast<void*>(const_cast<T*>(&val));
        struct iovec msgiov = {vptr, sizeof(T)};
        msg.msg_iov = &msgiov;
        msg.msg_iovlen = 1;
        msg.msg_control = &cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

        ssize_t ret = sendmsg(fileno(file), &msg, 0);
        if (ret != sizeof(T)) {
            perror("sendmsg");
            assert(false && "unable to send socket fd");
        }
    }
};

int CreateChild(const char* stub_path, char* argv0, size_t uargc,
                const char* const* uargv) {
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds[0]);
    if (ret < 0) {
        perror("socketpair");
        std::exit(1);
    }

    std::string client_config = std::to_string(fds[1]);

    std::vector<const char*> exec_args;
    exec_args.reserve(uargc + 3);
    exec_args.push_back(argv0);
    exec_args.push_back(client_config.c_str());
    for (size_t i = 0; i < uargc; i++)
        exec_args.push_back(uargv[i]);
    exec_args.push_back(nullptr);

    int memfd = -1;
    if (!stub_path) {
        static const unsigned char instrew_stub[] = {
    #include "client.inc"
        };

        memfd = memfd_create("instrew_stub", MFD_CLOEXEC);
        if (memfd < 0) {
            perror("memfd_create");
            std::exit(1);
        }
        size_t written = 0;
        size_t total = sizeof(instrew_stub);
        while (written < total) {
            auto wres = write(memfd, instrew_stub + written, total - written);
            if (wres < 0) {
                perror("write");
                std::exit(1);
            }
            written += wres;
        }
    }

    pid_t forkres = fork();
    if (forkres < 0) {
        perror("fork");
        std::exit(1);
    } else if (forkres > 0) {
        close(fds[0]);
        if (memfd >= 0)
            fexecve(memfd, const_cast<char* const*>(&exec_args[0]), environ);
        else
            execve(stub_path, const_cast<char* const*>(&exec_args[0]), environ);
        perror("fexecve");
        std::exit(1);
    }
    if (memfd >= 0)
        close(memfd);
    close(fds[1]);
    return fds[0];
}

class RemoteMemory {
private:
    const static size_t PG_SIZE = 0x1000;
    using Page = std::array<uint8_t, PG_SIZE>;
    std::unordered_map<uint64_t, std::unique_ptr<Page>> page_cache;
    Conn& conn;

public:
    RemoteMemory(Conn& c) : conn(c) {}

private:
    Page* GetPage(size_t page_addr) {
        const auto& page_it = page_cache.find(page_addr);
        if (page_it != page_cache.end())
            return page_it->second.get();

        struct { uint64_t addr; size_t buf_sz; } send_buf{page_addr, PG_SIZE};
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
        size_t start_page = start & ~(PG_SIZE - 1);
        size_t end_page = end & ~(PG_SIZE - 1);
        size_t bytes_written = 0;
        for (size_t cur = start_page; cur <= end_page; cur += PG_SIZE) {
            Page* page = GetPage(cur);
            if (!page)
                break;
            size_t start_off = cur < start ? (start & (PG_SIZE - 1)) : 0;
            size_t end_off = cur + PG_SIZE > end ? (end & (PG_SIZE - 1)) : PG_SIZE;
            std::copy(page->data() + start_off, page->data() + end_off, buf + bytes_written);
            bytes_written += end_off - start_off;
        }
        return bytes_written;
    }
};

} // end namespace

struct IWConnection {
    const struct IWFunctions* fns;
    InstrewConfig& cfg;
    Conn& conn;

    IWServerConfig iwsc;
    IWClientConfig iwcc;
    bool need_iwcc;

    RemoteMemory remote_memory;
    instrew::Cache cache;

    IWConnection(const struct IWFunctions* fns, InstrewConfig& cfg, Conn& conn)
            : fns(fns), cfg(cfg), conn(conn), remote_memory(conn) {}

private:
    FILE* OpenObjDump(uint64_t addr) {
        if (!cfg.dumpobj)
            return nullptr;
        std::stringstream debug_out1_name;
        debug_out1_name << std::hex << "func_" << addr << ".elf";
        return std::fopen(debug_out1_name.str().c_str(), "wb");
    }

public:
    bool CacheProbe(uint64_t addr, const uint8_t* hash) {
        (void) addr;
        auto res = cache.Get(hash);
        if (res.first < 0)
            return false;
        conn.SendMsgHdr(Msg::S_OBJECT, res.second);
        conn.Sendfile(res.first, res.second);
        close(res.first);
        return true;
    }

    void SendObject(uint64_t addr, const void* data, size_t size,
                    const uint8_t* hash) {
        if (need_iwcc) {
            conn.SendMsg(Msg::S_INIT, iwcc);
            need_iwcc = false;
        }
        conn.SendMsgHdr(Msg::S_OBJECT, size);
        conn.Write(data, size);
        if (FILE* df = OpenObjDump(addr)) {
            std::fwrite(data, size, 1, df);
            std::fclose(df);
        }
        if (hash)
            cache.Put(hash, size, static_cast<const char*>(data));
    }

    int Run() {
        if (conn.RecvMsg() != Msg::C_INIT) {
            std::cerr << "error: expected C_INIT message" << std::endl;
            return 1;
        }
        iwsc = conn.Read<IWServerConfig>();
        // In mode 0, we need to respond with a client config.
        need_iwcc = iwsc.tsc_server_mode == 0;

        cache = instrew::Cache(cfg);

        IWState* state = fns->init(this, cfg);
        if (need_iwcc)
            SendObject(0, "", 0, nullptr); // this will send the client config

        while (true) {
            Msg::Id msgid = conn.RecvMsg();
            if (msgid == Msg::C_EXIT) {
                fns->finalize(state);
                state = nullptr;
                return 0;
            } else if (msgid == Msg::C_TRANSLATE) {
                auto addr = conn.Read<uint64_t>();
                fns->translate(state, addr);
            } else if (msgid == Msg::C_FORK) {
                int child_fds[2];
                int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, &child_fds[0]);
                if (ret < 0) {
                    int err = errno;
                    perror("socketpair");
                    conn.SendMsg(Msg::S_FD, -err);
                    continue;
                }

                pid_t pid = fork();
                if (pid < 0) {
                    conn.SendMsg(Msg::S_FD, -errno);
                    close(child_fds[0]);
                    close(child_fds[1]);
                } else if (pid == 0) {
                    conn = child_fds[0];
                    close(child_fds[1]);
                } else {
                    conn.SendMsgWithFd(Msg::S_FD, 0, child_fds[1]);
                    close(child_fds[0]);
                    close(child_fds[1]);
                }
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
bool iw_cache_probe(IWConnection* iwc, uintptr_t addr, const uint8_t* hash) {
    return iwc->CacheProbe(addr, hash);
}
void iw_sendobj(IWConnection* iwc, uintptr_t addr, const void* data,
                size_t size, const uint8_t* hash) {
    iwc->SendObject(addr, data, size, hash);
}

int iw_run_server(const struct IWFunctions* fns, int argc, char** argv) {
    InstrewConfig cfg(argc - 1, argv + 1);
    const char* stub = !cfg.stub.empty() ? cfg.stub.c_str() : nullptr;
    Conn conn(CreateChild(stub, argv[0], cfg.user_argc, cfg.user_args));
    IWConnection iwc{fns, cfg, conn};
    return iwc.Run();
}
