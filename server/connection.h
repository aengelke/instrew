
#ifndef _INSTREW_SERVER_CONNECTION_H
#define _INSTREW_SERVER_CONNECTION_H

#include <cstddef>
#include <cstdio>
#include <cstdint>


namespace Msg {
    enum Id {
#define INSTREW_MESSAGE_ID(id, name) name = id,
#include "instrew-protocol.inc"
#undef INSTREW_MESSAGE_ID
    };
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

#endif
