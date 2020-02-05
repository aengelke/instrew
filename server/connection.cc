
#include "connection.h"

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>


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
    struct Hdr {
        uint32_t id;
        int32_t sz;
    } __attribute__((packed));
}

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
    if (!std::fwrite(buf, size, 1, file_wr)) {
        std::cerr << "unable to write msg content" << std::endl;
        abort();
    }
}
