
#include "config.h"

#include "connection.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>


namespace {

template<typename T> T ParseArg(const char* arg, size_t namelen);

template<> bool ParseArg<bool>(const char* arg, size_t namelen) {
    if (arg[namelen] != '\0')
        std::cerr << "ignoring extra characters for " << arg << std::endl;
    return true;
}
template<> int ParseArg<int>(const char* arg, size_t namelen) {
    if (arg[namelen] != '=') {
        std::cerr << "missing argument for " << arg << std::endl;
        return 0;
    }
    return strtol(arg + namelen + 1, NULL, 0);
}
template<> std::string ParseArg<std::string>(const char* arg, size_t namelen) {
    if (arg[namelen] != '=') {
        std::cerr << "missing argument for " << arg << std::endl;
        return 0;
    }
    return arg + namelen + 1;
}

} // anonymous namespace

InstrewConfig::InstrewConfig(int argc, const char* const* argv) {
    for (int i = 0; i < argc; i++) {
        const char* arg = argv[i];
        if (arg[0] == '-') {
            arg++;
            const char* realarg = arg;
            if (!strncmp(arg, "no", 2))
                realarg = arg + 2;

            if (false);
#define INSTREW_OPT(type, name, def) \
            else if (!strncmp(realarg, #name, sizeof(#name) - 1) && \
                (realarg[sizeof(#name) - 1] == '=' || !realarg[sizeof(#name) - 1])) \
                this->name = arg == realarg ? ParseArg<type>(arg, sizeof(#name) - 1) : type{};
#include "config.inc"
#undef INSTREW_OPT
            else
                std::cerr << "ignoring unknown server arg: " << realarg << std::endl;
        } else {
            user_argc = argc - i;
            user_args = &argv[i];
            break;
        }
    }
}
