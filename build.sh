#!/usr/bin/env bash

mkdir -p build
meson build -Dprefix="$PWD"/install -Dbuildtype=release
ninja -C build
ninja -C build test
ninja -C build install