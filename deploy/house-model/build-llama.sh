#!/usr/bin/env bash
# Builds the house model's llama.cpp `llama-server` with CUDA and with
# cpp-httplib's zstd and zlib support, so it decodes the engine's compressed
# request bodies (OF-604): cpp-httplib reads a request's Content-Encoding and
# hands llama-server the decoded body. Needs the zstd and zlib development
# packages (Debian/Ubuntu: libzstd-dev zlib1g-dev). See README.md.
#
# It builds the checkout at ONEIRON_HOUSE_LLAMA_SRC as it stands, cloning it
# first when there is none; pin the revision there.
set -euo pipefail

: "${ONEIRON_HOUSE_LLAMA_SRC:=/opt/oneiron-house/llama.cpp}"

if [ ! -d "$ONEIRON_HOUSE_LLAMA_SRC/.git" ]; then
  git clone https://github.com/ggml-org/llama.cpp "$ONEIRON_HOUSE_LLAMA_SRC"
fi
# llama.cpp's vendored cpp-httplib has no CMake switch for its codecs, so the
# two macros go to every C++ unit and both libraries to every C++ link.
cmake -S "$ONEIRON_HOUSE_LLAMA_SRC" -B "$ONEIRON_HOUSE_LLAMA_SRC/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DGGML_CUDA=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TESTS=OFF \
  "-DCMAKE_CXX_FLAGS=-DCPPHTTPLIB_ZSTD_SUPPORT -DCPPHTTPLIB_ZLIB_SUPPORT" \
  "-DCMAKE_CXX_STANDARD_LIBRARIES=-lzstd -lz"
cmake --build "$ONEIRON_HOUSE_LLAMA_SRC/build" --config Release --target llama-server -j "$(nproc)"
