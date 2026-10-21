#!/usr/bin/env bash
# Builds the house model's llama.cpp `llama-server` with CUDA and with
# cpp-httplib's zstd and zlib support, so it decodes the engine's compressed
# request bodies (OF-604): cpp-httplib reads a request's Content-Encoding and
# hands llama-server the decoded body. Needs the zstd and zlib development
# packages (Debian/Ubuntu: libzstd-dev zlib1g-dev). See README.md.
#
# It builds llama.cpp at exactly LLAMA_CPP_COMMIT, the commit the house
# server runs (FIX 7895), in the checkout at ONEIRON_HOUSE_LLAMA_SRC, cloning
# it first when there is none. A checkout with changes to tracked files is
# refused, never built as the pin. Beside the binary it writes
# llama-server.build.json: the commit, the CMake flags and the binary's
# SHA-256, which each launch's identity manifest names (llama_identity.py).
set -euo pipefail

LLAMA_CPP_COMMIT=d81235049384534c167caea52b85a694f6103d14
: "${ONEIRON_HOUSE_LLAMA_SRC:=/opt/oneiron-house/llama.cpp}"
: "${ONEIRON_HOUSE_PYTHON:=/opt/oneiron-house/.venv/bin/python}"

if [ ! -d "$ONEIRON_HOUSE_LLAMA_SRC/.git" ]; then
  git clone https://github.com/ggml-org/llama.cpp "$ONEIRON_HOUSE_LLAMA_SRC"
fi
if ! git -C "$ONEIRON_HOUSE_LLAMA_SRC" cat-file -e "$LLAMA_CPP_COMMIT^{commit}" 2>/dev/null; then
  git -C "$ONEIRON_HOUSE_LLAMA_SRC" fetch --quiet origin "$LLAMA_CPP_COMMIT"
fi
if [ -n "$(git -C "$ONEIRON_HOUSE_LLAMA_SRC" status --porcelain --untracked-files=no)" ]; then
  echo "build-llama.sh: $ONEIRON_HOUSE_LLAMA_SRC has changes to tracked files; refusing to build it as $LLAMA_CPP_COMMIT" >&2
  exit 1
fi
git -C "$ONEIRON_HOUSE_LLAMA_SRC" -c advice.detachedHead=false checkout --quiet "$LLAMA_CPP_COMMIT"
if [ "$(git -C "$ONEIRON_HOUSE_LLAMA_SRC" rev-parse HEAD)" != "$LLAMA_CPP_COMMIT" ]; then
  echo "build-llama.sh: $ONEIRON_HOUSE_LLAMA_SRC is not at $LLAMA_CPP_COMMIT" >&2
  exit 1
fi

# llama.cpp's vendored cpp-httplib has no CMake switch for its codecs, so the
# two macros go to every C++ unit and both libraries to every C++ link.
cmake_flags=(
  -DCMAKE_BUILD_TYPE=Release
  -DGGML_CUDA=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TESTS=OFF
  "-DCMAKE_CXX_FLAGS=-DCPPHTTPLIB_ZSTD_SUPPORT -DCPPHTTPLIB_ZLIB_SUPPORT"
  "-DCMAKE_CXX_STANDARD_LIBRARIES=-lzstd -lz"
)
cmake -S "$ONEIRON_HOUSE_LLAMA_SRC" -B "$ONEIRON_HOUSE_LLAMA_SRC/build" "${cmake_flags[@]}"
cmake --build "$ONEIRON_HOUSE_LLAMA_SRC/build" --config Release --target llama-server -j "$(nproc)"

"$ONEIRON_HOUSE_PYTHON" "$(dirname "$0")/llama_identity.py" record-build \
  "$ONEIRON_HOUSE_LLAMA_SRC/build/bin/llama-server" "$LLAMA_CPP_COMMIT" -- "${cmake_flags[@]}"
