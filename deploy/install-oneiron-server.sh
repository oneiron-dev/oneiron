#!/usr/bin/env sh
set -eu

ONEIRON_GIT_URL="${ONEIRON_GIT_URL:-https://github.com/oneiron-dev/oneiron}"

# Opt-in for a Linux host with the CUDA toolkit (`nvcc` on PATH): ONEIRON_CUDA=1
# builds candle's CUDA kernels, which an embedder or Oneironer `device = "cuda"`
# needs. They are candle's own features, not an oneiron-server feature, so the
# default build and `--all-features` stay free of the toolkit.
if [ "${ONEIRON_CUDA:-}" = "1" ]; then
  set -- "$@" --features candle-core/cuda,candle-nn/cuda
fi

if [ -n "${ONEIRON_GIT_REV:-}" ]; then
  exec cargo install --git "$ONEIRON_GIT_URL" --rev "$ONEIRON_GIT_REV" "$@" oneiron-server
fi

if [ -n "${ONEIRON_GIT_TAG:-}" ]; then
  exec cargo install --git "$ONEIRON_GIT_URL" --tag "$ONEIRON_GIT_TAG" "$@" oneiron-server
fi

ONEIRON_GIT_BRANCH="${ONEIRON_GIT_BRANCH:-main}"
exec cargo install --git "$ONEIRON_GIT_URL" --branch "$ONEIRON_GIT_BRANCH" "$@" oneiron-server
