#!/bin/sh
# Chromium reads CDP from fd 3 and writes it to fd 4 (--remote-debugging-pipe).
# They are the container's stdin and stdout, so the host driver is the only
# client: no debugging port exists. stderr stays the container's stderr.
set -eu
# The engine serves a declared fixture through the same private HTTP door.
exec chromium \
  --headless \
  --no-sandbox \
  --disable-quic \
  --remote-debugging-pipe \
  --user-data-dir=/tmp/profile \
  --no-first-run \
  --no-default-browser-check \
  --disable-gpu \
  --disable-dev-shm-usage \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --disable-features=Translate,MediaRouter,OptimizationHints \
  --metrics-recording-only \
  --no-pings \
  --mute-audio \
  --hide-scrollbars \
  --password-store=basic \
  --window-size=1366,900 \
  about:blank 3<&0 4>&1 </dev/null >/dev/null
