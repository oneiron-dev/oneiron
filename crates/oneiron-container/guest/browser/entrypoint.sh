#!/bin/sh
# The first argument names the engine: lightpanda (the default) or chromium.
# Either way CDP rides the container's stdin and stdout, so the host driver
# is the only client, and stderr stays the container's stderr.
set -eu
case "${1:-lightpanda}" in
chromium)
# Chromium reads CDP from fd 3 and writes it to fd 4 (--remote-debugging-pipe).
# They are the container's stdin and stdout: no debugging port exists.
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
;;
lightpanda)
# Lightpanda serves CDP as a WebSocket on the guest's own 127.0.0.1:9222, a
# loopback inside the fence; no host port exists. The relay alone holds the
# container's stdin and stdout, carries that one connection over them, and
# ends the browser when either side ends. A start that drops the image's
# environment (Firecracker's) still sends no telemetry. Lightpanda closes a
# client whose message passes --cdp-max-message-size (1 MiB unless named):
# 64 MiB carries a Fetch.fulfillRequest with the egress door's whole 32 MiB
# body in base64.
export LIGHTPANDA_DISABLE_TELEMETRY=true
exec /usr/local/bin/oneiron-browser-relay 9222 -- \
  /usr/local/bin/lightpanda serve --host 127.0.0.1 --port 9222 --log-level info \
  --cdp-max-message-size 67108864
;;
*)
echo "oneiron-browser-guest: no engine $1; name lightpanda or chromium" >&2
exit 2
;;
esac
