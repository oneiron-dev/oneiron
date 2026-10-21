#!/bin/sh
# The first argument names the engine: lightpanda (the default) or chromium.
# The second names the largest CDP message the host sends; the host derives
# it from its egress door's largest answer body (BrowserEngine::guest_argv).
# Either way CDP rides the container's stdin and stdout, so the host driver
# is the only client, and stderr stays the container's stderr.
set -eu
case "${1:-lightpanda}" in
chromium)
# Chromium reads CDP from fd 3 and writes it to fd 4 (--remote-debugging-pipe).
# They are the container's stdin and stdout: no debugging port exists.
# The engine serves a declared fixture through the same private HTTP door.
# No crash reporter: its handler spawn calls setsid(), which the fence refuses
# (it keeps every guest process in the group it stops and kills), and Chromium
# aborts at start. The network service runs in the browser process: as a child
# it crash-loops on an FD ownership check once crashpad is off, and no page
# loads (FIX 7662, proved on the fenced guest 10-22).
exec chromium \
  --disable-crashpad-for-testing \
  --enable-features=NetworkServiceInProcess2 \
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
# the host's bound carries a Fetch.fulfillRequest with the egress door's
# whole largest body in base64 (FIX 6815).
export LIGHTPANDA_DISABLE_TELEMETRY=true
exec /usr/local/bin/oneiron-browser-relay 9222 -- \
  /usr/local/bin/lightpanda serve --host 127.0.0.1 --port 9222 --log-level info \
  --cdp-max-message-size "${2:?the host names the largest CDP message}"
;;
*)
echo "oneiron-browser-guest: no engine $1; name lightpanda or chromium" >&2
exit 2
;;
esac
