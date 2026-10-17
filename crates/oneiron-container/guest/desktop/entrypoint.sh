#!/bin/sh
# The guest's desktop and its driver. cua-driver speaks MCP (JSON-RPC, one
# message per line) on the container's stdin and stdout, so the host session
# is its only client. Every other process writes to stderr: stdout carries
# the driver's replies alone. The apps it opens get their own null stdio.
set -eu
export DISPLAY=:99
export XDG_RUNTIME_DIR=/tmp/xdg
export XDG_CURRENT_DESKTOP=Openbox
# Apps expose their accessibility tree on the session's a11y bus.
export NO_AT_BRIDGE=0 GTK_MODULES=gail:atk-bridge ACCESSIBILITY_ENABLED=1
mkdir -p -m 0700 "$XDG_RUNTIME_DIR"

Xvfb "$DISPLAY" -screen 0 1366x900x24 -nolisten tcp </dev/null 1>&2 &
tries=0
while [ ! -S /tmp/.X11-unix/X99 ]; do
  tries=$((tries + 1))
  if [ "$tries" -gt 100 ]; then
    echo "the virtual display did not start" >&2
    exit 1
  fi
  sleep 0.1
done

# One session bus for the window manager, the apps and the driver; it
# starts the accessibility bus on demand.
exec dbus-run-session -- sh -c 'openbox </dev/null 1>&2 & exec cua-driver mcp --direct'
