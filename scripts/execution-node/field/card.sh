# Sourced by check_device_handoff.sh and check_cutoff_on_card.sh: one NVIDIA card's files and state, read from the
# driver (NVIDIA_PROC, default /proc/driver/nvidia), its device nodes (NVIDIA_DEV, default /dev) and nvidia-smi.
# Fixtures set NVIDIA_PROC and NVIDIA_DEV and put a stand-in nvidia-smi first on PATH.
NVIDIA_PROC=${NVIDIA_PROC:-/proc/driver/nvidia}
NVIDIA_DEV=${NVIDIA_DEV:-/dev}

# card_resolve <uuid>: sets CARD_BUS, CARD_MINOR, CARD_DRIVER, CARD (the files that open the card: its node, nvidiactl
# and its drm nodes) and CARD_SIDE (the driver's other nodes, which open no card by themselves). Returns 1 when the
# driver names no such card.
card_resolve() {
  local row node f
  row=$(nvidia-smi --query-gpu=uuid,pci.bus_id,driver_version --format=csv,noheader 2> /dev/null \
    | awk -F', *' -v u="$1" '$1 == u')
  [ -n "$row" ] || return 1
  # nvidia-smi prints an 8-digit PCI domain, the driver's and sysfs's directories a 4-digit one.
  CARD_BUS=$(awk -F', *' '{ print tolower($2) }' <<< "$row"); CARD_BUS=${CARD_BUS: -12}
  CARD_DRIVER=$(awk -F', *' '{ print $3 }' <<< "$row")
  # Driver 615.78.08 writes "Device Minor: <TAB> 0": every blank after the colon goes (FIX CARD-SH-MINOR-TAB-PARSE).
  CARD_MINOR=$(awk -F':[[:space:]]*' '/^Device Minor/ { gsub(/[[:space:]]/, "", $2); print $2 }' \
    "$NVIDIA_PROC/gpus/$CARD_BUS/information" 2> /dev/null)
  [ -n "$CARD_MINOR" ] || return 1
  CARD=("$NVIDIA_DEV/nvidia$CARD_MINOR" "$NVIDIA_DEV/nvidiactl")
  for node in /sys/bus/pci/devices/"$CARD_BUS"/drm/card* /sys/bus/pci/devices/"$CARD_BUS"/drm/renderD*; do
    [ -e "$node" ] && CARD+=("$NVIDIA_DEV/dri/$(basename "$node")")
  done
  CARD_SIDE=()
  for f in "$NVIDIA_DEV/nvidia-uvm" "$NVIDIA_DEV/nvidia-uvm-tools" "$NVIDIA_DEV/nvidia-modeset"; do
    [ -e "$f" ] && CARD_SIDE+=("$f")
  done
  return 0
}

# card_holders [allowed command name]...: one line `<pid> <comm> <uid> <file> allowed|not-allowed` for each open
# descriptor on a file of CARD (card_resolve first).
card_holders() {
  local fd target f pid comm allowed a
  for fd in /proc/[0-9]*/fd/*; do
    target=$(readlink "$fd" 2> /dev/null) || continue
    for f in "${CARD[@]}"; do
      [ "$target" = "$f" ] || continue
      pid=${fd#/proc/}; pid=${pid%%/*}
      comm=$(cat "/proc/$pid/comm" 2> /dev/null)
      allowed=not-allowed; for a in "$@"; do [ "$comm" = "$a" ] && allowed=allowed; done
      echo "$pid $comm $(stat -c %u "/proc/$pid" 2> /dev/null) $f $allowed"
    done
  done
}

# card_contexts <uuid>: one line per compute context on the card (`<uuid>, <pid>, <name>`).
card_contexts() {
  nvidia-smi --query-compute-apps=gpu_uuid,pid,process_name --format=csv,noheader 2>&1 | awk -F', *' -v u="$1" '$1 == u'
}

# card_probe <uuid>: the card's answer to a query, and nvidia-smi's exit status.
card_probe() {
  nvidia-smi --query-gpu=uuid,memory.used,utilization.gpu --format=csv,noheader -i "$1" 2>&1
}
