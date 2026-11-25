#!/usr/bin/env bash
# The harmless workload of the first job's step 3 (pass 33, 33-exec-node/DESIGN.md section 12 "R6 in five steps", T41).
# It computes nothing and never ends by itself. It ignores TERM, HUP and INT, and forks a child that leaves its session
# (setsid) and ignores them too, so only a kill of the whole job unit ends it. With --hold-device the child holds a CUDA
# context on the card the unit leased (python3 with ctypes on libcuda.so.1; no kernel is launched, so the card does no
# work), and the probe after the cutoff has a context to see gone.
#
# It writes only under $ONEIRON_JOB_OUT (the job unit sets it):
#   pids       one line per process: `<role> pid=<n> start=<field 22 of /proc/<n>/stat> sid=<n>`
#   heartbeat  `<role> <pid> <unix seconds>` from each process, every second
#   device     with --hold-device: `context pid=<n> device=<CUDA_VISIBLE_DEVICES>` once the context exists, or `refused <why>`
# check_cutoff_on_card.sh reads pids and heartbeat.
#
# usage (the template's entry): harmless_workload.sh [--hold-device]
set -u
out=${ONEIRON_JOB_OUT:?the job unit sets ONEIRON_JOB_OUT}
role=leader; hold=no
for arg in "$@"; do
  case $arg in
    --hold-device) hold=yes;;
    --child) role=child;;
    *) echo "unknown argument $arg" >&2; exit 64;;
  esac
done
trap '' TERM HUP INT

# This process's line for `pids`: its session (field 6 of /proc/<pid>/stat) and start time (field 22, in clock ticks),
# read after the command name, which may hold spaces.
record() {
  local pid=$BASHPID stat
  stat=$(cat "/proc/$pid/stat") || return 1; stat=${stat##*) }
  set -- $stat
  echo "$role pid=$pid start=${20} sid=$4" >> "$out/pids"
}
beat() { while :; do echo "$role $BASHPID $(date +%s)" >> "$out/heartbeat"; sleep 1; done; }

if [ "$role" = leader ]; then
  record
  child_args=(--child); [ "$hold" = yes ] && child_args+=(--hold-device)
  # Without job control the background job stays in this process group, so setsid(1) runs setsid(2) itself (it forks
  # only for a group leader) and the child's pid is its own.
  setsid bash "$0" "${child_args[@]}" &
  beat
fi

record
if [ "$hold" = yes ]; then
  # An ignored signal stays ignored across exec; python sets it again in case.
  exec python3 - "$out" "$role" <<'PY'
import ctypes, os, signal, sys, time
out, role = sys.argv[1], sys.argv[2]
for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(sig, signal.SIG_IGN)
def write(name, line):
    with open(os.path.join(out, name), "a") as f:
        f.write(line + "\n")
try:
    cuda = ctypes.CDLL("libcuda.so.1")
    device, context = ctypes.c_int(), ctypes.c_void_p()
    for step, rc in (("cuInit", lambda: cuda.cuInit(0)),
                     ("cuDeviceGet", lambda: cuda.cuDeviceGet(ctypes.byref(device), 0)),
                     ("cuCtxCreate", lambda: cuda.cuCtxCreate_v2(ctypes.byref(context), 0, device))):
        code = rc()
        if code != 0:
            raise RuntimeError(f"{step} returned {code}")
    write("device", f"context pid={os.getpid()} device={os.environ.get('CUDA_VISIBLE_DEVICES', '-')}")
except Exception as error:  # the job goes on without the card; the check reads why
    write("device", f"refused {error}")
while True:
    write("heartbeat", f"{role} {os.getpid()} {int(time.time())}")
    time.sleep(1)
PY
fi
beat
