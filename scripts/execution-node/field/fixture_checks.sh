#!/usr/bin/env bash
# Red and green runs of the two field checks on fixtures, so each check is shown to fail where its promise breaks and
# to pass where it holds, before it runs on a real card (row R6). Root, with systemd as process 1, on a SCRATCH machine:
# it makes accounts, fake device nodes and a stand-in nvidia-smi, and starts transient units. Run it in a container
# (fixture_checks_in_container.sh), never on a node.
#   T40 check_device_handoff.sh: red with the card's files open to every account (the box before the handoff); green
#       with them closed (phase nobody) and then open to the job account's group alone (phase oneiron-only).
#   T41 check_cutoff_on_card.sh: red when a TERM-ignoring child outlives its unit (KillMode=process); green when the
#       unit's whole group is killed at the maximum (KillMode=control-group), with the engine restarted meanwhile.
# The fake card has no driver behind it: an open that passes the permission check fails with ENXIO, which the T40
# check counts as opened, as it should.
# Prints `## FIXTURE <name> want=<PASS|FAIL> got=<PASS|FAIL|...> <RIGHT|WRONG>` per run, then `## FIXTURES rc=<n>`
# (0 when every run came out as wanted).
set -u
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "## FIXTURES rc=77 why=not-root"; exit 77; }
[ "$(cat /proc/1/comm 2> /dev/null)" = systemd ] || { echo "## FIXTURES rc=77 why=process-1-is-not-systemd"; exit 77; }
WRONG=0
fixture() { # <name> <want PASS|FAIL> <log file>: the TEST line of the log against the wanted result
  local got; got=$(awk '/^## TEST / { print $4 }' "$3" | tail -1)
  sed 's/^/    /' "$3"
  if [ "$got" = "$2" ]; then echo "## FIXTURE $1 want=$2 got=$got RIGHT"
  else echo "## FIXTURE $1 want=$2 got=${got:-none} WRONG"; WRONG=$((WRONG + 1)); fi
}

# The fake card: a driver tree, two device nodes and an nvidia-smi that answers for it. The nodes take a character
# major that no driver holds on this kernel (not the NVIDIA driver's 195, which a fleet host with a card has: there
# the open would reach the real card): one of the ranges the kernel keeps for local use (60-63, 120-127; the third,
# 240-254, is where it hands out dynamic majors), so an open past the permission check fails with ENXIO.
FX=/var/lib/oneiron-fixture; UUID=GPU-00000000-0000-4000-8000-0000000f1x00
export NVIDIA_PROC=$FX/proc NVIDIA_DEV=/dev/oneiron-fixture PATH=$FX/bin:$PATH
mkdir -p "$NVIDIA_PROC/gpus/0000:01:00.0" "$NVIDIA_DEV" "$FX/bin"
# The minor line as driver 615.78.08 writes it, with a tab (FIX CARD-SH-MINOR-TAB-PARSE).
printf 'Model: Fixture\nGPU UUID: %s\nDevice Minor: \t 0\n' "$UUID" > "$NVIDIA_PROC/gpus/0000:01:00.0/information"
major=$(awk '/^Character devices:/ { c = 1; next } /^$/ { c = 0 } c { print $1 }' /proc/devices \
  | awk 'BEGIN { split("60 61 62 63 120 121 122 123 124 125 126 127", local_use); for (i in local_use) free[local_use[i]] = 1 }
         { delete free[$1] }
         END { for (i = 1; i <= 12; i++) if (local_use[i] in free) { print local_use[i]; exit } }')
[ -n "$major" ] || { echo "## FIXTURES rc=77 why=no-free-local-use-character-major"; exit 77; }
rm -f "$NVIDIA_DEV/nvidia0" "$NVIDIA_DEV/nvidiactl"
mknod "$NVIDIA_DEV/nvidia0" c "$major" 0 && mknod "$NVIDIA_DEV/nvidiactl" c "$major" 255
echo "## FIXTURE-CARD major=$major (no driver) nodes=$NVIDIA_DEV"
: > "$FX/compute-apps"
cat > "$FX/bin/nvidia-smi" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *--query-gpu=uuid,pci.bus_id,driver_version*) echo "$UUID, 00000000:01:00.0, 999.99";;
  *--query-compute-apps*) cat "$FX/compute-apps";;
  *--query-gpu=uuid,memory.used,utilization.gpu*) echo "$UUID, 0 MiB, 0 %";;
  *) exit 2;;
esac
EOF
chmod 0755 "$FX/bin/nvidia-smi"
id -u oneiron-job > /dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin oneiron-job
for user in fixture-owner fixture-tool; do id -u "$user" > /dev/null 2>&1 || useradd --create-home "$user"; done
JOB_GID=$(id -g oneiron-job)
card() { # <owner:group> <mode> <driver gid> <driver mode, octal>: the files and the driver's setting
  chown "$1" "$NVIDIA_DEV/nvidia0" "$NVIDIA_DEV/nvidiactl"; chmod "$2" "$NVIDIA_DEV/nvidia0" "$NVIDIA_DEV/nvidiactl"
  printf 'ModifyDeviceFiles: 1\nDeviceFileUID: 0\nDeviceFileGID: %s\nDeviceFileMode: %s\n' "$3" "$((8#$4))" > "$NVIDIA_PROC/params"
  mkdir -p /etc/modprobe.d
  echo "options nvidia NVreg_DeviceFileUID=0 NVreg_DeviceFileGID=$3 NVreg_DeviceFileMode=0$4" > /etc/modprobe.d/oneiron-fixture.conf
}
t40() { bash "$here/check_device_handoff.sh" --device "$UUID" --job-account oneiron-job --evidence "$FX/evidence-$1.txt" "${@:2}"; }

card root:root 0666 0 666
t40 red --phase oneiron-only > "$FX/t40-red.log" 2>&1
fixture t40-open-to-every-account FAIL "$FX/t40-red.log"
card root:root 0600 0 600
t40 nobody --phase nobody > "$FX/t40-nobody.log" 2>&1
fixture t40-closed-to-every-account PASS "$FX/t40-nobody.log"
card "root:$JOB_GID" 0660 "$JOB_GID" 660
t40 green --phase oneiron-only > "$FX/t40-green.log" 2>&1
fixture t40-open-to-the-job-group-alone PASS "$FX/t40-green.log"
usermod -aG oneiron-job fixture-tool
t40 member --phase oneiron-only > "$FX/t40-member.log" 2>&1
fixture t40-another-account-in-the-job-group FAIL "$FX/t40-member.log"
gpasswd -d fixture-tool oneiron-job > /dev/null

# T41: one job of harmless_workload.sh in a transient unit cut off at its maximum, as R3b's unit is (the cutoff fires
# the stop grace before the maximum), and its end record written the way R3b's job-ended step writes it.
STATE=$FX/state; WORK=$FX/work; NODE_FILE=$FX/execution-node.toml
printf '[execution_node]\nstate_dir = "%s"\nwork_dir = "%s"\n' "$STATE" "$WORK" > "$NODE_FILE"
MAXIMUM=12; STOP_GRACE=2
boot_ns() { local up; read -r up _ < /proc/uptime; echo $(( ${up%.*} * 1000000000 + 10#${up#*.} * 10000000 )); }
engine() { systemctl stop oneiron-fixture-engine.service 2> /dev/null; systemd-run --quiet --unit oneiron-fixture-engine.service sleep infinity; }
t41() { # <label> <KillMode>
  local key=fixture-$1 id unit control out launch fired result empty
  id=$(printf '%s' "$key" | sha256sum | cut -c1-32); unit=oneiron-fixture-job-$id.service
  control=$STATE/control/$id; out=$WORK/$id/out
  rm -rf "$control" "$WORK/$id"; mkdir -p "$control" "$out" "$WORK/$id/checkout"
  cp "$here/harmless_workload.sh" "$WORK/$id/checkout/"; chown -R oneiron-job "$out"
  engine
  launch=$(boot_ns)
  printf '{"key":"%s","launch_boot_ns":%s,"maximum_secs":%s}\n' "$key" "$launch" "$MAXIMUM" > "$control/launch.json"
  systemd-run --quiet --unit "$unit" -p User=oneiron-job -p KillMode="$2" -p TimeoutStopSec="$STOP_GRACE" \
    -p RuntimeMaxSec=$((MAXIMUM - 2 * STOP_GRACE)) --setenv=ONEIRON_JOB_OUT="$out" \
    /usr/bin/bash "$WORK/$id/checkout/harmless_workload.sh"
  sleep 3
  local args=(--key "$key" --device "$UUID" --record "$FX/t41-$1.record" --node-file "$NODE_FILE"
    --engine-unit oneiron-fixture-engine.service --unit "$unit" --id "$id" --stop-grace-secs "$STOP_GRACE")
  bash "$here/check_cutoff_on_card.sh" --phase armed "${args[@]}" > "$FX/t41-$1-armed.log" 2>&1
  engine # the node's engine restarts while the job runs
  while [ "$(systemctl show "$unit" -p ActiveState --value)" != inactive ] && [ "$(systemctl show "$unit" -p ActiveState --value)" != failed ]; do sleep 1; done
  fired=$(boot_ns); result=$(systemctl show "$unit" -p Result --value)
  empty=true; [ -n "$(grep -lsF "/$unit" /proc/[0-9]*/cgroup)" ] && empty=false
  printf '{"instance":"%s","fired_boot_ns":%s}\n' "$id" "$fired" > "$control/cutoff.json"
  printf '{"key":"%s","service_result":"%s","boot_id":"%s","end_boot_ns":%s,"cutoff_fired":%s,"workload_started":true,"cgroup_empty":%s}\n' \
    "$key" "$result" "$(cat /proc/sys/kernel/random/boot_id)" "$fired" "$([ "$result" = timeout ] && echo true || echo false)" "$empty" \
    > "$control/ended.json"
  while [ "$(boot_ns)" -lt $(( launch + MAXIMUM * 1000000000 )) ]; do sleep 1; done
  bash "$here/check_cutoff_on_card.sh" --phase after "${args[@]}" > "$FX/t41-$1-after.log" 2>&1
  cat "$FX/t41-$1-armed.log" "$FX/t41-$1-after.log" > "$FX/t41-$1.log"
  pkill -KILL -u oneiron-job 2> /dev/null; systemctl reset-failed "$unit" 2> /dev/null
}
t41 red process
fixture t41-a-child-outlives-its-unit FAIL "$FX/t41-red.log"
t41 green control-group
fixture t41-the-whole-unit-ends-at-the-maximum PASS "$FX/t41-green.log"

echo "## FIXTURES rc=$WRONG"
exit "$WRONG"
