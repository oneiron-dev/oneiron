#!/usr/bin/env bash
# Runs qualify_systemd_scope.sh as root inside a scratch container with systemd as process 1, so the job unit is
# qualified on no real machine (pass 33 row R3b). The container is privileged (systemd needs its own cgroup tree,
# mounts and namespaces) and is removed at the end, pass or fail.
#
# The image is the host's own distribution, so the `oneiron` binary built on the host runs in it: the packages that
# own the binary's shared libraries on the host are installed in it too.
#
# usage: qualify_in_container.sh <oneiron binary> [qualify_systemd_scope.sh arguments...]
# Its output is qualify_systemd_scope.sh's (`## TEST ...`, `## QUALIFY rc=...`), after `## CONTAINER ...` lines.
set -u
bin=$(realpath "${1:?the oneiron binary}"); shift
here=$(cd "$(dirname "$0")" && pwd)
command -v docker > /dev/null || { echo "## QUALIFY rc=77 why=no-docker"; exit 77; }
. /etc/os-release
case $ID in
  arch)
    base=docker.io/library/archlinux:latest
    owners=$(ldd "$bin" | awk '/=> \// { print $3 }' | xargs -r pacman -Qoq 2> /dev/null | sort -u | tr '\n' ' ')
    install="pacman -Syu --noconfirm --needed systemd polkit dbus jq socat util-linux procps-ng iproute2 shadow coreutils $owners && pacman -Scc --noconfirm"
    init=/usr/lib/systemd/systemd;;
  debian | ubuntu)
    base=docker.io/library/$ID:${VERSION_CODENAME:-$VERSION_ID}
    owners=$(ldd "$bin" | awk '/=> \// { print $3 }' | xargs -r dpkg -S 2> /dev/null | cut -d: -f1 | sort -u | tr '\n' ' ')
    install="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus polkitd jq socat util-linux procps iproute2 passwd coreutils $owners && rm -rf /var/lib/apt/lists/*"
    init=/lib/systemd/systemd;;
  *) echo "## QUALIFY rc=77 why=unsupported-host-distribution-$ID"; exit 77;;
esac
tag=oneiron-qualify-systemd:$ID
echo "## CONTAINER base=$base packages-for-libraries=[$owners]"
docker build -q -t "$tag" - > /dev/null <<EOF || { echo "## QUALIFY rc=77 why=image-build-failed"; exit 77; }
FROM $base
RUN $install
STOPSIGNAL SIGRTMIN+3
EOF
name=oneiron-qualify-$$-$(date +%s)
stage=$(mktemp -d)
trap 'docker rm -f "$name" > /dev/null 2>&1; rm -rf "$stage"' EXIT
cp "$bin" "$stage/oneiron" && cp "$here/qualify_systemd_scope.sh" "$here/qualify_device_query.sh" "$stage/"
docker run -d --name "$name" --privileged --cgroupns=private --memory 8g --cpus 4 \
  --tmpfs /run --tmpfs /run/lock -v "$stage:/opt/qualify:ro" "$tag" "$init" > /dev/null \
  || { echo "## QUALIFY rc=77 why=container-did-not-start"; exit 77; }
# Every `docker exec` before systemd has made its cgroups lands in the container's root cgroup, and while a process
# lives there systemd can enable no controller (cgroup v2: a cgroup with processes delegates none; qualification q2,
# 25 Nov: no pids.max, every job refused). So wait for the manager's socket with short execs only, and run the
# qualification in a scope of its own, which takes it out of the root cgroup.
# The boot wait is short execs too (review r4 R4-03): no `--wait` that would sit in the root cgroup while systemd
# starts.
for _ in $(seq 1 240); do docker exec "$name" test -S /run/systemd/private 2> /dev/null && break; sleep 0.5; done
for _ in $(seq 1 240); do
  state=$(docker exec "$name" systemctl is-system-running 2>&1)
  case $state in running | degraded) break;; esac
  sleep 0.5
done
echo "## CONTAINER $name system=$state kernel=$(uname -r)"
docker exec "$name" systemd-run --scope --quiet --unit=oneiron-qualify-run \
  bash /opt/qualify/qualify_systemd_scope.sh --oneiron /opt/qualify/oneiron "$@"
rc=$?
[ $rc -ne 0 ] && docker exec "$name" journalctl --no-pager -n 200 -u 'oneiron-job*' 2> /dev/null | sed 's/^/## JOURNAL /'
exit $rc
