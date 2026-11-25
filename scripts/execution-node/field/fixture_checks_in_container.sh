#!/usr/bin/env bash
# Runs fixture_checks.sh as root inside a scratch container with systemd as process 1, so the two field checks are
# shown red and green on no real machine and no real card (row R6). The container is privileged (systemd needs its
# own cgroup tree, and the fixture makes device nodes) and is removed at the end, pass or fail.
# usage: fixture_checks_in_container.sh
# Its output is fixture_checks.sh's (`## FIXTURE ...`, `## FIXTURES rc=...`), after `## CONTAINER ...` lines.
set -u
here=$(cd "$(dirname "$0")" && pwd)
command -v docker > /dev/null || { echo "## FIXTURES rc=77 why=no-docker"; exit 77; }
. /etc/os-release
case $ID in
  arch)
    base=docker.io/library/archlinux:latest
    install="pacman -Syu --noconfirm --needed systemd dbus jq python util-linux procps-ng shadow coreutils gawk grep sed && pacman -Scc --noconfirm"
    init=/usr/lib/systemd/systemd;;
  debian | ubuntu)
    base=docker.io/library/$ID:${VERSION_CODENAME:-$VERSION_ID}
    install="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus jq python3 util-linux procps passwd coreutils gawk grep sed && rm -rf /var/lib/apt/lists/*"
    init=/lib/systemd/systemd;;
  *) echo "## FIXTURES rc=77 why=unsupported-host-distribution-$ID"; exit 77;;
esac
tag=oneiron-field-fixtures:$ID
echo "## CONTAINER base=$base"
docker build -q -t "$tag" - > /dev/null <<EOF || { echo "## FIXTURES rc=77 why=image-build-failed"; exit 77; }
FROM $base
RUN $install
STOPSIGNAL SIGRTMIN+3
EOF
name=oneiron-field-fixtures-$$-$(date +%s)
trap 'docker rm -f "$name" > /dev/null 2>&1' EXIT
docker run -d --name "$name" --privileged --cgroupns=private --memory 2g --cpus 2 \
  --tmpfs /run --tmpfs /run/lock -v "$here:/opt/field:ro" "$tag" "$init" > /dev/null \
  || { echo "## FIXTURES rc=77 why=container-did-not-start"; exit 77; }
state=$(docker exec "$name" timeout 120 systemctl is-system-running --wait 2>&1)
echo "## CONTAINER $name system=$state kernel=$(uname -r)"
docker exec "$name" bash /opt/field/fixture_checks.sh
