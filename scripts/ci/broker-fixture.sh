#!/usr/bin/env bash
# The credential broker's paid-leg fixture (ARCH-0069 `#broker-design`) with the
# broker as a second OS user. Elsewhere a host that cannot run a second user skips
# these cases; this is the reference Linux host's run, so such a host fails it.
# Needs an /etc/subuid and /etc/subgid range for this user, and newuidmap.
set -euo pipefail
cd "$(dirname "$0")/../.."
export ONEIRON_BROKER_FIXTURE=require
exec cargo nextest run --locked -p oneiron-server --test it --all-features \
  --no-fail-fast -E 'test(/broker_paid_leg/)' "$@"
