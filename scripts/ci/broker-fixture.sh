#!/usr/bin/env bash
# The credential broker's paid-leg fixture (ARCH-0069 `#broker-design`) with the
# broker as a second OS user. Elsewhere a host that cannot run a second user skips
# these cases; this is the reference Linux host's run, so such a host fails it.
# Needs an /etc/subuid and /etc/subgid range for this user, and newuidmap.
set -euo pipefail
cd "$(dirname "$0")/../.."
export ONEIRON_BROKER_FIXTURE=require
# The workspace's feature set, as in the full test leg, so the gate reuses that leg's `it`
# binary instead of building a second oneiron for `-p oneiron-server` alone. `--test it`
# builds only the `it` targets, so the cdylib crates the doctest step relinked stay as they are.
exec cargo nextest run --locked --workspace --all-features --test it --no-fail-fast \
  -E 'package(oneiron-server) & binary(=it) & test(/broker_paid_leg/)' "$@"
