#!/bin/bash
# Register this machine in the restricted organization runner group for oneiron-dev/oneiron.
# (AGENTS.md "Self-hosted runners").
#
# usage: RUNNER_TOKEN=<token> scripts/ci/install-runner.sh <name> <labels> <os-arch> <cargo-target-dir> [tmpdir]
#
#   name              runner name in the org's oneiron-trusted group, e.g. mac-mini
#   labels            comma-separated; workflows target self-hosted,macos,arm64
#                     or self-hosted,linux,x64, so include those plus a host tag
#   os-arch           runner package flavour: osx-arm64 | linux-x64 | linux-arm64
#   cargo-target-dir  persistent build cache OUTSIDE any checkout, e.g. ~/ci/target
#                     (macOS: never under ~/Desktop, ~/Documents or ~/Downloads — the
#                     runner service has no TCC grant there and blocks on a prompt)
#   tmpdir            macOS only: a real (non-symlink) TMPDIR, e.g. /private/tmp/ci-t
#
# RUNNER_TOKEN is the short-lived ORGANIZATION registration token from
# Organization Settings -> Actions -> Runners. A repository token is unsafe.
# It is read from the environment only, and
# only on first registration: never write it to a file, a commit, or a shell
# line you would paste anywhere.
#
# Idempotent: the runner package is downloaded once, the registration runs
# once (.runner present = registered), and .env is rewritten every time so the
# exported cache contract is exactly the one below. Afterwards start it with
# ./run.sh (foreground) or ./svc.sh install && ./svc.sh start (service).
set -euo pipefail
if [ "$#" -lt 4 ]; then
  echo "usage: RUNNER_TOKEN=<token> $0 <name> <labels> <os-arch> <cargo-target-dir> [tmpdir]" >&2
  exit 2
fi
NAME="$1"; LABELS="$2"; OSARCH="$3"; TDIR="$4"; TMP="${5:-}"
VER=2.337.0; DIR="$HOME/actions-runner"
mkdir -p "$DIR" "$TDIR"; cd "$DIR"
if [ ! -x ./config.sh ]; then
  curl -sSL -o runner.tgz "https://github.com/actions/runner/releases/download/v${VER}/actions-runner-${OSARCH}-${VER}.tar.gz"
  tar xzf runner.tgz && rm runner.tgz
fi
if [ -f .runner ]; then
  # Never silently keep a legacy repository-level runner. Those runners are
  # outside the org's workflow-ref restriction and still accept fork jobs.
  python3 -c 'import json,sys; from pathlib import Path; sys.exit(0 if json.loads(Path(".runner").read_text()).get("gitHubUrl") == "https://github.com/oneiron-dev" else 1)' || {
    echo "refusing repository-level registration; remove it and re-register in oneiron-trusted" >&2
    exit 1
  }
else
  : "${RUNNER_TOKEN:?set RUNNER_TOKEN to a fresh ORGANIZATION registration token (environment only)}"
  ./config.sh --url https://github.com/oneiron-dev --runnergroup oneiron-trusted --token "$RUNNER_TOKEN" --name "$NAME" --labels "$LABELS" --work _work --unattended --replace >/tmp/runner-config.log 2>&1 || { tail -5 /tmp/runner-config.log; exit 1; }
fi
{ echo "CARGO_TARGET_DIR=$TDIR"; echo "CARGO_INCREMENTAL=0"; echo "PATH=$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"; [ -n "$TMP" ] && { mkdir -p "$TMP"; echo "TMPDIR=$TMP"; }; } > .env
echo "configured $(cat .runner | tr -d '\n' | cut -c1-120)"
