#!/bin/bash
# Register this machine as a GitHub Actions runner for oneiron-dev/oneiron
# (AGENTS.md "Self-hosted runners").
#
# usage: RUNNER_TOKEN=<token> scripts/ci/install-runner.sh <name> <labels> <os-arch> <cargo-target-dir> [tmpdir]
#
#   name              runner name on the repo's Runners page, e.g. mac-mini
#   labels            comma-separated; workflows target self-hosted,macos,arm64
#                     or self-hosted,linux,x64, so include those plus a host tag
#   os-arch           runner package flavour: osx-arm64 | linux-x64 | linux-arm64
#   cargo-target-dir  persistent build cache OUTSIDE any checkout, e.g. ~/ci/target
#                     (macOS: never under ~/Desktop, ~/Documents or ~/Downloads — the
#                     runner service has no TCC grant there and blocks on a prompt)
#   tmpdir            macOS only: a real (non-symlink) TMPDIR, e.g. /private/tmp/ci-t
#
# RUNNER_TOKEN is the short-lived registration token from Settings -> Actions ->
# Runners -> New self-hosted runner. It is read from the environment only, and
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
if [ ! -f .runner ]; then
  : "${RUNNER_TOKEN:?set RUNNER_TOKEN to a fresh registration token (environment only)}"
  ./config.sh --url https://github.com/oneiron-dev/oneiron --token "$RUNNER_TOKEN" --name "$NAME" --labels "$LABELS" --work _work --unattended --replace >/tmp/runner-config.log 2>&1 || { tail -5 /tmp/runner-config.log; exit 1; }
fi
{ echo "CARGO_TARGET_DIR=$TDIR"; echo "CARGO_INCREMENTAL=0"; echo "PATH=$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"; [ -n "$TMP" ] && { mkdir -p "$TMP"; echo "TMPDIR=$TMP"; }; } > .env
echo "configured $(cat .runner | tr -d '\n' | cut -c1-120)"
