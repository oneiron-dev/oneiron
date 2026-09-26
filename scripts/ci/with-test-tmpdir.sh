#!/bin/bash
# Keep a single CI test step's temp vaults on tmpfs only when 12 GiB is free and it permits execution.
# Do not change the runner's disk TMPDIR when tmpfs is small or unavailable.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 command [args...]" >&2
  exit 2
fi

available="$(df -Pk /dev/shm 2>/dev/null | awk 'NR == 2 { print $4 }')" || available=""
if [[ "$available" =~ ^[0-9]+$ ]] && (( available >= 12 * 1024 * 1024 )); then
  runner="${RUNNER_NAME:-runner}"
  runner="${runner//[^[:alnum:]_-]/_}"
  if ci_tmpdir="$(mktemp -d "/dev/shm/ci-${runner}-XXXXXXXX")"; then
    # Some tmpfs mounts are noexec. Tests can run hooks created under TMPDIR.
    probe="$ci_tmpdir/.exec-probe"
    if printf '#!/bin/sh\nexit 0\n' > "$probe" && chmod 700 "$probe" && "$probe" >/dev/null 2>&1; then
      rm -f -- "$probe"
      export TMPDIR="$ci_tmpdir"
      trap 'rm -rf -- "$ci_tmpdir"' EXIT
      trap 'exit 130' INT
      trap 'exit 143' TERM
      echo "test TMPDIR: $TMPDIR (tmpfs; cleaned after step)"
    else
      rm -rf -- "$ci_tmpdir"
      ci_tmpdir=""
    fi
  fi
fi
if [ -z "${ci_tmpdir:-}" ]; then
  echo "test TMPDIR: ${TMPDIR:-system default} (disk fallback; /dev/shm has less than 12 GiB free, non-executable, or unavailable)"
fi
"$@"
