#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--reader" ]]; then
  [[ $# == 3 ]] || { echo "usage: $0 --reader NAME PDF" >&2; exit 2; }
  exec python3 "$HERE/runner.py" --reader "$2" "$3"
fi
[[ $# == 1 ]] || { echo "usage: $0 [--reader NAME] PDF" >&2; exit 2; }
exec python3 "$HERE/runner.py" "$1"
