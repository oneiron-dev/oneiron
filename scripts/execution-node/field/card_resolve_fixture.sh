#!/usr/bin/env bash
# card.sh's card_resolve on both forms of the driver's minor line: "Device Minor: 0" and driver 615.78.08's
# "Device Minor: <TAB> 0" (FIX CARD-SH-MINOR-TAB-PARSE, R6 on mel, 26 Nov). Needs no root: a temporary driver tree and a
# stand-in nvidia-smi. Prints `## FIXTURE card-minor-<form> want=0 got=<minor> RIGHT|WRONG` per form, then
# `## FIXTURES rc=<n>` (0 when both read minor 0).
set -u
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
UUID=GPU-00000000-0000-4000-8000-0000000f1x00
export NVIDIA_PROC=$tmp/proc NVIDIA_DEV=$tmp/dev PATH=$tmp/bin:$PATH
mkdir -p "$NVIDIA_PROC/gpus/0000:01:00.0" "$NVIDIA_DEV" "$tmp/bin"
printf '#!/usr/bin/env bash\necho "%s, 00000000:01:00.0, 615.78.08"\n' "$UUID" > "$tmp/bin/nvidia-smi"
chmod 0755 "$tmp/bin/nvidia-smi"
. "$here/card.sh"
WRONG=0
for form in spaces tab; do
  case $form in
    spaces) minor_line='Device Minor: 0';;
    tab) minor_line=$'Device Minor: \t 0';;
  esac
  printf 'Model: Fixture\nGPU UUID: %s\n%s\n' "$UUID" "$minor_line" > "$NVIDIA_PROC/gpus/0000:01:00.0/information"
  CARD_MINOR=; CARD=()
  card_resolve "$UUID"
  if [ "$CARD_MINOR" = 0 ] && [ "${CARD[0]:-}" = "$NVIDIA_DEV/nvidia0" ]; then
    echo "## FIXTURE card-minor-$form want=0 got=$CARD_MINOR RIGHT"
  else
    echo "## FIXTURE card-minor-$form want=0 got=$(printf '%q' "$CARD_MINOR") WRONG"; WRONG=$((WRONG + 1))
  fi
done
echo "## FIXTURES rc=$WRONG"
exit "$WRONG"
