#!/usr/bin/env bash
# Builds exllamav3's CUDA extension (exllamav3_ext) with FP16 GEMM
# accumulators on the RTX 4090 (sm_89), for ONEIRON_HOUSE_EXL3_EXT_DIR
# (README, "GEMM FP16 accumulators"). exllamav3's EXL3 GEMM accumulates its
# MMA results in FP16 within each k-slice and folds them into FP32 once per
# slice, on sm_86 only; this build turns the same path on for sm_89, one
# line of exllamav3_ext/quant/exl3_gemm_inner.cuh (QWEN-EVAL-1 arm
# opus-skill A-0008).
#
# It builds exllamav3 at exactly EXLLAMAV3_COMMIT (v1.6.0, the version
# requirements-exl3.lock pins) with that one line changed, for sm_89 only,
# against the torch of ONEIRON_HOUSE_PYTHON. Into <out dir> it writes the
# extension module and exllamav3_ext.build.json: the commit, the changed
# line, the toolchain and the module's SHA-256. The server loads the module
# when <out dir> is first on PYTHONPATH (serve-exl3.sh) and names its SHA-256
# in its identity.
#
# Needs git, a CUDA 12.8 toolkit at CUDA_HOME (the CUDA torch 2.11.0+cu128 is
# built with) and, where the system compiler is newer than nvcc 12.8 takes, a
# host compiler it does take (gcc 14 or older) in CUDAHOSTCXX. MAX_JOBS bounds
# the parallel nvcc jobs (default 2; each can take several GiB). About 13
# minutes with 2 jobs.
#
# Usage: build-exl3-ext.sh <out dir>
set -euo pipefail

EXLLAMAV3_COMMIT=151539c77abc7ab7425d30da7a4e8e3c5c154e7b
EXLLAMAV3_REPO=https://github.com/turboderp-org/exllamav3
GEMM_INNER=exllamav3/exllamav3_ext/quant/exl3_gemm_inner.cuh
STOCK_LINE='#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ == 860)'
H_ACC_LINE='#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ == 860 || __CUDA_ARCH__ == 890)'

OUT=${1:?usage: build-exl3-ext.sh <out dir>}
: "${ONEIRON_HOUSE_PYTHON:=/opt/oneiron-house/.venv/bin/python}"
: "${CUDA_HOME:?build-exl3-ext.sh: set CUDA_HOME to a CUDA 12.8 toolkit}"
: "${MAX_JOBS:=2}"
export CUDA_HOME MAX_JOBS TORCH_CUDA_ARCH_LIST=8.9
# torch builds through the venv's ninja (requirements-exl3.lock pins it).
export PATH="$(dirname "$ONEIRON_HOUSE_PYTHON"):$PATH"

nvcc_release=$("$CUDA_HOME/bin/nvcc" --version | sed -n 's/.*release \([0-9.]*\),.*/\1/p')
if [ "$nvcc_release" != 12.8 ]; then
  echo "build-exl3-ext.sh: $CUDA_HOME/bin/nvcc is release '$nvcc_release', not 12.8" >&2
  exit 1
fi
torch_build=$("$ONEIRON_HOUSE_PYTHON" -c 'import torch; print(torch.__version__, torch.version.cuda)')
case "$torch_build" in
  *" 12.8") ;;
  *) echo "build-exl3-ext.sh: the torch of $ONEIRON_HOUSE_PYTHON is '$torch_build', not a CUDA 12.8 build" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$work" init --quiet src
git -C "$work/src" fetch --quiet --depth 1 "$EXLLAMAV3_REPO" "$EXLLAMAV3_COMMIT"
git -C "$work/src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD

# The one changed line, refused unless the stock line is there exactly once.
"$ONEIRON_HOUSE_PYTHON" - "$work/src/$GEMM_INNER" "$STOCK_LINE" "$H_ACC_LINE" <<'EOF'
import sys
from pathlib import Path

path, stock, h_acc = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = path.read_text().split("\n")
if lines.count(stock) != 1:
    sys.exit(f"build-exl3-ext.sh: {path.name} holds the sm_86 line {lines.count(stock)} times, not once")
lines[lines.index(stock)] = h_acc
path.write_text("\n".join(lines))
EOF

# torch's cpp_extension refuses a host compiler newer than its own table for
# the CUDA release, even one nvcc takes (gcc 14 with CUDA 12.8); the releases
# are checked above, and the table check is skipped for this build only.
(cd "$work/src" && "$ONEIRON_HOUSE_PYTHON" - "$work" <<'EOF'
import runpy
import sys

import torch.utils.cpp_extension as cpp_extension

cpp_extension._check_cuda_version = lambda *args, **kwargs: None
work = sys.argv[1]
sys.argv = ["setup.py", "build_ext", "--build-temp", f"{work}/tmp", "--build-lib", f"{work}/lib"]
runpy.run_path("setup.py", run_name="__main__")
EOF
) > "$work/build.log" 2>&1 || { tail -40 "$work/build.log" >&2; exit 1; }

built=("$work"/lib/exllamav3_ext*.so)
if [ "${#built[@]}" -ne 1 ] || [ ! -f "${built[0]}" ]; then
  echo "build-exl3-ext.sh: the build wrote no single exllamav3_ext module" >&2
  exit 1
fi
mkdir -p "$OUT"
module=$(basename "${built[0]}")
cp "${built[0]}" "$OUT/$module"
"$ONEIRON_HOUSE_PYTHON" - "$OUT" "$module" "$EXLLAMAV3_COMMIT" "$GEMM_INNER" "$H_ACC_LINE" "$nvcc_release" \
  "$torch_build" "${CUDAHOSTCXX:-}" <<'EOF'
import hashlib
import json
import sys
from pathlib import Path

out, module, commit, changed, line, nvcc, torch_build, host_cxx = sys.argv[1:]
record = {
    "exllamav3_commit": commit,
    "changed_file": changed,
    "changed_line": line,
    "cuda_arch": "8.9",
    "nvcc_release": nvcc,
    "torch": torch_build,
    "host_compiler": host_cxx or "nvcc default",
    "module": module,
    "sha256": hashlib.sha256((Path(out) / module).read_bytes()).hexdigest(),
}
(Path(out) / "exllamav3_ext.build.json").write_text(json.dumps(record, indent=2) + "\n")
print(f"built {module} sha256 {record['sha256']} into {out}")
EOF
