#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
ROOT="${SEAL_INTEROP_HOME:-/mnt/wd16/w8-build/seal-interop}"
JOBS="${SEAL_INTEROP_BUILD_JOBS:-4}"
if ! [[ "$JOBS" =~ ^[1-4]$ ]]; then echo "SEAL_INTEROP_BUILD_JOBS must be 1..4" >&2; exit 2; fi
if ! mkdir -p "$ROOT"/{bin,cache,logs,share,poppler,java}; then echo "cannot create $ROOT" >&2; exit 2; fi
if [[ ! -w "$ROOT" ]]; then echo "not writable: $ROOT" >&2; exit 2; fi
warn() { printf 'WARN: %s\n' "$*" >&2; }

# Micromamba itself and every managed package/cache live under ROOT.
MM="$(command -v micromamba || true)"
if [[ -z "$MM" ]]; then
  case "$(uname -m)" in x86_64) mm_arch=linux-64;; aarch64|arm64) mm_arch=linux-aarch64;; *) mm_arch="";; esac
  if [[ -n "$mm_arch" ]]; then
    mkdir -p "$ROOT/bin"
    if curl -fsSL "https://micro.mamba.pm/api/micromamba/${mm_arch}/latest" | tar -xj -C "$ROOT" bin/micromamba; then MM="$ROOT/bin/micromamba"; else warn "micromamba bootstrap failed; exact conda-only readers may be unavailable"; fi
  else warn "unsupported architecture for micromamba: $(uname -m)"; fi
fi
export MAMBA_ROOT_PREFIX="$ROOT/mamba"
export CONDA_PKGS_DIRS="$ROOT/cache/conda-pkgs"
export MAMBA_PKGS_DIRS="$ROOT/cache/conda-pkgs"

mamba_env() {
  local prefix="$1" package="$2"
  if [[ -x "$prefix/bin/pdfsig" || -x "$prefix/bin/qpdf" || -x "$prefix/bin/python" ]]; then return 0; fi
  if [[ -z "$MM" ]]; then warn "cannot install $package: micromamba unavailable"; return 1; fi
  # Remove only an incomplete environment created at this exact managed prefix.
  if [[ -d "$prefix" && ! -d "$prefix/conda-meta" ]]; then rm -rf -- "$prefix"; fi
  if "$MM" create -y -c conda-forge -p "$prefix" "$package" >"$ROOT/logs/$(basename "$prefix")-install.log" 2>&1; then return 0; fi
  warn "failed to install $package under $prefix; see $ROOT/logs/$(basename "$prefix")-install.log"
  return 1
}

build_poppler22() {
  local src="$ROOT/cache/source/poppler-22.02.0" archive="$ROOT/cache/poppler-22.02.0.tar.xz" build="$ROOT/build/poppler-22.02.0" prefix="$ROOT/poppler/22.02.0"
  command -v cmake >/dev/null || { warn "cmake missing; Poppler22 unavailable"; return 1; }
  command -v make >/dev/null || { warn "make missing; Poppler22 unavailable"; return 1; }
  pkg-config --exists nss || { warn "NSS development files missing; cannot build cryptographic pdfsig for Poppler22"; return 1; }
  mkdir -p "$ROOT/cache/source" "$ROOT/build"
  local expected_sha="e390c8b806f6c9f0e35c8462033e0a738bb2460ebd660bdb8b6dca01556193e1" actual_sha
  if [[ ! -f "$archive" ]] && ! curl -fL --retry 3 https://poppler.freedesktop.org/poppler-22.02.0.tar.xz -o "$archive"; then rm -f "$archive"; warn "Poppler22 source download failed"; return 1; fi
  actual_sha="$(sha256sum "$archive" | awk '{print $1}')"
  if [[ "$actual_sha" != "$expected_sha" ]]; then rm -f "$archive"; warn "Poppler22 source checksum mismatch"; return 1; fi
  if [[ ! -f "$src/CMakeLists.txt" ]]; then
    mkdir -p "$src"
    if ! tar -xJf "$archive" --strip-components=1 -C "$src"; then warn "Poppler22 source extraction failed"; return 1; fi
  fi
  if ! cmake -S "$src" -B "$build" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_RPATH="$prefix/lib;$prefix/lib64" \
    -DENABLE_GLIB=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF -DENABLE_UTILS=ON \
    -DENABLE_CPP=ON -DENABLE_NSS3=ON -DENABLE_LIBCURL=OFF -DENABLE_BOOST=OFF \
    -DBUILD_GTK_TESTS=OFF -DBUILD_QT5_TESTS=OFF -DBUILD_QT6_TESTS=OFF -DBUILD_CPP_TESTS=OFF \
    >"$ROOT/logs/poppler-22.02-configure.log" 2>&1; then warn "Poppler22 configure failed; see $ROOT/logs/poppler-22.02-configure.log"; return 1; fi
  if ! cmake --build "$build" --parallel "$JOBS" >"$ROOT/logs/poppler-22.02-build.log" 2>&1; then warn "Poppler22 build failed; see $ROOT/logs/poppler-22.02-build.log"; return 1; fi
  if ! cmake --install "$build" >"$ROOT/logs/poppler-22.02-install.log" 2>&1; then warn "Poppler22 install failed; see $ROOT/logs/poppler-22.02-install.log"; return 1; fi
  [[ -x "$prefix/bin/pdfsig" ]] || { warn "Poppler22 build did not produce pdfsig"; return 1; }
}

# Poppler22 is best-effort: its failure must not block the other reader legs.
if [[ "${SEAL_INTEROP_SKIP_POPPLER22:-0}" != "1" && ! -x "$ROOT/poppler/22.02.0/bin/pdfsig" ]]; then
  if ! build_poppler22; then warn "continuing with Poppler22 row unavailable"; fi
fi
# Exact pins are used. Prefer a pre-existing exact-version binary; otherwise
# use a conda-forge build under ROOT. This does not install anything elsewhere.
for version in 24.02.0 25.02.0 26.05.0; do
  prefix="$ROOT/poppler/$version"
  [[ -x "$prefix/bin/pdfsig" ]] && continue
  candidate=""
  case "$version" in
    24.02.0) candidate="${SEAL_POPPLER_24_BIN:-/home/lexi/w8-opus/poppler-2402/bin}" ;;
    26.05.0) candidate="${SEAL_POPPLER_26_BIN:-/usr/bin}" ;;
  esac
  if [[ -x "$candidate/pdfsig" ]] && "$candidate/pdfsig" -v 2>&1 | grep -Fq "pdfsig version ${version}"; then
    mkdir -p "$prefix"
    printf '%s\n' "$candidate" >"$prefix/host-bin.path"
    continue
  fi
  if ! mamba_env "$prefix" "poppler=$version"; then warn "continuing with Poppler $version row unavailable"; fi
done

# qpdf is reused only when the host binary has the exact pin; otherwise install it under ROOT.
QPDF_BIN="$(command -v qpdf || true)"
if [[ -n "$QPDF_BIN" && "$($QPDF_BIN --version 2>/dev/null | head -1 | sed 's/^qpdf version //')" != "12.3.2" ]]; then QPDF_BIN=""; fi
if [[ -z "$QPDF_BIN" ]]; then
  if mamba_env "$ROOT/qpdf" 'qpdf=12.3.2'; then QPDF_BIN="$ROOT/qpdf/bin/qpdf"; else warn "qpdf row unavailable"; fi
fi

# pyHanko and PDFium share a pinned Python 3.12 venv. Failures are per-reader, not fatal.
PYTHON="$ROOT/venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  if [[ -n "$MM" ]]; then
    if "$MM" create -y -c conda-forge -p "$ROOT/python312" python=3.12 pip >"$ROOT/logs/python-install.log" 2>&1; then
      if "$ROOT/python312/bin/python" -m venv "$ROOT/venv"; then :; else warn "could not create Python venv"; fi
    else warn "Python 3.12 install failed; see $ROOT/logs/python-install.log"; fi
  else warn "Python venv unavailable; pyHanko/PDFium rows will be unavailable"; fi
fi
if [[ -x "$PYTHON" ]]; then
  if ! "$PYTHON" -c 'import pyhanko' >/dev/null 2>&1; then
    if command -v uv >/dev/null; then
      if ! UV_CACHE_DIR="$ROOT/cache/uv" UV_PROJECT_ENVIRONMENT="$ROOT/venv" uv sync --locked --project "$REPO_ROOT/crates/oneiron-seal/oracle" --python "${ROOT}/python312/bin/python" >"$ROOT/logs/pyhanko-install.log" 2>&1; then warn "pyHanko locked environment install failed; see $ROOT/logs/pyhanko-install.log"; fi
    else warn "uv unavailable; pyHanko row unavailable"; fi
  fi
  if ! "$PYTHON" -c 'import pypdfium2' >/dev/null 2>&1; then
    if command -v uv >/dev/null; then
      if ! UV_CACHE_DIR="$ROOT/cache/uv" uv pip install --python "$PYTHON" --only-binary :all: 'pypdfium2==4.30.0' >"$ROOT/logs/pdfium-install.log" 2>&1; then warn "PDFium wheel install failed; see $ROOT/logs/pdfium-install.log"; fi
    else warn "uv unavailable; PDFium row unavailable"; fi
  fi
fi
if [[ ! -f "$ROOT/npm/node_modules/pdfjs-dist/package.json" ]]; then
  if command -v npm >/dev/null && command -v node >/dev/null; then
    mkdir -p "$ROOT/npm"
    if ! npm_config_cache="$ROOT/cache/npm" npm install --prefix "$ROOT/npm" --ignore-scripts --no-audit --no-fund --save-exact 'pdfjs-dist@5.4.394' >"$ROOT/logs/pdfjs-install.log" 2>&1; then warn "pdf.js package install failed; see $ROOT/logs/pdfjs-install.log"; fi
  else warn "node/npm unavailable; pdf.js row unavailable"; fi
fi

# Java source/projects, Maven repository and build outputs all stay below ROOT.
if command -v mvn >/dev/null; then
  mkdir -p "$ROOT/src/pdfbox" "$ROOT/src/dss"
  cp -R "$SCRIPT_DIR/pdfbox/." "$ROOT/src/pdfbox/"
  cp -R "$SCRIPT_DIR/dss/." "$ROOT/src/dss/"
  if ! mvn -B -f "$ROOT/src/pdfbox/pom.xml" -Dmaven.repo.local="$ROOT/cache/m2" -Dmaven.test.skip=true package >"$ROOT/logs/pdfbox-build.log" 2>&1; then warn "PDFBox build failed; see $ROOT/logs/pdfbox-build.log"; fi
  if ! mvn -B -f "$ROOT/src/dss/pom.xml" -Dmaven.repo.local="$ROOT/cache/m2" -Dmaven.test.skip=true package >"$ROOT/logs/dss-build.log" 2>&1; then warn "DSS build failed; see $ROOT/logs/dss-build.log"; fi
else warn "mvn unavailable; DSS/PDFBox rows will be unavailable"; fi

# Task-local wrappers and sources.
cp "$SCRIPT_DIR/pyhanko_check.py" "$ROOT/share/pyhanko_check.py"
cp "$SCRIPT_DIR/pdfium.py" "$ROOT/share/pdfium.py"
cp "$SCRIPT_DIR/pdfjs.mjs" "$ROOT/share/pdfjs.mjs"
cp "$SCRIPT_DIR/reader_util.py" "$ROOT/share/reader_util.py"
write_shim() { local name="$1" body="$2"; printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$body" >"$ROOT/bin/$name"; chmod +x "$ROOT/bin/$name"; }
write_unavailable() {
  local name="$1" reader="$2" mode="$3" detail="$4"
  cat >"$ROOT/bin/$name" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '{"reader":"$reader","version":"unavailable","mode":"$mode","status":"unavailable","detail":"$detail"}'
exit 77
EOF
  chmod +x "$ROOT/bin/$name"
}
if [[ -x "$PYTHON" ]]; then
  write_shim seal-pyhanko "exec \"$PYTHON\" \"$ROOT/share/pyhanko_check.py\" \"\$@\""
  write_shim seal-pdfium "exec \"$PYTHON\" \"$ROOT/share/pdfium.py\" \"\$@\""
  write_shim seal-qpdf "exec \"$PYTHON\" \"$ROOT/share/reader_util.py\" qpdf \"$QPDF_BIN\" \"\$@\""
  for version in 22.02.0 24.02.0 25.02.0 26.05.0; do
    prefix="$ROOT/poppler/$version"
    if [[ -f "$prefix/host-bin.path" ]]; then bindir="$(cat "$prefix/host-bin.path")"; else bindir="$prefix/bin"; fi
    tag="${version%.*}"
    write_shim "seal-poppler-$tag" "exec \"$PYTHON\" \"$ROOT/share/reader_util.py\" poppler poppler-$version \"$bindir\" \"\$@\""
  done
else
  write_unavailable seal-pyhanko pyhanko verify "Python 3.12 venv unavailable"
  write_unavailable seal-pdfium pdfium parse "Python 3.12 venv unavailable"
  write_unavailable seal-qpdf qpdf check "Python 3.12 venv unavailable"
  for tag in 22.02 24.02 25.02 26.05; do write_unavailable "seal-poppler-$tag" "poppler-$tag" verify "Python 3.12 venv unavailable"; done
fi
if command -v node >/dev/null; then
  write_shim seal-pdfjs "SEAL_INTEROP_HOME=\"$ROOT\" exec node \"$ROOT/share/pdfjs.mjs\" \"\$@\""
else write_unavailable seal-pdfjs pdfjs parse "Node.js unavailable"; fi
if [[ -f "$ROOT/src/pdfbox/target/pdfbox-reader-1.0.jar" ]]; then
  write_shim seal-pdfbox "exec java -jar \"$ROOT/src/pdfbox/target/pdfbox-reader-1.0.jar\" \"\$@\""
else write_unavailable seal-pdfbox pdfbox verify "PDFBox Maven jar unavailable"; fi
if [[ -f "$ROOT/src/dss/target/dss-reader-1.0.jar" ]]; then
  write_shim seal-dss "exec java -jar \"$ROOT/src/dss/target/dss-reader-1.0.jar\" \"\$@\""
else write_unavailable seal-dss dss verify "EU DSS Maven jar unavailable"; fi

# Environment consumed by the optional oneiron-seal oracle. Extra PDFsig values
# are executable paths, not bin directories. Omit versions whose binary is absent.
PDFSIG_BINARIES=()
for version in 22.02.0 24.02.0 25.02.0 26.05.0; do
  prefix="$ROOT/poppler/$version"
  if [[ -f "$prefix/host-bin.path" ]]; then binary="$(cat "$prefix/host-bin.path")/pdfsig"; else binary="$prefix/bin/pdfsig"; fi
  if [[ -x "$binary" ]]; then PDFSIG_BINARIES+=("$binary"); fi
done
( printf 'export PATH="%s/venv/bin:$PATH"\n' "$ROOT"
  printf 'export SEAL_DSS_BIN="%s/bin/seal-dss"\n' "$ROOT"
  printf 'export SEAL_PDFBOX_BIN="%s/bin/seal-pdfbox"\n' "$ROOT"
  printf 'export SEAL_PDFIUM_BIN="%s/bin/seal-pdfium"\n' "$ROOT"
  printf 'export SEAL_PDFJS_BIN="%s/bin/seal-pdfjs"\n' "$ROOT"
  printf 'export SEAL_QPDF_BIN="%s/bin/seal-qpdf"\n' "$ROOT"
  printf 'export PDFSIG_EXTRA_BINARIES="%s"\n' "$(IFS=:; echo "${PDFSIG_BINARIES[*]}")" ) >"$ROOT/reader-env.sh"
echo "SEAL-INTEROP-INSTALLED root=$ROOT"
echo "source $ROOT/reader-env.sh; scripts/seal-interop/run.sh /path/to/sealed.pdf"
