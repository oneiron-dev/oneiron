#!/usr/bin/env bash
# Sourced by install.sh; requires ROOT, MM, and warn() from the caller.
mamba_env() {
  local prefix="$1" package="$2" required
  case "$package" in
    poppler=*) required=pdfsig ;;
    qpdf=*) required=qpdf ;;
    *) warn "unknown managed package: $package"; return 1 ;;
  esac
  if [[ -x "$prefix/bin/$required" ]]; then return 0; fi
  if [[ -z "$MM" ]]; then warn "cannot install $package: micromamba unavailable"; return 1; fi
  # Repair only a managed, incomplete prefix, even if conda-meta survived.
  if [[ -e "$prefix" ]]; then
    case "$prefix" in
      "$ROOT"/poppler/[0-9]*|"$ROOT"/qpdf) rm -rf -- "$prefix" ;;
      *) warn "refusing to remove unmanaged prefix: $prefix"; return 1 ;;
    esac
  fi
  if "$MM" create -y -c conda-forge -p "$prefix" "$package" >"$ROOT/logs/$(basename "$prefix")-install.log" 2>&1 && [[ -x "$prefix/bin/$required" ]]; then return 0; fi
  warn "failed to install $package under $prefix; see $ROOT/logs/$(basename "$prefix")-install.log"
  return 1
}
