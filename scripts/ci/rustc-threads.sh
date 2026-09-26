#!/bin/bash
# Workspace wrapper: 2026-09-26 16-core measurement, core test build 334 s -> 169–198 s cold; 84 s -> 76 s edit.
# Only oneiron gets -Zthreads=8; ONEIRON_PARALLEL_FRONTEND=0 opts out. Exit 101 retries without -Zthreads.
rustc=$1; shift
crate=""; prev=""
for a in "$@"; do [ "$prev" = --crate-name ] && crate=$a; prev=$a; done
[ "$crate" = oneiron ] && [ "${ONEIRON_PARALLEL_FRONTEND:-1}" != 0 ] || exec "$rustc" "$@"
echo "rustc-threads: parallel front end for $crate (-Zthreads=${ONEIRON_RUSTC_THREADS:-8})" >&2
RUSTC_BOOTSTRAP=oneiron "$rustc" "$@" -Zthreads=${ONEIRON_RUSTC_THREADS:-8}
rc=$?
[ $rc -eq 101 ] || exit $rc
echo "rustc-threads: the parallel front end crashed on $crate; compiling it again without -Zthreads" >&2
exec "$rustc" "$@"
