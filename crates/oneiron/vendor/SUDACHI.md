# Sudachi 0.6.11 Android portability patch

Source: `https://github.com/WorksApplications/sudachi.rs`, tag `v0.6.11`,
commit `90fd6068c80c2fc3b63e0dbab0e341475bad4d8f` (the existing lockfile pin).
The Apache-2.0 LICENSE and upstream copyright notices are retained.

This snapshot includes `sudachi/` (including its tests), `resources/`, `plugin/`,
`Cargo.toml`, `LICENSE`, `README.md`, and `CHANGELOG.md`.
The selected upstream `git archive` SHA-256 is `7bf6cdafe6cb4e4266eca7890888d382b6cc0672c81b1c68e0afe3b73bbc719a`.
It was copied from the already-resolved Cargo git checkout, not from a new version.

## Exact changes

1. `sudachi/src/plugin/loader.rs`: add `target_os = "android"` to the existing
   Linux/FreeBSD branch of `make_system_specific_name`. Android uses the same
   ELF `lib<name>.so` plugin filename. Bundled plugins and dictionary/tokenizer
   behavior are unchanged. Without this branch the Android build fails with
   E0425 because no platform implementation exists.
2. Root `Cargo.toml`: remove the CLI, fuzz, and Python workspace members and
   CLI default member, because they are not part of the vendored library.
   The library, its test plugins, package metadata, and all dependency
   requirements remain unchanged.

The engine workspace redirects only this git dependency to the snapshot.
It does not upgrade Sudachi or alter dependency versions. The Android target
build and Kotlin vault open/put/get/reopen instrumentation validate the embedded
engine path. Host analyzer tests retain their existing coverage.

Remove this snapshot once an audited upstream pin contains the Android branch;
do not replace it with a tokenizer-disable feature gate.
