# tsc-rs type checker module

`artifacts/ts_rust.wasm` is tsc-rs (`pingdotgg/ts-rust`, a Rust port of the
native TypeScript 7 compiler) built for `wasm32-wasip1` from its `ts_wasm`
crate. It is a selectable backend (`backend = "tsc-rs"`) of the optional
code-mode type check (`crates/oneiron-code-check`), whose default is tsrs: the
engine runs it on its own Wasmtime to check each program beside it as it
runs. The check is off by default. `mode = "shadow"`
under `[models.code_mode.check]` turns it on; it then records each program's
diagnostics and blocks nothing. The module is the compiler only: it never runs
a program.

## Pins

- tsc-rs commit `80f9944aab296595c4c9aa4d9d1ad65d1e5f76f6`, which ports
  TypeScript 7.1-dev at `673a5f17d713bdc8c7185f18a9c11e3c4ac5d781`.
- Upstream's `wasm` cargo profile (opt-level `z`, fat LTO, `panic = "abort"`),
  with no `wasm-opt` pass, so the build needs no binaryen or Node.
- `manifest.json` records the toolchain, the module's SHA-256 and size, and
  the notices' digests. The host (`crates/oneiron-code-check/src/tsc_rs.rs`)
  checks the same SHA-256 before it compiles the module.

The correctness oracle is Microsoft's TypeScript `7.1.0-dev.20261010.1`
(`MICROSOFT_TS_VERSION`), run as an external process. Both give the same
diagnostics on `crates/oneiron-code-check/tests/fixtures`.

## Build

The script installs no tools. The build host needs Rust 1.96 with the
`wasm32-wasip1` target, git, and an owned `CARGO_TARGET_DIR`. From the
repository root:

```text
python3 components/tsc-rs/build.py
python3 components/tsc-rs/build.py --check
```

The build clones the pinned commit into the target directory (or takes
`--source <checkout>`), maps every build path out of the module, and writes the
module, its manifest and its notices. `--check` verifies the module, the
notices, the host's literal pins and the import inventory without building.

## ABI

The module exports `memory`, `ts_input`, `ts_run`, `ts_output` and
`ts_output_len`, and imports `ts_host.fs`, `ts_host.fs_take` and a fixed set of
`wasi_snapshot_preview1` calls (`crates/ts_wasm/src/{lib,host}.rs` upstream).
`build.py` pins the whole import list with signatures, and `--check` requires
the host to register each `ts_host` call and no import the module lacks.
The engine answers them in memory: a read-only file system holding only the
check's files, a fixed clock, seeded random bytes, stdout captured up to a
bound, and `ENOSYS` for every other WASI call. A panic exits through
`proc_exit`, and anything on stderr marks the check crashed; either ends the
check, never the engine.

## Licence

tsc-rs is MIT; the parts it ports keep theirs (TypeScript Apache-2.0, Go
BSD-3-Clause, Unicode, vscode-languageserver-node MIT), so the module is
`MIT AND Apache-2.0`. `artifacts/notices/` carries the upstream `LICENSE`,
`NOTICE.md` and `licenses/`, and must travel with the module.
