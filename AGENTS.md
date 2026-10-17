# Agent guidance

Oneiron is a general-purpose memory engine (Rust workspace; core crate `crates/oneiron`, server
`crates/oneiron-server`, bindings `crates/oneiron-napi`). It is consumer-agnostic, and the repo is
public.

- Consumer boundary: `CLAUDE.md`. Products are built on top of the engine, never inside it: no
  product names, prompt/persona text, or product-branded modules in engine code.
- Review guidance: `REVIEW.md`.
- HTTP API reference for `oneiron-server`: `oneiron.skills.md` (over 70KB, too big for one read). Fetch
  it by tier heading, not by line number: `## Tier-1: Endpoint Activation Index`, `## Tier-2:
  Endpoint Details`, `## Tier-3: Schemas And Error Catalog`.

## Use the engine from an agent

On a Linux/macOS development/build host, from the repo root:

```sh
python3 examples/agent-quickstart/quickstart.py --keep-running
```

This installs this checkout, initializes a fresh vault with no model downloads,
mints an agent credential, starts loopback HTTP, saves and recalls a private diary
memory, and connects MCP stdio. Needs Python 3.11+, curl 7.76+, rustup and native
compiler tools; `--binary /absolute/path/to/oneiron` skips the build. It ignores
inherited `ONEIRON_*` overrides and never overwrites a vault. It prints the URL,
stop command, and absolute-path MCP config for Claude Code, Codex, or OpenCode.
No account, dashboard, API key, or interactive pairing is needed. Follow the
build-host rules below; never source-build this example on the owner's Mac.

Read `docs/agent-setup.md` for prerequisites, client config and repair. The complete
script is `examples/agent-quickstart/quickstart.py`. For direct HTTP use
`POST /v1/core/facade/self.memory.diary` with `{"content":"project note"}`, then
`POST /v1/core/facade/vault.recall` with
`{"query":"project note","effort":"light","limit":5}`. Authenticate with the
paired credential and holder proof (`oneiron api` signs it). For MCP, use the
printed `oneiron mcp --surface tool-first --credential-file <file> --url <origin>`
command, call `tools/list`, and pass verb inputs under `arguments.spec`.
A stopped vault needs `serve --config <config>`; the MCP bridge does not start it.

## The vibe build (owner decree, 2026-10-17)

These rules outrank every other process line in this repo.

- **Merge bar.** A change merges as soon as `cargo check --workspace --all-features` passes on its
  head. Nothing else blocks a merge. Add `--locked`, so a stale manifest fails instead of
  rewriting `Cargo.lock`.
- **No tests.** Do not write, compile or run tests. The existing tests stay in the repo, untouched.
- **No backward compatibility.** No vault exists yet. Write no migrations, legacy paths, upgrade
  code or old-format readers. Formats change freely.
- **No review rounds.** No Sol, Astra, CodeRabbit or Greptile review blocks a merge, and bot
  comments need no answer.
- No security sweeps, perf work, A/B tests, build-speed work or test work.
- **Fix list.** An issue you notice but do not fix goes on the owner's fix list,
  `/Users/olety/Desktop/temp/vibe-build-20261017/FIX-LIST.md` on the coordinator Mac, one line
  each: `- <MM-DD HH:MM> <lane>: <file:line or area> <issue>`.

A later pass writes an end-to-end suite and straightens the code. The old tests get fixed or
deleted in that pass.

## Git and hosts

- One git worktree per writer, outside the repo checkout. Branch from the newest `origin/main`.
- Sign every commit. No AI attribution lines (`Co-Authored-By`, "generated with") in commits or
  PR bodies.
- Squash-merge with an explicit body, so no branch commit trailer reaches `main`. Never
  force-push.
- Run Cargo on a fleet build host, never on the owner's MacBook. `rust-toolchain.toml` pins the
  toolchain.
- Never commit secrets.

## Commands

The merge bar:

    cargo check --locked --workspace --all-features

`scripts/verify.sh` is the full scripted check: fmt, clippy in three feature graphs, strict
rustdoc, the whole nextest suite, featureless library tests and doctests. It is not a merge bar.
`scripts/verify.sh --list` prints its eight stages and their commands without building;
`CODEMAP_CHECK=1` adds the code-map check as a first stage.

To format, run `cargo fmt -p <crate>` and inspect the diff. Never pass `--all`: it follows the
path dependency into the vendored `crates/heed`.

## Code map

Read `docs/CODEMAP.md` first (one row per crate, then each crate's top-level modules with layout,
size bucket and purpose), then search `docs/codemap/<crate>.md` for the owning module or type.
File paths in a crate map are relative to `crates/<crate>/`. The maps cover `crates/` only; the
macOS app lives at `apps/macos/src-tauri/` and is linked from the overview.

`scripts/codemap/` generates both map levels and the machine-readable `docs/codemap/codemap.json`.
Only `main` writes them: `.github/workflows/codemap.yml` regenerates and commits the map after
every push to `main`. Never hand-edit the map and never commit map output from a branch, so a
branch's map can lag its own changes. To read a fresh map for your branch, run
`python3 scripts/codemap/codemap.py`, then drop the output with
`git restore docs/CODEMAP.md docs/codemap`. `python3 scripts/codemap/codemap.py --sizes` prints
live line counts without changing the maps. The map is a source summary, not a call graph or
proof of which features compile.

For a narrow lookup, use `rg -n 'gate/evaluate|GateError' docs/codemap/oneiron.md`, then open the
matching path under `crates/oneiron/`. Do not load a large crate map (especially
`docs/codemap/oneiron.md`) whole.

Size and dependency questions without `tokei` or `cargo-modules` (`rg` is present):

    rg --files -g '*.rs' crates/oneiron/src | xargs wc -l | sort -n | tail -20      # biggest files
    rg -l 'crate::pipeline\b' crates --type rust                                     # who names a module
    rg -oIN '\bcrate::[a-z_]+' crates/oneiron/src/pipeline | sort | uniq -c | sort -rn  # what a module names

## Where code lives

The core is split into lower engine crates below `oneiron`. `crates/oneiron-contracts` is the
lowest: shared value vocabulary that depends on nothing in `oneiron`. A moved module keeps its
`oneiron::<module>` path through a facade file in `crates/oneiron/src/` that re-exports it; edit
the definition in the lower crate. A `#[non_exhaustive]` enum that `oneiron` matches exhaustively
stays in `oneiron`, because the attribute only allows exhaustive matches inside the defining
crate.

A substantial module is a directory module, `foo/mod.rs` plus children, with a `pub use` seam
that keeps every `crate::foo::*` path unchanged (`crates/oneiron/src/pipeline/mod.rs` shows the
shape). `scripts/refactor/tools/split_check.py <base-rev> <old-file> <new-dir>` checks that a
split is move-only. `scripts/refactor/conformance.sh` is refactor-wave machinery: it needs a
stage id, a base rev and a `moves/<stage>.tsv` manifest (`scripts/refactor/tools/README.md`).

The error type is defined in `crates/oneiron-contracts/src/error/`. `mod.rs` holds `Error` with
its cross-cutting variants, the flat `ErrorKind` and `kind()`. Each domain's variants sit in their
own enum, one file per domain, reached from `Error` through an `#[error(transparent)]` `#[from]`
wrapper. `crates/oneiron/src/error.rs` re-exports them, so every `oneiron::error` path is
unchanged.

## Ratchets

`scripts/ratchet/check.sh` counts six metrics over non-test code against
`scripts/ratchet/baseline.json`: files at or over 800 lines, `#[allow(` attributes, print macros,
process-global mutable statics, the keyspace census and raw core writes. It skips `tests/`
directories, `tests.rs`, `*_tests.rs` and `tests_*.rs`. `scripts/ratchet/root-surface-check.sh`
pins the `oneiron` crate root to the names in `scripts/ratchet/root-surface.txt`. Both run in
`ratchet.yml` after a push to `main`; neither blocks a merge.

## Vendored and forked code

- `crates/heed` and `crates/paste` are vendored upstream crates outside the workspace, and
  `crates/*/vendor/**` holds vendored third-party snapshots. `PROVENANCE.md` in `crates/heed`,
  `crates/paste` and `crates/oneiron-docedit`, and `crates/oneiron-seal/vendor/README.md`, say
  where each came from.
- sudachi and formualizer (used from `oneiron-xlsx-formula` on) are git dependencies on the
  `oneiron-dev` forks, pinned by `rev`. A change to either is a fork commit plus a new `rev`
  (`docs/ops/forked-dependencies.md`).
- The `oneiron` crate declares no default features.

## CI

GitHub CI is paused: the repository variable `CI_PAUSED` is `true`, so every workflow except
`codemap.yml` skips its jobs. The files under `.github/workflows/` describe what runs when CI is
unpaused; they are not the merge bar. `codemap.yml` still runs, because it is the map's only
writer.

## Self-hosted runners

- Workflows target `[self-hosted, macos, arm64]` or `[self-hosted, linux, x64]`, never a host
  name. `uniffi-stub` targets the capability label `xcode`; add that label to a runner only
  after a full Xcode (not Command Line Tools alone) is installed there.
- Host contract: rustup resolving `rust-toolchain.toml` (1.96 with rustfmt and clippy),
  `cargo-nextest`, `rg`, git and `python3` ≥ 3.11; macOS runners also need poppler's `pdfsig`
  (`seal-oracle.yml`). Pinned CI-only tools (cargo-deny, typos-cli, nextest where a host lacks
  it) go under `~/ci/tools`; the job installs them on first use.
- Cache contract: each runner's `~/actions-runner/.env` exports `CARGO_TARGET_DIR=~/ci/target`
  (persistent and outside any checkout), a `PATH` with `~/.cargo/bin`, and on macOS the
  real-path `TMPDIR=/private/tmp/ci-t`. On macOS the target dir must stay outside `~/Desktop`,
  `~/Documents` and `~/Downloads`: the runner is a launchd agent without those privacy grants,
  and its first `open()` there blocks on a consent prompt nobody sees. Workflows never set
  `CARGO_TARGET_DIR` or `RUSTFLAGS` (`-Dwarnings` there would also reach the vendored
  `crates/heed`). `scripts/ci/cap-target-cache.sh` trims a target cache; `docs/ops/build-performance.md`
  covers safe maintenance. Never share a runner's target directory with other Cargo jobs.
- To add a runner, mint a registration token (repo Settings → Actions → Runners → New
  self-hosted runner) and pass it in the environment only, never in a file or a commit:
  `RUNNER_TOKEN=… scripts/ci/install-runner.sh <name> <labels> <os-arch> <cargo-target-dir> [tmpdir]`.
  Then run `./run.sh`, or `./svc.sh install && ./svc.sh start`, in `~/actions-runner`.
