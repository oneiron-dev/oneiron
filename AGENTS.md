# Agent guidance

General doctrine (consumer boundary): `CLAUDE.md`. PR/verify workflow: `WORKFLOW.md`. Review
posture: `REVIEW.md`. Storage-ABI decision history — not agent guidance, read only for "why does
this format look like that": `MIGRATIONS.md`. HTTP API reference for `oneiron-server` (~55KB, over
most agents' single-read truncation threshold — fetch by tier, don't load the whole file):
`oneiron.skills.md` — locate a tier by its heading, not by line number: `## Tier-1: Endpoint
Activation Index`, `## Tier-2: Endpoint Details`, `## Tier-3: Schemas And Error Catalog`.

Oneiron is a general-purpose memory engine (Rust workspace; core crate `crates/oneiron`, server
`crates/oneiron-server`, bindings `crates/oneiron-napi`). Consumer-agnostic, public repo.

## Consumer boundary

Products are built on top of the engine, never inside it: no product names, prompt/persona text,
or product-branded modules in engine code. Full rule and its 4 consequences: `CLAUDE.md`.

## Exact commands

Dev-loop iteration — scoped, fast, default nextest profile, retries=0:

    cargo nextest run -p oneiron --all-features [-E 'test(<module>)']

The `default` profile skips a slow set — see *nextest tiers* below; a green dev loop is not a
green gate. Sync-lane iteration uses `--features sync` instead. A feature flag is no longer required: the
plain featureless build compiles its library *and* its test targets, and carries its own gates —
see the featureless-build entry under Landmines.

Full verify gate — run at VERDICT time only, never for iteration:

    scripts/verify.sh

`scripts/verify.sh` is the single source of truth for the scripted gate and runs the code-map
pin (`scripts/codemap/check.sh`) and then 6 stages: `cargo fmt --check` (members only — never `--all`, which would follow the path dependency into the
ONE-218 heed vendor), workspace clippy (`-D warnings`, all targets/features), featureless clippy
(`cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings`), `cargo nextest run
--workspace --all-features --profile full`, `cargo test -p oneiron --lib --no-default-features`,
and `cargo test --doc --workspace --exclude oneiron-bench --all-features`. Two more commands are current policy but NOT yet wired into the
script (`WORKFLOW.md` §3) — run them by hand until that gap closes: `RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps` and `cargo nextest run -p oneiron --features sync
--profile full`.

Distributed form: `LEG=fmt-clippy|tests:1/2|tests:2/2 scripts/verify-leg.sh`. Leg coverage is
narrower than the script: `fmt-clippy` runs the code-map pin, fmt and workspace clippy;
`tests:1/2` runs nextest partition `hash:1/2` plus doctests; `tests:2/2` runs partition
`hash:2/2`. No leg runs the two featureless stages, so a distributed run has a four-command
gap: featureless clippy, featureless lib tests, `cargo doc`, and the sync-profile nextest run.

## nextest tiers

The dev-loop command runs the `default` profile, which skips the slow set pinned in
`.config/nextest.toml`: `vault_open_drop_cycles_survive_pthread_key_limit`, the two
`hnsw_recall_at_10_*` recall benches, and the whole `sync_convergence_props` suite in the
`it_sync` binary. `--profile full` runs them with `retries = 2`; `default` is `retries = 0`.
Run `--profile full` (or `scripts/verify.sh`) before claiming a VERDICT.

## macOS test host

Linux is the reference host. On macOS:

- `TMPDIR` must be a real path, e.g. `mkdir -p /private/tmp/oneiron-t && export
  TMPDIR=/private/tmp/oneiron-t`. The default `/var/folders/…` is a symlink and 10
  `secret_lease::tests` refuse it.
- `oneiron-napi` cannot link its test binary on macOS: add `--exclude oneiron-napi` to
  workspace nextest runs.
- 7 `oneiron-bench` `eval::tests::*` cases fail on macOS with `VaultRootPreflight …
  UnsupportedPlatform` and pass on Linux. Known; ticket pending.
- Full suite on an M4 Max (16 cores): ~8 min wall warm, ~9.5k tests across 41 binaries.

## Code map

Read `docs/CODEMAP.md` first (one row per crate, then each crate's top-level modules with layout,
size bucket and purpose), then drill into `docs/codemap/<crate>.md` for the per-file table. Both
are generated deterministically by `scripts/codemap/` and pinned by `scripts/codemap/check.sh`
(stage 0 of `scripts/verify.sh`, also run by `ratchet.yml`): a stale map fails with
`CODEMAP-STALE` and prints the regenerate command. After adding, moving, or deleting a Rust file
run `python3 scripts/codemap/codemap.py` and commit the output in the same change. `python3
scripts/codemap/codemap.py --sizes` prints the live line counts.

Size and dependency questions without `tokei` / `cargo-modules` (`rg` is present):

    rg --files -g '*.rs' crates/oneiron/src | xargs wc -l | sort -n | tail -20      # biggest files
    rg -l 'crate::pipeline\b' crates --type rust                                     # who names a module
    rg -oIN '\bcrate::[a-z_]+' crates/oneiron/src/pipeline | sort | uniq -c | sort -rn  # what a module names

## Tool truth (verified on this box)

Present: `rtk` v0.44, `ast-grep` v0.44, `cargo-nextest` 0.9, `rg` (ripgrep 15). NOT installed —
don't assume them: `just`, `tokei`, `cargo-modules`, `cargo-public-api`.

## Landmines

- Never run `scripts/review-pr.sh` — it doesn't exist. Deleted as dead/banned/zero-referenced;
  if you find a reference to it, that reference is stale.
- Pre-GA, no deployed vaults: don't request migrations or legacy decoders for storage-ABI
  versions that have never shipped. `REVIEW.md`.
- Don't review or touch `crates/*/vendor/**` unless the PR modifies it.
- `scripts/refactor/conformance.sh` is GPS refactor-wave machinery — it needs a stage-id, a
  base-rev, and a pre-registered `moves/<stage>.tsv` manifest. Not general-purpose tooling; see
  `scripts/refactor/README.md`.
- No force-push, no interactive rebase, no local merge into `main`, no skipped hooks. `WORKFLOW.md`
  §5.
- Doc/comment/naming findings are informational, never blocking. `REVIEW.md`.
- Featureless builds: the crate declares NO default features. The library **and its test
  targets** compile with no features, and must stay that way. These are Wave-6 acceptance gates;
  `scripts/verify.sh` runs them as its `clippy-featureless` and `test-featureless` stages, in
  addition to (never instead of) the all-features stages:

      cargo test -p oneiron --lib --no-default-features
      cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings

  Coverage is feature-independent on purpose: a test whose law is base-mode must RUN featureless.
  When a featureless build reports an unresolved or unused name, gate the *import* to match its
  consumers (`#[cfg(feature = "sync")]` / `#[cfg(all(feature = "sync", test))]`), or seed a local
  fixture constant — never cfg-disable the test itself, which would silently delete base-mode
  coverage. `BatchBuilder::put_replicated` is the fixture door — no production caller, gated to
  exactly its consumers (`test`, plus `sync`+`test-hooks` for the cross-crate seam
  `sync::selector::put_selector_test_federation_grant`); `TxnBatchBuilder::put_replicated`
  remains the sync production replay door, and OF-060 F1 pins `put_replicated` out of non-sync
  production sources. Widening that gate reintroduces a `-D dead-code` failure under plain
  `--features sync`, which is its own gate lane.

## CI truth

- `ci.yml` — `workflow_dispatch` only, no auto-trigger; jobs: changes/fmt/clippy/test/package
  (`oneiron-server`)/deny (`cargo-deny`)/typos; `RUSTFLAGS="-Dwarnings -Cdebuginfo=0"`. Under
  the dispatch-only trigger only `changes` (path detector) and `deny` (gated on
  `workflow_dispatch`) execute: fmt/clippy/typos are gated on `pull_request`, `test` on
  `pull_request` or `push`, and `package` waits for a `v*` tag push that can never trigger the
  workflow, so that gate is unreachable as written. Nothing pre-merge enforces fmt, clippy or
  tests; `scripts/verify.sh` on the branch is the gate.
- `seal-oracle.yml` — `push` to `main` path-scoped to `crates/oneiron-seal/**` (plus the workflow
  file), and `workflow_dispatch`; never on PR, tags or schedule. The `v*`-tag trigger the A6
  header used to promise was removed by the 2026-08-24 amendment; header and `on:` block now
  agree.
- `ratchet.yml` — `push` to `main` only, no PR trigger and no schedule; installs ripgrep and runs
  `scripts/ratchet/check.sh`, `scripts/codemap/check.sh` and
  `scripts/ratchet/root-surface-check.sh`. It is a post-merge reporter: it cannot block a merge,
  it can only turn `main` red after one. Main-only on purpose: a stacked wave's middle commits
  can sit transiently above baseline for a state that never lands.
- `stickydisk-cleanup.yml` — twice-weekly cron sweep of sticky-disk cargo artifacts (cost
  control).
- `uniffi-stub.yml` — PR-triggered, path-scoped to `crates/oneiron-uniffi` (plus the workflow
  file and `Cargo.lock`), and `workflow_dispatch`; Swift-binding compile proof.
- `wire-quickstart.yml` — PR to `main` and `push` to `main`, both path-scoped to
  `packages/oneiron`, `crates/oneiron{,-py,-remote,-napi,-server}`, the wire scripts
  (`scripts/wire-test-server.sh`, `scripts/tests/test_wire_*.py`) and the Cargo/toolchain
  files; plus `workflow_dispatch`. Installs the shipped SDK surface and proves four-verb parity.

## Where new code goes

The former monolith files are gone: `store`, `gate`, `task_verb`, `batch`, and the fifteen
2026-08 wave-6 wells (`session_overlay`, `repo_mutation`, `dreamer_consolidation`,
`connector_key`, `code_run`, `consent`, `receipt`, `deletion`, `outbound`,
`booking/anti_abuse`, `saved_query`, `dreamer_runner`, `pipeline`, `skill_hub`) are all
directory modules now (old→new map: `docs/ops/w6-module-split-map.md`). Don't grow an existing
child file past the 800-line ratchet bar — a new concern gets its own file under the owning
module directory:

| New concern is about... | Goes in...                      |
|--------------------------|-----------------------------------|
| storage                  | its own file under `store/`       |
| gate evaluation           | its own file under `gate/`        |
| task-verb logic           | its own file under `task_verb/`   |
| batch application          | its own file under `batch/`       |

Never create `utils.rs` or `helpers.rs` — name a file for what it does.

## Module style

Two file shapes are legal; never convert one to the other for style alone.

- Under the giant-file bar (`scripts/ratchet/check.sh` fails a non-test file at or over 800
  lines; `tests/` directories, `tests.rs` and `*_tests.rs` are excluded from the count): a module
  stays `foo.rs` with its tests in `foo/tests.rs`.
- Over the bar: the module becomes a directory module `foo/mod.rs` + children. Seam shape is
  `crates/oneiron/src/pipeline/mod.rs` — `mod` declarations, a `pub use` seam that keeps every
  `crate::foo::*` path unchanged, and a `#[cfg(test)] use self::{…}` shim so `tests.rs` resolves
  as before. Children are `pub(super)`, never widened; the seam re-exports what the crate needs.
- A split is move-only. Check it with
  `scripts/refactor/tools/split_check.py <base-rev> <old-file> <new-dir>` (fails closed with
  `SPLIT-CHECK-ERROR`). The manifest-driven `scripts/refactor/conformance.sh` is not needed for
  the common case.

## Closest wins

A crate-local `CLAUDE.md` or `AGENTS.md`, if one exists, overrides this file for that crate's
scope. None exist today (checked 2026-08-19); this file is authoritative everywhere until one
appears.

## Review priority

- Invariants missing at any door (admission / replay / rematerialization / export / batch).
- Validator-vs-writer-promise gaps.
- Hostile-peer-reachable paths, fail-open errors.
- Regressions in code introduced by earlier review fixes.
