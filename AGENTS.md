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

Sync-lane iteration uses `--features sync` instead. A feature flag is no longer required: the
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

Code map — read `docs/CODEMAP.md` first (one row per crate, then each crate's top-level modules
with layout, size bucket and purpose), then drill into `docs/codemap/<crate>.md` for the per-file
table. Both are generated: after adding, moving, or deleting a Rust file run `python3
scripts/codemap/codemap.py` and commit the result; `scripts/codemap/check.sh` (`--check`) is the
first verify stage and fails on a stale map. `python3 scripts/codemap/codemap.py --sizes` prints
the live line counts.

## Tool truth (verified on this box)

Present: `rtk` v0.44, `ast-grep` v0.44, `cargo-nextest` 0.9. NOT installed — don't assume them:
`just`, `tokei`, `cargo-modules`, `cargo-public-api`.

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

## Closest wins

A crate-local `CLAUDE.md` or `AGENTS.md`, if one exists, overrides this file for that crate's
scope. None exist today (checked 2026-08-19); this file is authoritative everywhere until one
appears.

## Review priority

- Invariants missing at any door (admission / replay / rematerialization / export / batch).
- Validator-vs-writer-promise gaps.
- Hostile-peer-reachable paths, fail-open errors.
- Regressions in code introduced by earlier review fixes.
