# Agent guidance

General doctrine (consumer boundary): `CLAUDE.md`. PR/verify workflow: `WORKFLOW.md`. Review
posture: `REVIEW.md`. Storage-ABI decision history — not agent guidance, read only for "why does
this format look like that": `MIGRATIONS.md`. HTTP API reference for `oneiron-server` (43KB, over
most agents' single-read truncation threshold — fetch by tier, don't load the whole file):
`oneiron.skills.md` — Tier-1 endpoint index at L51, Tier-2 endpoint detail at L298, Tier-3
schemas/error catalog at L801.

Oneiron is a general-purpose memory engine (Rust workspace; core crate `crates/oneiron`, server
`crates/oneiron-server`, bindings `crates/oneiron-napi`). Consumer-agnostic, public repo.

## Consumer boundary

Products are built on top of the engine, never inside it: no product names, prompt/persona text,
or product-branded modules in engine code. Full rule and its 4 consequences: `CLAUDE.md`.

## Exact commands

Dev-loop iteration — scoped, fast, default nextest profile, retries=0:

    cargo nextest run -p oneiron --all-features [-E 'test(<module>)']

Sync-lane iteration uses `--features sync` instead. A feature flag is required either way —
see the featureless-build landmine below.

Full verify gate — run at VERDICT time only, never for iteration:

    scripts/verify.sh

`scripts/verify.sh` is the single source of truth for the scripted gate and runs 4 stages: `cargo
fmt --all --check`, workspace clippy (`-D warnings`, all targets/features), `cargo nextest run
--workspace --all-features --profile full`, and `cargo test --doc --workspace --exclude
oneiron-bench --all-features`. Two more commands are current policy but NOT yet wired into the
script (`WORKFLOW.md` §3) — run them by hand until that gap closes: `RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps` and `cargo nextest run -p oneiron --features sync
--profile full`.

Distributed form: `LEG=fmt-clippy|tests:1/2|tests:2/2 scripts/verify-leg.sh` — same 4-stage
coverage split across legs; the same two-command gap applies.

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
- Featureless builds: the crate declares NO default features. The library compiles with no
  features and must stay that way (no gate lane checks it — breakage is invisible until someone
  runs plain `cargo build`). The TEST targets do NOT compile featureless (pre-existing
  `crate::sync` references in authority/facade/store test code), so every test command needs
  `--all-features` or `--features sync`.

## CI truth

- `ci.yml` — `workflow_dispatch` only, no auto-trigger; jobs: changes/fmt/clippy/test/package
  (`oneiron-server`)/deny (`cargo-deny`)/typos; `RUSTFLAGS=-Dwarnings`.
- `seal-oracle.yml` — `push` to `main` path-scoped to `crates/oneiron-seal/**` (plus the workflow
  file), and `workflow_dispatch`; never on PR, tags or schedule. The `v*`-tag trigger the A6
  header used to promise was removed by the 2026-08-24 amendment; header and `on:` block now
  agree.
- `ratchet.yml` — `push` to `main` only, no PR trigger and no schedule; installs ripgrep and runs
  `scripts/ratchet/check.sh`. Main-only on purpose: a stacked wave's middle commits can sit
  transiently above baseline for a state that never lands.
- `stickydisk-cleanup.yml` — twice-weekly cron sweep of sticky-disk cargo artifacts (cost
  control).
- `uniffi-stub.yml` — PR-triggered, path-scoped to `crates/oneiron-uniffi`; Swift-binding
  compile proof.

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
