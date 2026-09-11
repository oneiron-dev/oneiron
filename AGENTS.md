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
green gate. Sync-lane iteration uses `--features sync,test-hooks` instead (the bare `sync` feature does not build). A feature flag is no longer required: the
plain featureless build compiles its library *and* its test targets, and carries its own gates —
see the featureless-build entry under Landmines.

Full verify gate — run at VERDICT time only, never for iteration:

    scripts/verify.sh

`scripts/verify.sh` is the single source of truth for the scripted gate and runs the code-map
pin (`scripts/codemap/check.sh`) and then 6 stages: `cargo fmt --check` (members only — never `--all`, which would follow the path dependency into the
ONE-218 heed vendor), workspace clippy (`-D warnings`, all targets/features), featureless clippy
(`cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings`), `cargo nextest run
--workspace --exclude oneiron-napi --all-features --profile full` (napi cannot link its test binary
off a Node host — ONE-1997), `cargo test -p oneiron --lib --no-default-features`,
and `cargo test --doc --workspace --exclude oneiron-bench --all-features`. Two more commands are current policy but NOT yet wired into the
script (`WORKFLOW.md` §3) — run them by hand until that gap closes: `RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps` and `cargo nextest run -p oneiron --features sync,test-hooks
--profile full` (the bare `sync` feature does not build: `sync::selector::tests` calls a
`test-hooks`-gated helper).

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
- `oneiron-napi` links its test binary on macOS: its build script passes the linker
  `-undefined dynamic_lookup` for every link of the crate, so `cargo test -p oneiron-napi` runs
  there. On Linux it still does not link off a Node host (ONE-1997), so Linux workspace runs
  and `scripts/verify.sh` keep `--exclude oneiron-napi`.
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

- `oneiron-napi` cannot link its test binary on any host (the `napi_*` symbols come from a Node
  host at load time on Linux; macOS links it since the build script passes `-undefined
  dynamic_lookup`): Linux workspace nextest runs carry `--exclude oneiron-napi`, `scripts/verify.sh` included.
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

Every workflow runs on our own runners since 2026-09-08 (HYG-06b) — hosts, labels and the cache
contract are under *Self-hosted runners* below. All of them honour `CI_PAUSED`.

- `ci.yml` — `pull_request` (non-draft) + `push` to `main` + `workflow_dispatch`; `CI_PAUSED=true`
  repo variable pauses every job (wave affordance); drafts do not run. No `paths` filter
  (2026-09-11): every non-draft PR and every `main` push starts a run, because the `main` ruleset
  requires the `Checks` and `Test` contexts and a filtered trigger starts no run at all, so a
  docs-only PR reported neither and was blocked forever (#921 needed `--admin`). The `changes` job
  still detects a rust diff; it now gates STEPS, not the run. Jobs: `changes` (path detector) /
  `checks` (fmt, workspace + featureless clippy, typos, `cargo-deny` policy — one job, one runner
  slot) / `test` (macOS) /
  `test-linux` (Linux reference) / `package` (`oneiron-server`, Linux);
  no `RUSTFLAGS` (see *Self-hosted runners*). `checks` and `test` both run on every non-draft
  `pull_request`, on every `push` to `main` and on `workflow_dispatch`, so both required contexts
  always report; each gates its cargo steps on a rust diff (always on dispatch and tags, fail-open
  if the detector broke), so a docs-only run is a checkout plus the always-on typos and `cargo-deny`
  policy steps. `test` runs the macOS recipe
  (the 7 `oneiron-bench` `eval::tests::*` cases that fail on macOS
  filtered out by name — ONE-1996 — then the featureless lib tests and doctests); on `push` that
  job keeps the rust-diff gate at job level; `test-linux` runs the `--profile full` suite with
  only the napi exclusion, plus the same two stages, on `push` to `main` and `workflow_dispatch`
  only — never on PRs, Arch is the Wave host; `package` waits for a `v*` tag push that no
  trigger sends, so that gate is unreachable as written. The PR run enforces fmt, clippy and
  tests pre-merge; `scripts/verify.sh` on the branch stays the local gate.
- `seal-oracle.yml` — `push` to `main` path-scoped to `crates/oneiron-seal/**` (plus the workflow
  file), and `workflow_dispatch`; never on PR, tags or schedule. The `v*`-tag trigger the A6
  header used to promise was removed by the 2026-08-24 amendment; header and `on:` block now
  agree. Runs on the macOS runners without a container: uv 0.12.1, CPython 3.12 and pyhanko
  0.35.2 (`uv.lock`) are pinned in the job; `pdfsig` is the host's poppler.
- `ratchet.yml` — `push` to `main` only, no PR trigger and no schedule; runs
  `scripts/ratchet/check.sh` and `scripts/ratchet/root-surface-check.sh` with the host's
  ripgrep. It is a post-merge reporter:
  it cannot block a merge, it can only turn `main` red after one. Main-only on purpose: a
  stacked wave's middle commits can sit transiently above baseline for a state that never lands.
- `uniffi-stub.yml` — PR-triggered (non-draft), path-scoped to `crates/oneiron-uniffi` (plus the
  workflow file and `Cargo.lock`), and `workflow_dispatch`; Swift-binding compile proof on the
  macOS runners' Xcode toolchain.
- `wire-quickstart.yml` — PR (non-draft) to `main` and `push` to `main`, both path-scoped to
  `packages/oneiron`, `crates/oneiron{,-py,-remote,-napi,-server}`, the wire scripts
  (`scripts/wire-test-server.sh`, `scripts/tests/test_wire_*.py`) and the Cargo/toolchain
  files; plus `workflow_dispatch`. Installs the shipped SDK surface and proves four-verb parity.

## Self-hosted runners

- Hosts and labels: MacBook `self-hosted,macos,arm64,mbp` (16 cores, the first and strongest);
  the Mac mini joins with the same macOS labels; Arch box `self-hosted,linux,x64,arch` (16 cores,
  the Wave host — only `test-linux`, `package` and dispatch runs touch it). Workflows target
  `[self-hosted, macos, arm64]` or `[self-hosted, linux, x64]`, never a host name.
- Cache contract: each runner's `~/actions-runner/.env` exports `CARGO_TARGET_DIR=~/ci/target`
  (persistent, outside the checkout, so `clean: true` checkouts never wipe it; on macOS it must
  also stay outside `~/Desktop`, `~/Documents` and `~/Downloads` — the runner is a launchd agent
  without those TCC grants, and its first `open()` there blocks on a consent prompt nobody sees),
  `CARGO_INCREMENTAL=0`, a `PATH` with `~/.cargo/bin`, and on macOS the real-path
  `TMPDIR=/private/tmp/ci-t`. Workflows never set `CARGO_TARGET_DIR` and never add cache or
  toolchain actions: the toolchain is the host rustup resolving `rust-toolchain.toml`, and no
  workflow sets `RUSTFLAGS`: `-Dwarnings` there also reaches the vendored `crates/heed` path
  dependency, which cargo does not lint-cap (its 1.96 lifetime-elision warnings turned the first
  proving run red); warnings are gated by clippy's `-D warnings` as in `verify.sh`, and unset
  flags let the runner caches share fingerprints with developer builds. The cache only grows
  (cargo never evicts stale artifacts), so every cargo job ends with
  `scripts/ci/cap-target-cache.sh 20`: past 20 GB the dir is removed and the next job on that
  runner builds cold; it never touches a path that is not `…/ci/target`.
- Host contract: rustup with the 1.96 channel + rustfmt + clippy, `cargo-nextest`, `rg`, git,
  `python3` ≥ 3.11; macOS runners also poppler's `pdfsig` (seal-oracle). `uniffi-stub` needs a
  full Xcode, not Command Line Tools alone, so it targets the capability label `xcode`; add that
  label to a runner only after Xcode is installed there (today: both Macs). Pinned CI-only tools (cargo-deny 0.19.4, typos-cli 1.45.1, nextest if a host
  lacks it) go under `~/ci/tools`, installed by the job on first use and reused after.
- One runner runs one job at a time; a PR takes a `checks` slot and a `test` slot, so with one
  macOS runner they serialise. Every job has `timeout-minutes` so a hang cannot hold the slot.
- Waves: set the repository variable `CI_PAUSED=true` while a wave lands commits and every job
  in every workflow skips; flip it back when the wave closes.
- Adding a runner: mint a registration token (repo Settings → Actions → Runners → New
  self-hosted runner) and run it from the environment only, never from a file or a commit:
  `RUNNER_TOKEN=… scripts/ci/install-runner.sh <name> <labels> <os-arch> <cargo-target-dir> [tmpdir]`,
  e.g. `… install-runner.sh mac-mini self-hosted,macos,arm64,mini osx-arm64 ~/ci/target
  /private/tmp/ci-t`; then `./run.sh` or `./svc.sh install && ./svc.sh start` in `~/actions-runner`.
- Fork PRs from outside collaborators need approval before they run (repo setting, already set).

## Where new code goes

The monolith files are gone. `store`, `gate`, `task_verb`, `batch` and the fifteen 2026-08
wave-6 wells were the first to go; the 2026-09 hygiene pass (ONE-1992) split 106 more over-bar
modules the same way, so a directory module is now the normal shape for anything substantial.
Two files still sit over the bar and nothing is deferred any more — the `_attribution` block in
`scripts/ratchet/baseline.json` gives the structural reason for each one:
`voice_cascade/tts_spikes.rs` and `claim/lifecycle.rs` are reasoned indivisible. Do not use
either as precedent for a new large file. (`error.rs` was the third until ONE-2001 split it;
see *The error type* below.)

Don't look for a static old→new map; `docs/CODEMAP.md` and `docs/codemap/<crate>.md` are
regenerated deterministically and are the only current answer to "where does X live now".
(`docs/ops/w6-module-split-map.md` covers the wave-6 fifteen only and is history, not a map of
the tree today.) Don't grow an existing child file past the 800-line ratchet bar — a new concern
gets its own file under the owning module directory:

| New concern is about... | Goes in...                      |
|--------------------------|-----------------------------------|
| storage                  | its own file under `store/`       |
| gate evaluation           | its own file under `gate/`        |
| task-verb logic           | its own file under `task_verb/`   |
| batch application          | its own file under `batch/`       |

Never create `utils.rs` or `helpers.rs` — name a file for what it does.

## The error type

`crates/oneiron/src/error/` is a directory module (ONE-2001, `DESIGN-error-enum.md` option B).
`error/mod.rs` holds `pub enum Error` with the 21 cross-cutting bag variants, `pub enum
ErrorKind`, `kind()`, `is_retryable`, the two manual `From` impls and the two one-hop `From`
delegations. The other 203 variants live in twelve per-domain enums, one file each —
`artifact`, `claim`, `code`, `gate`, `maintenance`, `off_record`, `record`, `registry`, `relay`,
`secret`, `store`, `sync` — reached from the root through an `#[error(transparent)]` `#[from]`
wrapper, so Display and `source()` are still the leaf's.

A new variant goes in the domain enum that owns the door it refuses, constructed as
`Error::Domain(DomainError::Variant ..)`, with its `ErrorKind` twin and a `kind()` arm in that
domain's `kind()`. It goes in the bag only when it is genuinely cross-cutting (storage, io,
arithmetic, invariant). `ErrorKind` is the stable persisted surface — its Debug names are
written to disk as quarantine reason codes and are the server's mapping key — so it stays flat
and is never renamed or reordered. Each domain enum is `pub` and re-exported from `error`, never
from the crate root: the root-surface pin does not move. `kind()` and the moved
constructors are `pub(crate)`, with public forwarders on `Error`.

`scripts/ratchet/check.sh` ratchets four counters over non-test code — files at or over 800
lines, `#[allow(` attributes, `println!`/`eprintln!`/`dbg!` calls, and process-global mutable
statics (baseline 2 / 98 / 91 / 38, `scripts/ratchet/baseline.json`) — and
`scripts/ratchet/root-surface-check.sh` pins the crate root at exactly the 701 names in
`scripts/ratchet/root-surface.txt`. A change may lower a
counter; raising one, or moving the pin, is a reviewed decision stated in the PR, never a
silent bump. Reason-carrying `#[allow(…)]` is the only legal form and it never hides a warning
that a private item became dead — delete the item instead.

Engine state belongs to a vault or to a thread, never to the process: a new `static` holding a
`Mutex`, `RwLock`, `Atomic`, `OnceLock`/`OnceCell`, `LazyLock`/`Lazy` or `Cell`/`RefCell` is a
stated decision in the PR, and a `thread_local!` or a field on the owning object is the default.
`scripts/ratchet/process_globals.py --list` names every one it counts.

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

- Reach: an item is declared at the narrowest visibility its callers need — private when
  only its own file names it, `pub(super)` when only its parent directory does, `pub(in
  crate::x)` when an ancestor directory does, `pub(crate)` only when another top-level directory
  names it, and `pub` only through the `lib.rs` root surface. The 2026-09-10 census (#919)
  narrowed 749 engine items this way. The compiler is the arbiter: when it names a caller outside
  the boundary, widen to exactly that caller's scope and no further. Re-export seams follow the
  same rule — a `pub(crate) use` that nothing outside the directory names is a plain `use`.

## Test style

A test asserts what a caller can observe: the returned value, the stored row, the typed error
variant, the wire body. It does not assert a log line, an internal counter, a private field, the
wording of a message, or a source scan of the file under test. When the outcome has no observable
door, add the door in the same change — a typed `Error` variant, a reason code, or an accessor on
the type that owns the fact (the 2026-09-10 pass rewrote 940 assertions to this shape and added 59
such doors) — never widen a private item so a test can reach it. Shared fixtures live in the
owning module's `tests/support.rs`; a helper one file uses stays in that file, and a helper with
no remaining caller is deleted, not kept. Test files (`tests/**`, `tests.rs`, `*_tests.rs`) sit
outside the giant-file ratchet and the visibility census, so length is not the concern there;
duplication is — a test that only re-proves what a sibling proves is deleted.

## Closest wins

A crate-local `CLAUDE.md` or `AGENTS.md`, if one exists, overrides this file for that crate's
scope. None exist today (checked 2026-08-19); this file is authoritative everywhere until one
appears.

## Review priority

- Invariants missing at any door (admission / replay / rematerialization / export / batch).
- Validator-vs-writer-promise gaps.
- Hostile-peer-reachable paths, fail-open errors.
- Regressions in code introduced by earlier review fixes.
