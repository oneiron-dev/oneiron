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

## Start a task

1. Read `CLAUDE.md`, this file, `WORKFLOW.md`, and `REVIEW.md`; then any closer instructions.
2. Confirm the branch and working tree with `git status --short --branch`. Use one external
   worktree per writer. `WORKFLOW.md` §1 covers target-directory ownership and host budgets.
3. Read `docs/CODEMAP.md`, then search only the owning `docs/codemap/<crate>.md` and source
   subtree. File paths in a crate map are relative to `crates/<crate>/`.
4. Use a scoped dev loop below. The coordinator owns the full gate after integration;
   a scoped pass is not a VERDICT.

## Exact commands

Discover the gate without compiling or running tests:

    scripts/verify.sh --help
    scripts/verify.sh --list

For generated navigation, `scripts/codemap/check.sh` checks without writing;
`python3 scripts/codemap/codemap.py` regenerates. See *Code map* for when to regenerate.

`--list` prints the live stage names and commands from the same definitions used by execution.
It does not run the code-map check or emit `VERIFY-OK`. Unknown arguments fail before any stage.

Dev-loop examples for the core crate; replace the crate or test filter with the changed scope:

    cargo fmt -p oneiron --check
    cargo clippy -p oneiron --all-targets --all-features -- -D warnings
    cargo nextest run -p oneiron --all-features -E 'test(gate::)'

To apply formatting, use `cargo fmt -p oneiron` (or the owning crate), then inspect the diff.
For the workspace use `cargo fmt --check`, never `--all`: that follows the path dependency into
the ONE-218 heed vendor. Sync-lane iteration uses `--features sync,test-hooks` instead of
`--all-features`; bare `sync` does not build the test targets. The plain featureless library
and test targets also have gates; see *Landmines*. The default nextest profile skips slow tests
and has no retries. A green dev loop is not a green gate.

Full scripted gate — run at VERDICT time, not after every edit:

    scripts/verify.sh

The script is the source of truth. Its **nine stages** check the code-map pin, fmt,
workspace clippy, featureless clippy, **server-production clippy** (`clippy-server`),
**rustdoc with warnings denied** (`rustdoc`), full workspace nextest (excluding
`oneiron-napi`), featureless library tests, and doctests (excluding `oneiron-bench`).
Server clippy deliberately has no `--all-targets`: it checks the engine's production
`sync` selection without test-only feature unification. Linux is the reference full-gate host;
the macOS caveats below still apply to this script.

`WORKFLOW.md` §3 lists the one additional policy command not wired into the script:
narrow sync/test-hooks full nextest. The strict rustdoc stage runs before runtime tests:

    env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

The child command clears inherited encoded flags, which otherwise override `RUSTDOCFLAGS`
even when empty. Other stages keep their inherited environment.
The distributed form (`scripts/verify-leg.sh`) still omits **five** commands (featureless clippy,
server-production clippy, featureless lib tests, rustdoc, and narrow sync full nextest).
Do not report a distributed-only pass as the full gate.

## nextest tiers

The dev-loop command runs the `default` profile, which skips the slow set pinned in
`.config/nextest.toml`: `vault_open_drop_cycles_survive_pthread_key_limit`, the two
`hnsw_recall_at_10_*` recall benches, and the whole `sync_convergence_props` suite in the
`it_sync` binary. `--profile full` runs them with `retries = 2`; `default` is `retries = 0`.
Run `--profile full` (or `scripts/verify.sh`) before claiming a VERDICT.

## macOS test host

Linux is the reference host. On macOS:

- Prefer a real `TMPDIR`, e.g. `mkdir -p /private/tmp/oneiron-t && export
  TMPDIR=/private/tmp/oneiron-t`. Secret lease/snapshot fixtures canonicalize their temp root
  before creating test paths, so macOS's `/var` alias does not mask their intentional symlink
  tests. Production secret-file policy still refuses symlink ancestors.
- `oneiron-napi` links its test binary on macOS through `-undefined dynamic_lookup`.
  Linux Rust tests enable napi-rs `dyn-symbols` through a Linux-only dev-dependency;
  normal production builds still resolve Node-API symbols from the importing Node host.
  Hostless Rust tests cover conversion/engine logic, not the JS ABI. Real Node-host tests
  remain necessary. `scripts/verify.sh` retains its existing `--exclude oneiron-napi`.
- 7 `oneiron-bench` `eval::tests::*` cases fail on macOS with `VaultRootPreflight …
  UnsupportedPlatform` and pass on Linux. Known; ticket pending.
- Full suite on an M4 Max (16 cores): ~8 min wall warm, ~9.5k tests across 41 binaries.

## Code map

Read `docs/CODEMAP.md` first (one row per crate, then each crate's top-level modules with layout,
size bucket and purpose), then search `docs/codemap/<crate>.md` for the owning module or type.
These maps cover `crates/` only; the workspace's macOS app lives separately at
`apps/macos/src-tauri/` and is linked from the overview. Both map levels
are generated deterministically by `scripts/codemap/`, along with the machine-readable
`docs/codemap/codemap.json`. They are pinned by `scripts/codemap/check.sh` (stage 0 of
`scripts/verify.sh`, CI `Checks`, and `ratchet.yml`): a stale map fails with `CODEMAP-STALE`
and prints the regenerate command. No watcher or installed hook is needed.

After adding, moving, or deleting a Rust file, run `python3 scripts/codemap/codemap.py` and
commit its output in the same change. Also regenerate when a file's leading `//!` purpose,
public items, or size bucket changes. The check is read-only; generation updates only changed
artifacts and removes orphan crate pages. `python3 scripts/codemap/codemap.py --sizes` prints
live line counts without changing the maps. The index is a source summary, not a call graph
or proof of which features compile.

For a narrow lookup, use `rg -n 'gate/evaluate|GateError' docs/codemap/oneiron.md`, then open the
matching path under `crates/oneiron/`. Read only matching rows or a narrow line range;
do not load large crate maps (especially `docs/codemap/oneiron.md`) whole.

The generator and verification CLI have dependency-free fixture tests (no Cargo builds):

    python3 -m unittest discover -s scripts/tests -p test_codemap.py -v
    python3 -m unittest discover -s scripts/tests -p test_verify.py -v

Size and dependency questions without `tokei` / `cargo-modules` (`rg` is present):

    rg --files -g '*.rs' crates/oneiron/src | xargs wc -l | sort -n | tail -20      # biggest files
    rg -l 'crate::pipeline\b' crates --type rust                                     # who names a module
    rg -oIN '\bcrate::[a-z_]+' crates/oneiron/src/pipeline | sort | uniq -c | sort -rn  # what a module names

## Tools and hosts

Arch Linux is the reference host; the Mac mini and MacBook also run development and macOS
checks. Read `rust-toolchain.toml` for the Rust pin and components. Gate tools are `cargo`
(with rustfmt, clippy, and nextest), `git`, `python3` ≥ 3.11, `bash`, and `rg`.

Check tools on the host you are using, not on the coordinator's host. `rtk` and `ast-grep` are
useful when available, but optional wrappers are not gate requirements. Do not assume `just`,
`tokei`, `cargo-modules`, or `cargo-public-api` are installed; the code map and `rg` work without
them. Do not install global hooks, change shared Cargo configuration, or start a second full
build to work around an occupied target directory.

## Landmines

- `oneiron-napi` hostless Rust tests are not JS ABI tests: Linux test builds use napi-rs
  dynamic symbols, and macOS uses `-undefined dynamic_lookup`. Production addons still need
  a real Node host. `scripts/verify.sh` retains its exclusion on all hosts; distributed nextest
  legs retain their Linux exclusion. Neither exclusion is changed by the test-link repair.
  macOS CI includes the crate too.
- Never run `scripts/review-pr.sh` — it doesn't exist. Deleted as dead/banned/zero-referenced;
  if you find a reference to it, that reference is stale.
- Pre-GA, no deployed vaults: don't request migrations or legacy decoders for storage-ABI
  versions that have never shipped. `REVIEW.md`.
- Don't review or touch `crates/*/vendor/**` (heed, paste, pkix-chain) unless the PR modifies it.
- sudachi and formualizer (from `oneiron-xlsx-formula` on) are git dependencies on the `oneiron-dev`
  forks pinned by `rev`, never vendored: a change to either is a fork commit plus a new `rev`
  (`docs/ops/forked-dependencies.md`).
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

- `ci.yml` — scoped CI (owner ruling 2026-09-26: test only what changed). `pull_request` (non-draft) and
  `push` to `main` run `scripts/ci/ci_scope.py` on the diff; `Checks` lints only the touched packages (plus the
  featureless build when `oneiron` changed), `Test` runs nextest for the touched packages and only the touched
  top-level `oneiron` modules (integration tests only when `crates/oneiron/tests` changed; no doctests), and
  `Test (featureless)` runs the shared-process `cargo test` lane for those modules. `cargo-deny` runs only
  when `Cargo.lock` or `deny.toml` changed, the tooling tests only when `scripts/` or `.github/` changed.
  The full gate (workspace clippy in three feature graphs, strict rustdoc, the whole nextest suite, doctests,
  both featureless process models) runs nightly at 03:00 JST (`schedule`), on `workflow_dispatch`, and when a
  build file changes (root `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, clippy/rustfmt/nextest
  config). `Test (macOS)` and the mutation audit are dispatch-only. `Checks`, `Test` and `Test (featureless)`
  are required contexts and always report; a PR stays a draft until its review passes, so it gets one CI run.
  `CI_PAUSED=true` pauses every job. `package` waits for a `v*` tag.
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
  the Wave host — both Linux test jobs and `package` can run on it). Workflows target
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
  flags let the runner caches share fingerprints with developer builds. Cargo does not evict stale
  artifacts itself. Cache maintenance is opt-in per workflow: the macOS Checks/Test jobs and
  binding/wire/seal workflows call `scripts/ci/cap-target-cache.sh`; neither Linux test job
  has a cap step. Do not assume every host has the same cache budget. Policy and safe maintenance
  commands live in `docs/ops/build-performance.md`; the script is the behavior source of truth.
  Never share a runner's target directory with concurrent developer jobs.
- Host contract: rustup with the 1.96 channel + rustfmt + clippy, `cargo-nextest`, `rg`, git,
  `python3` ≥ 3.11; macOS runners also poppler's `pdfsig` (seal-oracle). `uniffi-stub` needs a
  full Xcode, not Command Line Tools alone, so it targets the capability label `xcode`; add that
  label to a runner only after Xcode is installed there (today: both Macs). Pinned CI-only tools (cargo-deny 0.19.4, typos-cli 1.45.1, nextest if a host
  lacks it) go under `~/ci/tools`, installed by the job on first use and reused after.
- One runner runs one job at a time; a PR takes a `checks` slot and two Linux test slots.
  With enough Linux runners the test jobs run in parallel. Every job has `timeout-minutes`
  so a hang cannot hold the slot.
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
statics (baseline 2 / 98 / 91 / 33, `scripts/ratchet/baseline.json`) — and
`scripts/ratchet/root-surface-check.sh` pins the crate root at exactly the 701 names in
`scripts/ratchet/root-surface.txt`. A change may lower a
counter; raising one, or moving the pin, is a reviewed decision stated in the PR, never a
silent bump. Reason-carrying `#[allow(…)]` is the only legal form and it never hides a warning
that a private item became dead — delete the item instead.

Engine state belongs to a vault or to a thread, never to the process: a new `static` holding a
`Mutex`, `RwLock`, `Atomic`, `OnceLock`/`OnceCell`, `LazyLock`/`Lazy` or `Cell`/`RefCell` is a
stated decision in the PR, and a `thread_local!` or a field on the owning object is the default.
A `#[cfg(test)]` static is the worst case, not an exemption: `cargo test --lib` runs the suite as
parallel threads of ONE process, so a test-only global is shared by every sibling test — that is
what #922 and #923 were. Test seams belong on the vault's `#[cfg(test)] StoreCore.test_hooks`,
reached as `vault.test_hooks()`. `scripts/ratchet/process_globals.py --list` names every one it
counts, resolving same-file `type` aliases and named wrapper structs so a name cannot hide one.

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
