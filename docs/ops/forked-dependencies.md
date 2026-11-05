# Forked dependencies

Two third-party crates carry changes of ours as git forks. Neither is vendored: each is a git
dependency on a fork under `github.com/oneiron-dev`, pinned by a full commit `rev`, never by a
branch or a tag. lopdf carries changes of ours as a vendored snapshot instead; see
[Vendored, modified snapshots](#vendored-modified-snapshots).
The fork branch holds upstream's release commit plus our commits, one per change, each message
saying what it changes and why. Upstream licence files and copyright notices stay untouched on
the fork. A third org fork, `oneiron-dev/iroh`, is pinned by rev in
`crates/oneiron-mesh-transport/Cargo.toml` for the opt-in mesh transport; this page does not
cover it.

| crate | upstream base | fork branch | pinned rev | licence |
|---|---|---|---|---|
| `sudachi` 0.6.11 | [WorksApplications/sudachi.rs](https://github.com/WorksApplications/sudachi.rs) tag `v0.6.11`, `90fd6068c80c2fc3b63e0dbab0e341475bad4d8f` | [`oneiron/v0.6.11`](https://github.com/oneiron-dev/sudachi.rs/tree/oneiron/v0.6.11) | `d8cba3609521805ebf35bfc2b71d8099a13befef` | Apache-2.0 |
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/parity`](https://github.com/oneiron-dev/formualizer/tree/oneiron/parity) | `e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f` | MIT OR Apache-2.0 |

## Changing a forked crate

1. Commit the change on the fork branch (or on a new `oneiron/<upstream version>` branch cut from
   the next upstream release), with a message that names the change and the reason.
2. Push the branch and move the `rev` in the manifest to the new branch head.
3. Update the table above. `deny.toml` allows each fork URL in `[sources] allow-git`;
   `unknown-git` stays `deny`.
4. The merge bar is `cargo check --workspace --all-features` on the head (see `AGENTS.md`).
   `cargo-deny --locked check` confirms the source allow-list.

## sudachi

`crates/oneiron-retrieval/Cargo.toml` (the multilingual analyzer's crate):

```toml
sudachi = { git = "https://github.com/oneiron-dev/sudachi.rs", rev = "d8cba3609521805ebf35bfc2b71d8099a13befef" }
```

Fork commits on `oneiron/v0.6.11`, over upstream `v0.6.11`:

- `baa525f0` names Android plugins `lib<name>.so`: `target_os = "android"` joins the
  Linux/FreeBSD branch of `make_system_specific_name` in `sudachi/src/plugin/loader.rs`. Without
  it the crate does not build for Android (E0425). The Android embedded workflow depends on it.
- `d8cba360` gives each bare `#[allow]` in `sudachi/src` and `sudachi/tests` a `reason` (24),
  removes two that no lint needed, and raises the workspace `rust-version` to 1.81, the release
  that stabilised lint reasons.

The fork keeps upstream's full workspace, including the CLI, fuzz and Python members; Cargo reads
it as a git dependency.

## formualizer

`crates/oneiron-xlsx-formula` links the five crates; nothing of formualizer is vendored. Its
manifest keeps the exact `=0.9.3` and `=3.1.2` requirements; the root `Cargo.toml` patches all
five to the fork by rev:

```toml
[patch.crates-io]
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f" }
```

Fork branch `oneiron/parity` (0.9.3-oneiron.17), over `362becff`:

- `adc4743f` "Owned evaluator patch 0.9.3-oneiron.1" (the `oneiron/0.9.3` branch head):
  `formualizer-eval/src/interpreter.rs` propagates a typed error on either side of `&`, in both
  the AST and the arena paths, before text coercion. Literal text `"#N/A"` stays text.
  `crates/oneiron-xlsx-formula/tests/workbook.rs`
  (`concatenation_preserves_error_values_for_iferror_in_retained_xlsx`) pins it.
- `adc4743f..f01d8eff`: the Excel parity work (ONE-2700). Each commit fixes one Excel behaviour
  in general, never a per-case answer, and was kept only when neither score dropped. Where Excel
  for Windows and Excel for Mac differ, the fork follows Windows (owner ruling); the goldens are
  recorded on Excel for Windows 16.0.20430, en-US region. A few commits are cherry-picked from
  upstream `main` with `git cherry-pick -x`. At `f01d8eff` the fork matches all 2,967
  SpreadsheetBench workbooks and all 811 pinned goldens. `git log adc4743f..f01d8eff` on the
  fork names each change and its reason; the Excel probe notes behind them are
  `ops/excel-*-probe-*.md` in the calc workspace.
- `7ada5f2f` makes the `TEXT` renderer public, `formualizer_eval::{format_number, format_text}`,
  and adds `formualizer_workbook::number_format_code`, the code en-US Excel for Windows reads for
  a style id with no definition. It changes no evaluation, so the version label stays
  `0.9.3-oneiron.13`. `oneiron-xlsx-formula`'s `cell_display_text` uses them for an anchored
  comment's snapshot of a sheet cell.
- `04a3fc07` adds a synchronous caller checkpoint to the existing cancellation token and
  polls that same token at interpreter AST and arena nodes, including reference evaluation
  (FIX 186). The adapter carries its actual `Resources` through this token. A caller-supplied
  deadline can stop inside a formula; no deadline remains untimed. Long builtins without
  cooperative polls remain open. Existing scheduling flags and core precision fallback stay
  unchanged. This patch is `0.9.3-oneiron.14`; it makes no new corpus or timing claim.
- `683e1314` polls the same caller token inside the matrix builtins MMULT, MDETERM,
  MINVERSE and MUNIT through the existing `FunctionContext` port (FIX 186). Arithmetic
  order, existing singular/error results and the MUNIT cap are unchanged. Input
  materialization, individual inner loops and other long builtins still have unpolled
  work. This patch is `0.9.3-oneiron.15`; it makes no new corpus or timing claim.
- `7edd615ce268ed8ffda9f4fcdb1fe226b235e03b` polls the same caller token between RATE, IRR and XIRR solver
  iterations, IRR bracket probes and initial Brent NPV phases (FIX 186). Cancellation
  exits as a typed error rather than falling through to another solver or non-convergence.
  Existing constants, guesses, arithmetic and convergence outcomes are unchanged.
  Cashflow intake and individual NPV scans remain unpolled. This patch is
  `0.9.3-oneiron.16`; it makes no new corpus or timing claim.
- `e7cbab17d0eb27f2b32b68c5f7ea2d9f63e47e3f` polls the same caller token between YIELD and ODDFYIELD Newton
  iterations and before their final valuations (FIX 186). Cancellation propagates before
  numeric-result boxing. Existing constants, arithmetic, convergence and the YIELD
  single-coupon path are unchanged; intake and individual coupon scans remain unpolled.
  This patch is `0.9.3-oneiron.17`; it makes no new corpus or timing claim.

`deny.toml` allows `https://github.com/oneiron-dev/formualizer` in `allow-git`, and CC0-1.0
(owner ruling 2026-09-26) for `tiny-keccak` 2.0.2, which `formualizer-eval` pulls in at build
time through `arrow` → `ahash` → `const-random`. The engine stamps recalculated versions
`oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.17`.

## Vendored, modified snapshots

A git fork keeps our changes in another repository, pinned by rev. A vendored snapshot keeps a
crates.io archive in this repository, beside the crate that needs it, and a `[patch.crates-io]`
path entry redirects the exact pin to it; its `Cargo.lock` entry has no `source` or `checksum`.
The `README.md` in the vendor directory records the archive's checksum, what was left out of it
and every local source change.

- `lopdf` 0.44.0, `crates/oneiron-seal/vendor/lopdf-0.44.0` (MIT): an additive `DecodeAdmission`
  hook, so a decode can ask for memory before it grows a buffer (FIX 7654). Provenance and the
  patch list are in `crates/oneiron-seal/vendor/README.md`. The `pkix-chain` 0.4.1 snapshot
  beside it is unmodified.

## Licences and attribution

No source of either project is copied into this repository; the upstream licence texts ship in
the forks and in every Cargo checkout of them.

- sudachi.rs: Apache License 2.0, `LICENSE` at the repository root. Copyright (c) 2021 Works
  Applications Co., Ltd.
- formualizer: MIT OR Apache-2.0, `LICENSE-MIT` and `LICENSE-APACHE` at the repository root.
  Copyright (c) 2025-2026 Frank Colson and Formualizer contributors.
