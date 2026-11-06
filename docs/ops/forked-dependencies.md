# Forked dependencies

Two third-party crates carry changes of ours as git forks. Neither is vendored: each is a git
dependency on a fork under `github.com/oneiron-dev`, pinned by a full commit `rev`, never by a
branch or a tag. lopdf, html5ever and dom_query carry changes of ours as vendored snapshots instead; see
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

- `html5ever` 0.39.0, `crates/oneiron/vendor/html5ever-0.39.0` (MIT OR Apache-2.0):
  an additive caller checkpoint in the existing tokenizer, plus a checked document driver
  that returns the first typed caller failure after dropping the partial DOM (FIX 9615).
  `dom_query` 0.28.0 and the engine use that same 0.39.0 snapshot; html5ever 0.38.0 remains
  at its original registry pin. Provenance, omitted non-production files and local changes
  are in `crates/oneiron/vendor/README.md`. An optional native sink-operation
  checkpoint propagates arena refusals before a failed node handle can be used,
  through reconstruction, adoption, foreign insertion and table-text draining.
  Native diagnostic recording uses that same typed error channel and reserves the
  actual error-vector backing before its original push. Successful messages/order
  are retained; owned diagnostic payloads remain unadmitted. A failed diagnostic
  push can leave private work in the current parser step until its next checkpoint.
  `CheckedParser::one_str` consumes borrowed UTF-8 through inline single-scalar
  tendrils, avoiding the whole-input heap copy before the first checkpoint. The
  caller-memory template path uses it; ordinary one-shot parsing is unchanged.
  Scalar mode coalesces adjacent table-text runs with the same split status
  instead of retaining one pending-vector entry per scalar. Full text is kept.
  Retained tokenizer/lookahead payloads remain separate allocations. An optional
  pre-input open-element reservation admits the actual private Vec before growth;
  its guard releases after the stack frees at parser completion, not after rendering.
  An optional temporary-buffer reservation replaces only that checked parser's
  spec buffer with a UTF-8 String. The caller admits full replacement capacity
  before growth and settles its actual capacity; bytes free before the owned
  callback releases admission. Emission copies to a native tendril and clears
  the retained scratch. That output tendril and DOM payload remain unadmitted.
  A separate checked tag-name String uses the same capacity reservation and
  parser-owned lifetime. Native tag-name bytes, case folding, end-tag matching
  and LocalName construction are unchanged; atom storage remains unadmitted.
  A separate checked attribute-name String also uses that reservation. Empty
  and duplicate-name checks, LocalName construction and namespace/value handling
  keep their original bytes and order; atoms remain unadmitted. Checked
  attribute-value tendrils have their own native reservation, described below.
  Other private parser vectors and transitive payloads remain unadmitted.

- `dom_query` 0.28.0, `crates/oneiron/vendor/dom-query-0.28.0` (MIT):
  a fallible native node-arena reservation API admits whole replacement storage
  before allocation and settles actual capacity. The checked HTML parser uses
  it for root, element/template, comment, doctype and newly created text nodes;
  existing adjacent text still coalesces without another arena slot. A caller's
  reservation stays with the Document through rendering and drop. Transitive
  node heap, parser/input buffers, attributes and diagnostic payloads are not
  admitted by this API. No node-count or content-size cap is added. The separately locked 0.27.0
  package stays on the registry. See the snapshot's `PROVENANCE.md`.

- `tendril` 0.5.1, `crates/oneiron/vendor/tendril-0.5.1` (MIT OR Apache-2.0):
  additive fallible native slice/reserve APIs admit the reported backing extent,
  including header and rounding, before payload use. The shared native header
  retains the caller reservation until after last-owner backing free. Fallible
  replacements keep old and new allocations admitted through the copy; ordinary
  APIs remain unadmitted and keep their copying behavior. The checked HTML comment
  producer reserves before each real UTF-8 append and moves that same native
  backing into DOM comment storage. Other tendril/DOM payloads, boxed guard
  metadata, allocator-private overhead and opaque intervals remain unadmitted.
  Package version, production dependencies and features are unchanged. See the
  snapshot's `PROVENANCE.md`; no content-size cap or new timer is added.
  The checked attribute-value producer also reserves before every character or
  slice append, including decoded character references. It retains the same
  native header through moves and shares; later allocating attribute copies,
  including shared-value atomic wrapping, have separate unadmitted backing.
  The doctype name and public/system identifiers also reserve their actual
  tendrils before each UTF-8 character append. Accepted tokens move that backing
  through the native tree builder and DOM sink; ignored tokens drop it. Diagnostic
  formatting and other native/private payloads remain outside this reservation.

## Licences and attribution

No source of either project is copied into this repository; the upstream licence texts ship in
the forks and in every Cargo checkout of them.

- sudachi.rs: Apache License 2.0, `LICENSE` at the repository root. Copyright (c) 2021 Works
  Applications Co., Ltd.
- formualizer: MIT OR Apache-2.0, `LICENSE-MIT` and `LICENSE-APACHE` at the repository root.
  Copyright (c) 2025-2026 Frank Colson and Formualizer contributors.
