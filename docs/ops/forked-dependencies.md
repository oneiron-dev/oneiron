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
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/parity`](https://github.com/oneiron-dev/formualizer/tree/oneiron/parity) | `3b59f96d89e09aaf090fecbc34d619010620cd82` | MIT OR Apache-2.0 |

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
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "3b59f96d89e09aaf090fecbc34d619010620cd82" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "3b59f96d89e09aaf090fecbc34d619010620cd82" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "3b59f96d89e09aaf090fecbc34d619010620cd82" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "3b59f96d89e09aaf090fecbc34d619010620cd82" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "3b59f96d89e09aaf090fecbc34d619010620cd82" }
```

Fork branch `oneiron/parity` (0.9.3-oneiron.33), over `362becff`:

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
- `7c6a6e6aeec0d6b190ce2a639a7344dd89d45a72` carries the same full caller token through NPV/IRR/XNPV/XIRR
  cashflow/date intake, date truncation and their individual NPV/derivative scans.
  Five private helpers return typed errors through every production caller; cancellation
  never becomes NUM, non-convergence, another solver attempt or a boxed success.
  All arithmetic, coercion/drop rules, existing caps, tolerances and iteration constants
  are unchanged. This is `0.9.3-oneiron.18`; other financial/coupon/allocation/work-budget
  work remains PART, with no new corpus, timing or hard-preemption claim.

- `ad1d661dfcf96cc5c17294eaad121ae8f22764a9` extends the same full caller token to MIRR intake/discount scans,
  CUMIPMT/CUMPRINC payment periods and FVSCHEDULE schedule traversal. The cumulative
  functions retain the existing `f64` summation and numeric helper expressions; only
  typed cancellation short-circuits them. FVSCHEDULE returns cancellation before its
  ordinary numeric-result boxing. NPV's separate hard 255-total-argument refusal is
  removed; its existing variadic schema, minimum arity, coercion and numeric order stay.
  This is `0.9.3-oneiron.19`; allocation internals and remaining financial/coupon/work-budget
  work are still PART. No new timer, work quota, default or corpus/timing claim.

- `ed24fe3bf7c39968cd6ff84421ca25f183e14cbe` carries the same full token into ACCRINT accrued-interest
  periods, PRICE/YIELD coupon-price sums, YIELD slope sums and DURATION/MDURATION
  cashflow sums. Real helper Results propagate typed cancellation before ordinary
  numeric-result boxing; numeric expressions, order, guesses, iteration counts and
  ordinary errors are unchanged. This is `0.9.3-oneiron.20`; calendar/schedule helpers,
  allocation internals and other financial/coupon paths still have unpolled work.
  No new clock, quota, cap, default or corpus/timing/hard-preemption claim.

- `5f6f9a59d929a483ef9755d10cc8bda0d8bcd318` carries the same full caller token into NETWORKDAYS,
  WORKDAY and both .INTL variants: holiday argument/range-slice/column/cell traversal,
  recursive array cells and each visited calendar day. The fallible holiday helpers
  propagate typed cancellation through all four real evaluators, never as a boxed
  successful result. Normal calendar arithmetic, coercion, weekend masks, sorting,
  deduplication and ordinary skipped range errors stay unchanged. This is
  `0.9.3-oneiron.21`; holiday sorting, allocation, other builtins and work-budget
  coverage remain PART. No new clock, quota, cap, default or corpus/timing claim.

- `9145d08f2301128f5585b88d3312c80ffcdb8c88` extends the same full caller token to DB, VDB and
  AMORDEGRC period calculations. Both VDB switch/no-switch paths and both real
  helper callers propagate typed cancellation before ordinary numeric-result
  boxing. Numeric formulas, period/fraction handling, switching, rounding and
  ordinary errors stay unchanged. This is `0.9.3-oneiron.22`; intake/allocation
  internals, remaining builtins and work-budget coverage stay PART. No new clock,
  quota, cap, default or corpus/timing claim.

- `758adf209ef58d1310d9fcbaa3d8f01c34b2dcc7` carries the same full caller token through ODDFPRICE,
  ODDFYIELD, ODDLPRICE and ODDLYIELD coupon-date walks, quasi-period counts and
  coupon valuations. ODDFYIELD propagates cancellation from each price and both
  finite-difference slope valuations, not only between solver iterations. Typed
  cancellation leaves all four evaluators before numeric-result boxing. Date
  rules, coupon arithmetic, iteration order and ordinary errors stay unchanged.
  This is `0.9.3-oneiron.23`; intake/allocation, remaining financial work and
  work-budget coverage stay PART. No new clock, quota, cap, default or
  corpus/timing claim.
  The twelve database D-functions also poll the same token through their four
  common evaluation paths: header lookup, criteria parsing, row matching and
  numeric aggregate passes. Typed cancellation returns before result boxing;
  criteria, ordinary errors and numeric order stay unchanged. Range/cell,
  individual-predicate and allocation work remain outside this coverage.

- `a832ec805006b8438e0cc078a52a19fb1a1638f5` carries the same full caller token through SUMPRODUCT
  argument, range-row, row, column and inner multiplication boundaries, and through
  the six conditional aggregates' shared criteria intake and fallible chunk,
  column, fallback-cell and matched-error scans. Typed cancellation leaves before
  scalar boxing; the separate range cancellation flag and all arithmetic,
  criteria, cache and ordinary-error order remain unchanged. This is
  `0.9.3-oneiron.24`. Cached masks, Arrow kernels, some mask/count and
  logical/scalar fallback loops, individual cell/predicate work, prior row
  buffering, allocation and native work-budget coverage stay PART. No new clock,
  quota, cap, default or corpus/timing claim.

- `ad1f5a38e46f3553369e4989d61762e3c98c7795` carries the same full caller token through GCD/LCM
  argument reduction and Euclidean recursion; COMBIN, PERMUT, FACTDOUBLE and
  COMBINA product loops; SUMSQ argument/range-cell traversal; and all three
  SUMX2MY2, SUMX2PY2 and SUMXMY2 shared input-collection and pairwise reduction
  paths. Typed cancellation leaves before result boxing. The pair reductions
  retain Rust's original sum path; numeric expressions, coercion, limits,
  rounding and evaluation order remain unchanged. This is `0.9.3-oneiron.25`.
  Range/input materialization, individual cell work, allocation, remaining
  numeric builtins and native work-budget coverage stay PART. No new clock,
  quota, cap, default or corpus/timing claim.

- `d7eb14f50817fe0119de19b5500081de2d7e37e9` carries the same full caller token through
  MULTINOMIAL argument/cell intake, value conversion, its original integer-sum
  path and denominator traversal; SERIESSUM coefficient intake and original
  power-series accumulation; and MIN/MAX argument, slice, column and error-lane
  cell traversal before unchanged Arrow kernels. Typed cancellation leaves
  before result boxing. Numeric order, ordinary errors, coercion, ignored values
  and result-format selection remain unchanged. The bounded factorial helper
  is unchanged. This is `0.9.3-oneiron.26`. Literal-array flattening, Arrow kernel
  internals, individual cell/conversion work, allocation, other builtins and
  native work-budget coverage stay PART. No new clock, quota, cap, default or
  corpus/timing claim.

- `02132dd595b0c4828e361ac937c2e8221541e4b9` adds same-token checkpoints to both conditional-aggregate
  mask-count paths, the COUNT-only logical-tail criteria loop and scalar-fallback
  criteria traversal. The existing full token is borrowed, not recaptured.
  Counts retain the same validity/value checks and integer cast; logical-tail
  matching preserves first-false short-circuiting and empty-criteria behavior.
  Typed cancellation leaves through the native error path before result boxing.
  Numeric expressions, ordinary errors, cache behavior and no-deadline behavior
  remain unchanged. This is `0.9.3-oneiron.27`. Cached-mask construction, Arrow
  kernels, individual cell/predicate work, row buffering, allocation, other
  builtins and native work-budget coverage stay PART. No new clock, quota, cap,
  default or corpus/timing claim.

- `250c262b2f49b5ea2a559ad41187cfc013369862` carries the existing borrowed caller token through
  the criteria get/build/memo path and polls cached-mask tag, chunk, row and
  null-fill traversal. The existing API now returns a typed cancellation error
  separately from unavailable optimization; ordinary mask/Arrow failures remain
  no-mask fallback. Memo insertion follows a completed build, so cancellation
  cannot become cached unavailability. Numeric, blank/text, predicate, cache-key
  and no-token behavior stay unchanged. Numeric null-fill still collects directly
  into the same BooleanArray, without an extra materialized value vector. This
  is `0.9.3-oneiron.28`. Arrow kernels, individual cell/predicate work, buffering,
  allocation, other builtins and native work-budget coverage stay PART. No new
  clock, quota, cap, default or corpus/timing claim.

- `88a8da6d1e24980355066bdfc33572a7abec3475` adds same-token checkpoints to COUNTA and
  COUNTBLANK argument, range-chunk, column and individual-cell traversal, so
  cancellation within a chunk returns through the native error path. Both
  functions poll before numeric-result boxing; COUNTBLANK also polls before its
  unvisited logical-tail count. Count arithmetic, blank/text rules, ordinary
  errors, reference handling, closed-workbook precedence and no-token behavior
  stay unchanged. This is `0.9.3-oneiron.29`; Arrow kernels, buffering,
  allocation, other builtins and native work-budget/hard-time coverage stay PART.
  No new clock, quota, cap, default or corpus/timing claim.

- `501767a79a30d774116c0c304ddd8655ea0bbe03` adds same-token checkpoints to MAP, BYROW and
  BYCOL argument, row, column and cell traversal, including MAP input bindings
  and BYCOL's column-copy rows. Their private bound-invocation helper returns
  native cancellation through all three callers, rather than boxing it as a
  cell error on the final invocation. Ordinary errors remain cell values;
  broadcasting, source-reference bindings, blank/nested-array rules, traversal
  order and normal no-token execution stay unchanged. This is
  `0.9.3-oneiron.30`; grid materialization internals, cloning, allocation, other
  LAMBDA helpers and native work-budget/hard-time coverage stay PART. No new
  clock, quota, cap, default or corpus/timing claim.

- `da15df45a1abb54fe815aaa3bdffb3c32fd39f79` threads one full caller cancellation token through
  XLOOKUP value/reference searches and XMATCH. Natural empty, reverse/fallback,
  approximate and sorted-verification scans poll it, as do XLOOKUP spill rows
  and columns. Both local optional-search helpers return typed cancellation
  through all four callers. Native cancellation from argument-range reads is
  not boxed as an ordinary error cell. First/last, wildcard, numeric/blank-tail,
  reference/fallback, ordinary errors and normal no-token behavior stay unchanged.
  This is `0.9.3-oneiron.31`; existing lookup-index and forward Arrow paths keep
  their optimizations and are polled around the call, not inside cache-building
  or kernel work. Individual cell operations, allocation, other lookup functions
  and native work-budget/hard-time coverage remain PART. No new clock, quota,
  cap, default or corpus/timing claim.

- `c83319ef63ddf50768ce00b07613e8d93620ad77` adds same-token natural-loop checkpoints to
  FILTER's include-flag and row/column selection and UNIQUE's line/cell intake,
  key construction, kept-line selection and transposition. Native cancellation
  from UNIQUE range and flag argument reads propagates before result boxing;
  ordinary and value-level error cells keep their prior behavior. UNIQUE,
  XLOOKUP and XMATCH distinguish a stored scalar cancellation-error value from
  evaluation cancellation through the argument's existing cached resolution,
  without evaluating it again. Selection and traversal order, case/numeric keys, duplicate counts, eager ordinary flag
  evaluation, fallback and normal no-token behavior stay unchanged. This is
  `0.9.3-oneiron.32`; individual cell operations, string conversion, hashing,
  cloning, allocation and native work-budget/hard-time coverage remain PART.
  No new clock, quota, cap, default or corpus/timing claim.

- `3b59f96d89e09aaf090fecbc34d619010620cd82` adds same-token row and cell checkpoints to
  RANDARRAY and SEQUENCE after their original argument, dimension and generated-
  cell checks, plus a checkpoint before final result boxing. SEQUENCE also polls
  before its outer allocation. RANDARRAY retains its single RNG-counter advance,
  row-major draws and numeric expressions; SEQUENCE retains its accumulation and
  numeric conversion order. Defaults, ordinary errors, existing size guards and
  no-token execution stay unchanged. This is `0.9.3-oneiron.33`; individual RNG
  and cell operations, coercion, allocation, boxing and native work-budget/hard-
  time coverage remain PART. No new clock, quota, cap, default or corpus/timing
  claim.

`deny.toml` allows `https://github.com/oneiron-dev/formualizer` in `allow-git`, and CC0-1.0
(owner ruling 2026-09-26) for `tiny-keccak` 2.0.2, which `formualizer-eval` pulls in at build
time through `arrow` → `ahash` → `const-random`. The engine stamps recalculated versions
`oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.33`.

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
