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
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/parity`](https://github.com/oneiron-dev/formualizer/tree/oneiron/parity) | `9c0cf828e4bf016c0a17556b8d30f12924787fad` | MIT OR Apache-2.0 |

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
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "9c0cf828e4bf016c0a17556b8d30f12924787fad" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "9c0cf828e4bf016c0a17556b8d30f12924787fad" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "9c0cf828e4bf016c0a17556b8d30f12924787fad" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "9c0cf828e4bf016c0a17556b8d30f12924787fad" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "9c0cf828e4bf016c0a17556b8d30f12924787fad" }
```

Fork branch `oneiron/parity` (0.9.3-oneiron.99), over `362becff`:

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

- `97b16c27a93b6b25c83446743c6a5d55dd250a1c` adds full-token checkpoints to TRANSPOSE,
  TAKE and DROP after their original shape and selection checks. They poll
  before output allocation, at row and column boundaries and before result
  boxing. Their array-read guards distinguish native cancellation from cached
  stored scalar cancellation errors without evaluating the argument again.
  Transpose orientation, signed selection windows, omitted columns, empty
  results, ordinary errors and regular no-token execution stay unchanged. This
  is `0.9.3-oneiron.34`; individual cell reads, range materialization, cloning,
  allocation, boxing and native work-budget/hard-time coverage remain PART.
  No new clock, quota, cap, default or corpus/timing claim.

- `b990e18f6905e4bf5c10d900b37f1afb0864f1fc` adds full-token checkpoints to HSTACK and VSTACK before
  argument intake, at output collection boundaries and before final result
  boxing. HSTACK polls each copied cell; VSTACK polls each row callback and
  propagates its typed cancellation error. Native range-argument cancellation
  exits before scalar fallback, while stored scalar error values keep that
  fallback. Empty inputs, shape checks, concatenation order, original buffers
  and regular no-token execution stay unchanged. This is `0.9.3-oneiron.35`;
  VSTACK row buffering/cloning, range resolution, individual cell operations,
  allocation, boxing and native work-budget/hard-time coverage remain PART.
  No new clock, quota, cap, default or corpus/timing claim.

- `c22a8bdf8cef9df9456511c7be58da30f2945d2f` adds full-token checkpoints to CHOOSECOLS and
  CHOOSEROWS after original source/shape checks, through index intake, before
  output allocation, through the selected row and cell walks and before result
  boxing. Existing native source/index error propagation and index error cells
  stay unchanged, as do signed indices, truncation, duplicate selection, output
  order, capacities and regular no-token execution. This is `0.9.3-oneiron.36`;
  source resolution, cell operations, cloning, allocation, boxing and native
  work-budget/hard-time coverage remain PART. No new clock, quota, cap, default
  or corpus/timing claim.

- `d793282347f1db607e742bbb17158b2a39201793` adds same-full-token materialization, row/cell,
  flattening/wrapping and pre-boxing checkpoints to TOCOL, TOROW, EXPAND,
  WRAPROWS and WRAPCOLS. A private error-origin carrier lets only native
  cancellation exit as a typed error; stored cancellation errors and every
  other error keep their original result path. Ignore/scan/ragged-fill order,
  omitted sizes, truncation, dimension checks, padding, original buffers and
  regular no-token execution stay unchanged. This is `0.9.3-oneiron.37`; row
  buffering, width scans, individual cell/coercion/clone work, allocation,
  boxing and native work-budget/hard-time coverage remain PART. No new clock,
  quota, cap, default or corpus/timing claim.

- `47aa495d9690dbc9b25ece786922bba264eeb699` adds one-full-token row/cell and pre-boxing
  checkpoints to REDUCE, SCAN and MAKEARRAY after their original input checks.
  A private invocation helper keeps native callable cancellation typed while
  retaining stored error values and ordinary-error boxing. Uncancelled
  invocation order/count, accumulators, output shapes, numeric expressions and
  buffers stay unchanged; the existing aggregate invocation and ordering paths
  are byte-identical and remain outside this slice. This is `0.9.3-oneiron.38`;
  input materialization, individual invocation/read/clone work, allocation,
  boxing and native work-budget/hard-time coverage remain PART. No new clock,
  quota, cap, default or corpus/timing claim.

- `6bd3acec29ad7a704433250b803ee2b07b0c2f17` adds one-full-token criterion, row/cell,
  ordering, reconstruction and pre-boxing checkpoints to SORT and SORTBY.
  Token-bearing calls use a private fallible stable index merge with two
  additional index vectors, followed by an inverse-permutation swap. Each
  merge/copy and permutation step polls the same token; ordinary no-token calls
  keep the original standard stable sort. The literal comparator, per-comparison
  date-system lookup, selected axes, criteria priority, stored errors and
  ordinary-error boxing remain unchanged; only native argument cancellation
  propagates as a typed error. Aggregate/volatile-callable ordering is untouched.
  This is `0.9.3-oneiron.39`; index capacity and native allocation are not a
  proved heap floor. Individual comparisons/reads/clones, allocation, boxing
  and native work-budget/hard-time coverage remain PART. No new clock, quota,
  cap, default or corpus/timing claim.

- `efe988dff9fa5be398039acce8a4ce983267806f` adds one captured full-token entry and natural key/member,
  non-sort aggregate and output checkpoints to GROUPBY and PIVOTBY. A private
  origin carrier keeps older value/intake errors boxed while direct checkpoints
  and raw non-sort callable cancellation leave typed. Stored cancellation values
  and ordinary callable-error boxing keep their old paths. The original
  Aggregate::apply, column builder, both standard sorts and lazy PIVOTBY totals
  remain byte-identical; uncancelled invocation count/order and ordinary numeric,
  selection and shape rules are unchanged. This is `0.9.3-oneiron.40`.
  Result-collection and line-assembly allocator specialization/capacities are not
  asserted equal. Sort-path callable propagation, input/distinct-key/axis/column
  construction, individual reads/clones, allocation, boxing and native
  work-budget/hard-time coverage remain PART. No new clock, quota, cap, default
  or corpus/timing claim.

- `2723c85d38f2461fdeaedbdf7fd234ab806ae79d` passes the same borrowed full token through the
  non-sort GROUPBY/PIVOTBY column builder, with initial, per-row and pre-boxing
  checkpoints. The three actual aggregate consumers pass their existing token;
  one/two argument materialization stays left-to-right before one invocation.
  Stored cell errors stay values; only direct checkpoints use the existing
  native channel. Original sort-only column/apply paths, both standard sorts
  and lazy PIVOTBY totals stay byte-identical. This is `0.9.3-oneiron.41`.
  Result-collection capacities/specialization and individual cell/read/clone/
  allocator spans are not a heap floor; sort-path/input/native-work-budget and
  hard-time coverage remain PART. No new clock, quota, cap, default or timing.

- `057d05a6b6b01358f487944da0f9b0705ce24be2` keeps native cancellation typed through the
  GROUPBY/PIVOTBY grid, optional-value and callable argument intake. It reuses
  the private Value/Native carrier: only raw native Cancelled enters Native;
  stored cells, coercion failures and every ordinary error remain Value. The
  existing cached scalar-error predicate runs after the same range conversion,
  without another evaluation or cache clone. Omitted values, argument/validation
  order, numeric/header/filter/relative rules, old column/apply paths and both
  lazy volatile sorts are unchanged. This is `0.9.3-oneiron.42`.
  Range-row iteration and individual materialization/read/clone/allocation spans,
  sort-path callable propagation, native work-budget and hard-time coverage
  remain PART. No new clock, quota, cap, default or corpus/timing claim.

- `8880b5104a0bd80672e42ae7175363b5eb5c7937` polls the same borrowed full token during
  GROUPBY/PIVOTBY grid materialization. All five intake calls retain the original
  range conversion and buffered row reader. A checkpoint before collecting rows
  and before each existing row clone/push returns native Cancelled; stored
  cancellation cells remain data and ordinary errors remain boxed. Uncancelled
  argument/validation order, row reads/clones, numeric rules, both sorts and old
  aggregation paths stay unchanged. This is `0.9.3-oneiron.43`.
  Wide-row reads, individual clone/allocation spans, volatile sort-path callable
  propagation, native work-budget and hard-time coverage remain PART. No new
  clock, quota, cap, default or corpus/timing claim.

- `873b02959986de0a61c443018b75c59ed022576c` carries the same borrowed full token through
  GROUPBY/PIVOTBY filter-row selection, distinct-key identity, non-comparator
  parent position/rank construction, axis labels/subtotal membership and gathered
  row membership, plus PIVOTBY membership intersections. New checkpoint errors
  use the native channel; stored filter errors and ordinary validation errors
  remain values. Uncancelled first-appearance order, numeric/depth/header rules,
  subtotal placement and callable count/order stay unchanged. Both standard key
  sort bodies (including lazy aggregate callbacks), the original parent-prefix
  scan and the pure row-index sort body are unchanged. This is `0.9.3-oneiron.44`.
  Sorts, individual prefix/key/string scans, filter flattening, atomic clones
  and allocation retain unpolled spans. Result collection/manual membership
  assembly need not preserve capacities or specialization; heap-floor, native
  work-budget and hard-time coverage remain PART. No new clock, quota, cap,
  default or corpus/timing claim.

- `51ea6e1ff7f46901ff483b5a8d2e20bf56fc7fe5` extends the same borrowed full token into
  GROUPBY/PIVOTBY cell-by-cell buffered grid reads, non-comparator parent-prefix
  scans and filter-array flattening. The local grid reader retains the original
  buffer capacity/reuse, row/cell order and cell/row clone count. Prefix tests
  keep zipped short-circuit identity comparisons; parent rank still takes the
  minimum matching position or zero. Flattening moves the same filter values
  in order; stored filter errors remain values and only direct checkpoints use
  native cancellation. Both standard sort bodies, lazy aggregate callbacks,
  pure row-index sort and uncancelled numeric/header/depth/subtotal rules stay
  unchanged. This is `0.9.3-oneiron.45`.
  Individual cell/key/string operations, atomic clones, allocation and sort-path
  work retain unpolled spans. Collection specialization/capacities outside the
  original grid buffer are not asserted equal; heap-floor, native work-budget
  and hard-time coverage remain PART. No new clock, quota, cap, default or
  corpus/timing claim.

- `e36343073bc4955e901f0b52593d4af616057274` polls the same borrowed full token during
  GROUPBY/PIVOTBY grid-width maxima, sort-spec flattening/coercion/validation,
  header/detail assembly and PIVOTBY relative-row index copies. Raw argument
  cancellation keeps its existing native channel; stored spec/coercion errors
  remain values and stored header/detail cells stay data. New direct checkpoint
  errors are native. Uncancelled maximum/truncation/short-circuit/header/numeric
  and copy ordering stay unchanged, with no extra invocation/evaluation/token
  capture. Both standard sort bodies, lazy aggregate callbacks and pure row-index
  sort remain unchanged. This is `0.9.3-oneiron.46`.
  Individual cell/string/coercion/formatting/clone operations, allocation and
  sort work retain unpolled spans. Collection specialization/capacities are not
  asserted equal; heap-floor, native work-budget and hard-time coverage remain
  PART. No new clock, quota, cap, default or corpus/timing claim.

- `88c3f89f8ce578e5db737e3da107680b44ab8736` polls the same borrowed full token before each outer
  GROUPBY/PIVOTBY grid-row and new distinct-key element clone, while initializing
  order/default sort columns/position indices and while copying grand-total
  key indices. Stored values, including error cells, are cloned once per outer
  element in the same order. Grand-total labels precede their key copies;
  both standard sort bodies and lazy aggregate callbacks remain unchanged.
  New checkpoints use the native error channel, without new token captures or
  callable invocations. This is `0.9.3-oneiron.47`.
  Recursive LiteralValue/string/error clones, allocation and initial PIVOTBY
  blank-row fills retain unpolled spans. Collection specialization/capacities
  are not asserted equal; heap-floor, native work-budget and hard-time
  coverage remain PART. No new clock, quota, cap, default or corpus/timing claim.

- `06130070137afff64d8b99a2d778836ffd46b64a` polls the same borrowed full token between PIVOTBY
  blank-header-prefix element copies, keeping one blank evaluation even at zero
  length and, at nonzero length, the original all-but-final clones then final
  seed move. The grid-row/new distinct-key copier also polls nested array rows
  and cells and text characters; text preserves original UTF-8 bytes in order.
  Other values, including stored error cells, retain their data clone behavior.
  Direct checkpoints remain native, with no extra token capture/evaluation or
  callable invocation. Header overwrites, labels, numeric rules and both sorts
  with lazy aggregate callbacks remain unchanged. This is `0.9.3-oneiron.48`.
  Allocation, error clones and other materialization/clone/sort paths retain
  unpolled spans; capacities/specialization are not asserted equal, and
  heap-floor, native work-budget and hard-time coverage remain PART. No new
  clock, quota, cap, default or corpus/timing claim.

- `450dc64441a72adcfeb350672582a6b6e37829a6` reuses the same nested/text copier for non-sort
  GROUPBY/PIVOTBY key/header/axis-label/detail-output cells and cancellable
  aggregate columns. Missing cells stay Empty, stored error cells remain data
  and native-only copy errors keep their existing channel at callers. Aggregate
  columns remain left to right before the original single invocation. The
  automatic header probe borrows the same first two cells and keeps the original
  short-circuit test without cloning their contents. Empty membership buckets
  poll the same token per key. The original sort-only cell/column/apply path,
  both standard sorts, lazy totals and numeric/index rules remain unchanged.
  This is `0.9.3-oneiron.49`.
  Other materialization, allocation, error-clone and sort paths retain unpolled
  spans. Collection specialization/capacities are not asserted equal; heap-floor,
  native work-budget and hard-time coverage remain PART. No new clock, quota,
  cap, default or corpus/timing claim.

- `4813bd8031043151718d8d83fd49717d115b248a` guards the existing argument value-cache insertion after
  reference-or-value resolution. When the value cache is already occupied, it
  skips the deep clone whose insertion would fail; empty-cache insertion,
  resolution order, returned values and cached error channels remain unchanged.
  Owned-row conversion also lends its existing full token to the row builder
  for a check before each cell's format/tag/value mutation. The public ordinary
  row append still has no token. The original per-row check remains first,
  stored errors remain data and cancellation drops the local builder before
  the final sheet is published. Text copying within a cell, padding, provisioning
  and chunk finishing remain unpolled spans.
  This is `0.9.3-oneiron.50`. The cache guard adds no token lookup or cancellation
  poll. The resolution's own clone and first cache population remain unpolled,
  as do other materialization/allocation/sort spans; heap-floor, native work-budget
  and hard-time coverage remain PART. No new clock, quota, cap, default or
  corpus/timing claim.

- `c845a71b6444bad744413b465fc426198e1b5afb` lends the owned-row constructor's same existing full
  token into initial builder setup and deferred provisioning, without a lookup
  or token clone. Initial setup polls before each empty column chunk and each
  builder/format/count/reserve entry in the original separate field passes.
  Deferred provisioning keeps its fast path and original six assignments per
  column, with a check before each column. Original public constructors and
  ordinary appenders still use None. Raw initial chunk capacities, the stored
  minimum-one chunk size, value/error lanes, counters and row order remain
  unchanged. An early error drops local unpublished partial construction.
  This is `0.9.3-oneiron.51`; collection capacity/specialization equality is
  not claimed. Width scanning, padding, individual text-body copying/reserves,
  chunk finishing and other clone/sort spans remain unpolled. Heap-floor,
  native work-budget and hard-time coverage remain PART. No new clock, quota,
  cap, default or corpus/timing claim.

- `da2eb0d4aa288c505567215a414f9b1cc43f83dd` checks the owned-row constructor's same existing full
  token while discovering the maximum row width and padding each shorter row.
  Row lengths are read in the original order; padding keeps the original
  reserve call, one Empty seed (including zero padding), n-1 clones and final
  seed move, with a direct native checkpoint before each inserted cell. The
  original per-row check stays before padding, then the same cell conversion
  follows. Zero-row/zero-width results, stored errors and row order remain
  unchanged when not cancelled. This is `0.9.3-oneiron.52`; there is no new
  lookup, token clone, width cap, clock or refusal policy. Individual reserves,
  text bodies, chunk finishing and other clone/sort spans remain unpolled;
  heap-floor, native work-budget and hard-time coverage remain PART. No
  collection specialization/capacity equality or corpus/timing claim.

- `5ee026e671674838ac984aae74c67d8c4bb10e96` lends the owned-row constructor's same existing full
  token to automatic chunk flushes and final sheet construction. Chunk flushing
  checks before each column, then preserves the numeric, boolean, text, error,
  tag, format, metadata and counter order. Final construction checks before each
  column, each chunk-count alignment check, and each outer and inner row-length
  alignment iteration. Chunk starts, alignment panics and ordinary no-token
  finish/append behavior remain unchanged when not cancelled. Native cancellation
  drops unpublished local state before the final Arc; stored errors remain data.
  This is `0.9.3-oneiron.53`; individual Arrow finishes, format-run construction,
  text bodies, reserves and other clone/sort spans remain unpolled. Heap-floor,
  native work-budget and hard-time coverage remain PART. No new lookup, token
  clone, clock, quota, cap, default, refusal policy or corpus/timing claim.

- `b0cc39301fe9055f3525c658b1729223ca57caa4` lends the chunk flush's same borrowed full token
  to format-run construction. Its all-General scan checks before each id and
  still stops at the first non-General id; only that case runs the original
  second encoding pass, now with a check before each id. Empty/all-General
  results, format/run-end push order and index/length casts remain unchanged
  when not cancelled. Ordinary public format constructors still use no token.
  A native error drops unpublished local arrays and format buffers before final
  sheet publication; stored errors remain data. This is `0.9.3-oneiron.54`.
  Individual Arrow finishes, text bodies, reserves and other clone/sort spans
  remain unpolled. Heap-floor, native work-budget and hard-time coverage remain
  PART. No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `2777e9557162b75bc8394eeac1a6ffa110fb117b` copies native owned-row text with the chunk's same borrowed
  full token. With a token it checks before each original UTF-8 character slice,
  writes the raw bytes directly into the Arrow string builder, then closes the
  same single value once. Without a token it keeps the original single append.
  Empty text still creates one empty entry. The numeric and boolean null appends
  stay before the text append; the text counter and error null append stay after
  success. Cancellation drops the unpublished local builder, including any
  unfinished text bytes, before final sheet publication. Ordinary text appenders
  and stored errors are unchanged. This is `0.9.3-oneiron.55`. Individual write
  allocations, Arrow finishes, reserves and other clone/sort spans remain
  unpolled. Heap-floor, native work-budget and hard-time coverage remain PART.
  No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `83049a39b5ab49d3a484e77b5a730f4144c40494` checks the owned numeric-result normalization scan
  with the range's same optional full token. With a token it checks before each
  column and each original array item, including nulls; it still stops at the
  first number needing the original normalization. Without a token it keeps the
  original iterator scan. Rebuilding checks before each row allocation and cell
  read, preserving row-major order, normalization, stored error data and linked
  reference restoration. Borrowed ranges still return unchanged. A native error
  drops local rows before a new owned range is published. This is
  `0.9.3-oneiron.56`. Individual allocations and cell clones, Arrow finishes,
  reserves and other clone/sort spans remain unpolled. Heap-floor, native
  work-budget and hard-time coverage remain PART. No new lookup, token clone,
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `46c78e0f2851e2a527bcd9748a10d7f3b2a2acd1` lends the same range token to each original column
  in shared row-chunk construction and all six typed slice projections: numbers,
  booleans, text, lowered text, errors and type tags. Checks happen before each
  column's original lane/null/overlay work and return native cancellation on the
  same fallible stream. Indexes, missing-column branches, base/overlay order,
  tuple shapes, stored error data and ordinary no-token behavior are unchanged.
  On cancellation the local partial output vector drops; any earlier lazy cache
  entry remains owned by its original sheet, as before. This is
  `0.9.3-oneiron.57`. Individual lane construction, null-array allocation, text
  lowering, overlay selection, cloning and other opaque allocation spans remain
  unpolled. Heap-floor, native work-budget and hard-time coverage remain PART.
  No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `a0f42b394b5ba0e6379c0941ec13f58f5070d25e` lends the same borrowed full token from the fallible
  lowered-text slice projection to each original lower-cache row. Cache hits
  retain the fast return; cancellation drops the unfinished local text builder
  before cache insertion. The three ordinary data-returning calls keep the
  uncancelled wrapper. Null handling, Unicode case-folding, allocation order and
  the existing cache race remain unchanged. This is `0.9.3-oneiron.58`.
  Individual case folds, appends, null-array allocation, Arrow finishing and
  overlay selection remain opaque, unpolled spans. Previously populated caches
  remain owned by their original sheet. Heap-floor, native work-budget and
  hard-time coverage remain PART. No new lookup, token clone, clock, quota, cap,
  default, refusal policy or corpus/timing claim.

- `95306160e744bb03ceb3fbccbbd7ff9242d2e1de` checks the same borrowed full token before each character
  folded and copied into a lower-cache text entry. The token-bearing path writes
  each folded scalar directly to the Arrow text builder and closes exactly one
  value, without constructing an intermediate folded string. A pure shared
  character mapping keeps Unicode simple lowercase, dotted-I and final-sigma
  behavior identical. Without a token, the original whole-string fold and
  single append remain; the ordinary ASCII fast path is unchanged. Nulls,
  empty strings, cache hits and cache races retain their original behavior.
  Cancellation drops the unfinished local builder before cache insertion;
  existing sheet-owned caches remain. This is `0.9.3-oneiron.59`. Individual
  scalar folds, encoded writes, allocations, Arrow finishing and overlay
  selection remain opaque spans. Heap-floor, native work-budget and hard-time
  coverage remain PART. No new lookup, token clone, clock, quota, cap, default,
  refusal policy or corpus/timing claim.

- `4fb5935d5e158715294d3186f3528580ce864b1b` lends the same borrowed full token from all six fallible
  typed slice projections to partial-overlay mask and value construction.
  Numbers, booleans, text, errors, type tags and lowered text check before each
  original row; the lowered-text point-scalar fallback checks before each
  original row too. Ordinary data-returning selectors keep their uncancelled
  wrappers. User/computed precedence, nulls, row order, base fallbacks and
  ordinary overlay statistics remain unchanged. Cancellation drops the local
  slots and unfinished output builders before zip selection; previously owned
  sheet caches remain. This is `0.9.3-oneiron.60`. Overlay detection, layer
  application, dense/run fast paths, whole-cell overlay text folds and clones,
  individual allocations, Arrow finishing and zip selection retain unpolled
  spans. Heap-floor, native work-budget and hard-time coverage remain PART.
  No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `a84fd25ae097ea2864abac6c729237c2df950004` carries the same borrowed full token through all six
  overlay layer readers and their existing fragment/payload walk. It checks
  before each fragment or point, including entries later filtered out, and
  before each sparse or dense payload row, run header and run payload row.
  The existing visitor remains infallible; native cancellation returns from
  the walker through the original single traversal, without a captured-error
  side channel or replay. Computed/user and fragment/point order, range filters,
  indexes, nulls, value expressions and ordinary statistics remain unchanged.
  Existing ordinary selectors retain their uncancelled wrappers. Cancellation
  drops local slots before output/zip construction; previously owned sheet
  caches remain. This is `0.9.3-oneiron.61`. Overlay detection, dense/run fast
  paths, individual value reads, whole-cell text clones/folds, allocations,
  Arrow finishing and zip selection retain opaque spans. Heap-floor, native
  work-budget and hard-time coverage remain PART. No new lookup, token clone,
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `dbe84e7346b6f62acbec00b447d5443ee09d1d68` carries the same borrowed full token into overlay-presence
  and full-cover discovery, including all six fallible typed projection guards.
  It checks before each original point and fragment scan step, including entries
  later filtered out. User/computed order, empty-range and point-veto behavior,
  first-match short circuits, shape/coverage rules and duplicate-cover refusal
  remain unchanged. Ordinary discovery calls keep their uncancelled wrappers;
  the pure fragment partition and interval operations are unchanged. Native
  cancellation returns through the existing fallible projection stream and
  drops any local output, without treating stored error cells as control.
  Previously owned sheet caches remain. This is `0.9.3-oneiron.62`. Individual
  fragment partition/interval checks, dense/run materialization, whole-cell
  text clones/folds, allocations, Arrow finishing and zip selection remain
  opaque spans. Heap-floor, native work-budget and hard-time coverage remain
  PART. No new lookup, token clone, clock, quota, cap, default, refusal policy
  or corpus/timing claim.

- `318cd8bc9b0fc68ba6fdd5b2660c76f701bbc7d9` carries the same borrowed full token through all six typed
  run materializers and their original single run walk. It checks before each
  original run header and repeated row append, including nulls. Value conversion
  and text folding still happen once per original run, with the result reused
  for repeated rows. Native cancellation returns directly through the fallible
  callback and drops unfinished local builders before Arrow publication.
  Run intersections, early exits, row order, nulls, type tags, statistics and
  ordinary no-token results remain unchanged. Stored error cells remain data;
  previously owned sheet caches remain. This is `0.9.3-oneiron.63`. Individual
  appends, value reads, whole-cell text folds and clones, allocations, dense
  materialization, Arrow finishing and zip selection retain opaque spans.
  Heap-floor, native work-budget and hard-time coverage remain PART. No new
  lookup, token clone, clock, quota, cap, default, refusal policy or corpus/timing
  claim.

- `530c261b8cdc91398b65cf8295111ac37a3f8df8` carries the same borrowed full token through dense lowered-text
  materialization. Both existing selector fast paths forward it through the
  original dense window into the materializer, which checks before each original
  payload row, including nulls. The original row index, window, value conversion,
  case fold, append/null expressions and statistics remain unchanged. Native
  cancellation returns directly through the existing fallible selector and
  drops the unfinished local builder before Arrow publication. Ordinary
  no-token results, stored error-cell data and previously owned sheet caches
  remain. This is `0.9.3-oneiron.64`. The other five dense typed paths remain
  unchanged. Individual value reads, whole-cell folds and
  clones, appends, allocations, Arrow finishing and zip selection retain opaque
  spans. Heap-floor, native work-budget and hard-time coverage remain PART.
  No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `50fda530432e54cc9cff376e0dc8b98a4110afbc` reuses the existing cancellable text appender for typed run-text,
  run-lowered-text and dense lowered-text copies. The same borrowed full token
  checks before each original UTF-8 character slice and one close finishes the
  Arrow value. The original run-repeat and dense-row checks remain. Conversion
  and folding still happen once per run or dense row; the same resulting value
  is borrowed for copying. Without a token the original single append remains.
  Empty entries, null branches, row order, type tags, statistics and stored
  error-cell data remain unchanged. Native cancellation drops the unfinished
  local builder before publication; previously owned sheet caches remain.
  This is `0.9.3-oneiron.65`. Whole-cell folds and clones, individual value reads,
  character writes, allocations, Arrow finishing and zip selection retain
  opaque spans. Heap-floor, native work-budget and hard-time coverage remain
  PART. No new lookup, token clone, clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `b16583658c0c5245ea0a792e7f4a996b120c07fc` carries the same borrowed full token into lowered-text payload
  folding for the run and dense materializers. It checks before each original
  character, applies the existing Unicode-simple and sigma mapping, and pushes
  into the local string. Folding still happens once per run or dense row, not
  once per repeated copy. Without a token the original whole-string fold and
  ASCII fast path remain. Missing tags, nulls, numeric, date/time, duration,
  boolean and stored-error branches remain unchanged. The working infallible
  overlay-layer caller keeps its no-token wrapper. Native cancellation drops
  the partial folded string and unfinished local output builder before
  publication; previously owned sheet caches remain. This is
  `0.9.3-oneiron.66`. Layer folding, individual tag/value reads, numeric string
  conversion, character writes, allocations, Arrow finishing and zip selection
  retain opaque spans. Heap-floor, native work-budget and hard-time coverage
  remain PART. No new lookup, token clone, clock, quota, cap, default, refusal
  policy or corpus/timing claim.

- `bccd581fa8d821770682c4049af186550611284a` carries the same borrowed full token into lowered-text fragment
  value folding. All six fragment value providers and the existing payload
  visitor return native Results through the same single traversal. The five
  other typed providers keep their original value expressions; the lowered-text
  provider calls the existing cancellable payload fold. Sparse, dense and run
  visitors propagate native cancellation directly, without a captured-error
  side channel, replay or second walk. Conversion remains once per original
  payload visit, including each visited repeated run row. Original checks,
  filters, indexes, nulls, statistics, early exits, computed/user and fragment/
  point order stay unchanged. The now-unused private no-token payload wrapper
  is removed after its real caller is replaced; ordinary no-token selectors
  keep their original results. Native cancellation drops local slots and any
  partial folded string before zip publication; previously owned sheet caches
  and stored error-cell data remain. This is `0.9.3-oneiron.67`. Point-scalar
  folding, whole-cell text clones, individual reads, numeric string conversion,
  writes, allocations, Arrow finishing and zip selection retain opaque spans.
  Heap-floor, native work-budget and hard-time coverage remain PART. No new
  lookup, token clone, clock, quota, cap, default, refusal policy or corpus/timing
  claim.

- `b2b115af6d4b260d8bae60e7a638ebf847529b3f` factors the existing cancellable string fold into one
  private supplier and lends the same borrowed full token to point-overlay and
  point-scalar fallback text folding through native Result companions. Both
  existing scalar no-token entrypoints remain available with their original
  results. Text uses the existing Unicode-simple and sigma mapping, checking
  before each original character; without a token the original whole-string
  fold and ASCII fast path remain. Numeric, date/time, duration, boolean, null
  and stored-error branches keep their expressions. The two fallible callers
  propagate cancellation directly through their original point and fallback
  loops. Borrowed scalar lookup, computed/user and fragment/point precedence,
  masks, indexes, nulls and statistics stay unchanged. Native cancellation drops
  local partial strings and unfinished outputs before publication; previously
  owned sheet caches and stored error-cell data remain. This is
  `0.9.3-oneiron.68`. Whole-cell text clones, individual reads, numeric string
  conversion, writes, allocations, Arrow finishing and zip selection retain
  opaque spans. Heap-floor, native work-budget and hard-time coverage remain
  PART. No new lookup, token clone, clock, quota, cap, default, refusal policy
  or corpus/timing claim.

- `ef2019bff9e401e642ebc078d0984323fe2ffdee` lends the same borrowed full token to local string-to-Arrow
  copies in the partial-overlay lowered-text selector and its point-scalar
  fallback. Both reuse the existing cancellable text appender at their original
  copy sites. With a token it checks before each original UTF-8 slice, writes
  directly and closes one value; without a token it keeps the original single
  append. Empty values still close one entry. Nulls, masks, slots, row order,
  computed/user precedence, statistics and finishing remain unchanged. Native
  cancellation drops the unfinished local builders and slots before publication;
  previously owned sheet caches and stored error-cell data remain. This is
  `0.9.3-oneiron.69`. Whole-cell text clones, individual reads, numeric string
  conversion, writes, allocations, Arrow finishing and zip selection retain
  opaque spans. Heap-floor, native work-budget and hard-time coverage remain
  PART. No new lookup, token clone, clock, quota, cap, default, refusal policy
  or corpus/timing claim.

- `7b78eafdda8b60beecd7ccdc100d474c2b5214dd` lends the same borrowed full token to the original local
  string-to-Arrow copy in the ordinary-text partial-overlay selector. It reuses
  the existing cancellable text appender: with a token, each original UTF-8
  slice is checked before direct writing and one value closes; without a token,
  the original single append remains. Empty entries, nulls, masks, slot values,
  row checks, branch order, computed/user precedence, statistics and finishing
  remain unchanged. No separate ordinary-text point fallback is introduced.
  Native cancellation drops the unfinished local builders and slots before
  publication; previously owned sheet caches and stored error-cell data remain.
  This is `0.9.3-oneiron.70`. Text cloning into slots, whole-cell text clones,
  individual reads, numeric conversion, writes, allocations, Arrow finishing
  and zip selection retain opaque spans. Heap-floor, native work-budget and
  hard-time coverage remain PART. No new lookup, token clone, clock, quota,
  cap, default, refusal policy or corpus/timing claim.

- `aff6392bee7ab3b40366b65537228a7691e6b837` lends the same borrowed full token to the two original
  ordinary-text copies into partial-overlay slots: fragment payloads and points.
  One private literal-text copier checks each original character before pushing
  it into the local String, without case folding. Without a token, the original
  `to_string` remains. The existing single fragment walk and native Result path
  propagate cancellation; points still overwrite fragments, user layers still
  overwrite computed layers, and nontext/null values still mark present slots.
  Row checks, indices, statistics, fast paths and the final cancellable Arrow
  copy remain unchanged. On native cancellation, local partial strings and
  caller-owned slots drop before publication; prior owned caches and stored
  error-cell data remain. This is `0.9.3-oneiron.71`. Whole-cell text clones,
  individual reads, numeric conversion, writes, allocations, String pushes,
  Arrow finishing and zip selection retain opaque spans. Heap-floor, native
  work-budget and hard-time coverage remain PART. No new lookup, token clone,
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `64af12031772a345c9d7992c308afeb7f7cd0f4a` replaces the original three token-bearing final text-zip
  copies with one private typed copier. Ordinary text, lowered fragment text and
  lowered point-scalar text select the same original mask's source row, preserve
  its null or empty value, and reuse the existing literal-text appender with the
  same borrowed full token. Each row and each copied character checks native
  cancellation. The original token-absent Arrow zip calls, their diagnostics and
  the lowered-text downcast/wrap remain. Existing fast paths, slots, mask/value
  construction, row checks, precedence and statistics stay unchanged. This
  replaces the original zip output walk, without a second walk or extra text
  buffer; it reuses the existing row/byte capacity expression. Cancellation
  drops the local output and caller-owned mask, values and slots before
  publication. Prior owned caches and stored error-cell data remain. This is
  `0.9.3-oneiron.72`. Whole-cell text clones, individual reads, numeric conversion,
  writes, allocations, String pushes, finishing and Arc construction retain
  opaque spans. Other zip paths, heap-floor, native work-budget and hard-time
  coverage remain PART. No new lookup, token clone, clock, quota, cap, default,
  refusal policy or corpus/timing claim.

- `b7eaa7b5f79c77ade04cbd12b04a6499b1342b71` replaces the original four token-bearing final fixed-width
  zip copies with one private primitive copier for the numeric, error and
  type-tag lanes and one private boolean copier. The same original mask selects
  the source row; nulls, sliced offsets, Float64 bits, UInt8 codes and booleans
  stay unchanged. Each copied row checks the same borrowed full token and
  propagates native cancellation. The original token-absent Arrow zip calls,
  diagnostics and typed downcast/wrap remain. Existing fast paths, slots,
  mask/value construction, row checks, precedence, statistics and text zips
  stay unchanged. The native copy replaces the original zip output walk, with
  no second walk or extra input copy, and keeps the existing row-capacity
  expression. Cancellation drops local output and caller-owned mask, values
  and slots before publication; prior owned caches and stored error-cell data
  remain. This is `0.9.3-oneiron.73`. Whole-cell text clones, individual reads,
  numeric conversion, writes, allocations, finishing and Arc construction
  retain opaque spans. Other zip paths, heap-floor, native work-budget and
  hard-time coverage remain PART. No new lookup, token clone, clock, quota,
  cap, default, refusal policy or corpus/timing claim.

- `abf699910f6764b2857104623e064477335f02ce` prepares an eligible WriteCell overlay under the original active
  cancellation job before recording the current cell's delta or updating its
  graph value. Its text conversion replaces the original String clone with
  the existing literal copier and the same borrowed full token; Arc construction
  remains opaque. The original paid-prefix buffer flush still runs first, with
  its resource checks and error precedence. Shared eligibility guards skip
  unused conversion; format lookup and buffered or direct overlay publication
  stay at the original publication point, with no new cancellation point
  between the graph update and overlay publication. Token-absent calls and
  ordinary mirror wrappers retain the old conversion and order. A conversion
  error drops local text before current-cell mutation; prior paid prefixes,
  owned caches and stored error-cell data remain. This is `0.9.3-oneiron.74`,
  not whole-job rollback or full cancellation coverage. Graph value cloning,
  individual reads, numeric conversion, writes, allocation, String pushes,
  finishing and Arc construction retain opaque spans; heap-floor, native
  work-budget and hard-time coverage remain PART. No new lookup, token clone,
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `4189b017da78b106a2d4d97d4073a0272c6db453` also prepares the original graph-input Text String copy under
  the same active cancellation job, after overlay preparation but before the
  current cell's delta or graph update. It reuses the same literal copier through
  a crate-local method; each copied character checks the same borrowed token.
  The graph input is prepared even when overlay eligibility skips conversion.
  Token-absent and nontext input still clone at the original graph-update point.
  This replaces the original second String copy, without a third text buffer,
  another walk, token clone or a new cancellation point between graph and
  overlay publication. Native cancellation drops the partial graph input and
  prepared overlay before current-cell mutation; the original paid-prefix flush
  and its error precedence remain. This is `0.9.3-oneiron.75`. Native string
  interning, nontext and nested-array clones, old-value reads, Arc construction,
  allocation, writes, finishing and other callers retain opaque spans; heap-floor,
  native work-budget and hard-time coverage remain PART. No new clock, quota,
  cap, default, refusal policy or corpus/timing claim.

- `1ba5220ff9a79de88b74fb038c225fac840a37f6` carries the same borrowed active cancellation token through the
  original WriteCell delta's owned old-value text read, after the paid-prefix
  flush, overlay preparation and graph-input preparation, but before recording
  the current delta or updating the graph. One shared fallible Arrow cell reader
  preserves bounds, missing cells, user-over-computed-over-base precedence,
  nulls, date serials and stored error-cell data. Point and fragment overlay
  text and base text reuse the existing literal copier; each copied character
  checks the original token. The ordinary readers pass no token and retain
  their infallible values and missing/Empty-to-None behavior. Cancellation
  propagates before current-cell mutation and drops local partial text and
  prepared inputs; prior paid prefixes and owned caches remain. This is
  `0.9.3-oneiron.76`. The fragment's earlier Arc construction, equality checks,
  string interning, other callers, allocations and finishing remain opaque;
  heap-floor, native work-budget and hard-time coverage remain PART. No new
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `34aec020ebd1faae5271a6662f0d1f56f6cf36e8` adds native cancellation checkpoints during the original WriteCell
  delta's Text/Text equality comparison, using the same borrowed active token
  and existing checkpoint function. Equal-length text compares its original
  bytes in order and stops at the first mismatch; unequal lengths and empty
  text retain their direct results. Token-absent and nontext values keep the
  original derived equality, without new text copies or buffers. Cancellation
  propagates before recording the current delta or updating the graph, dropping
  local old-value and prepared inputs while preserving paid prefixes and owned
  caches. The earlier flush, overlay and graph-input preparation, owned read,
  and paired graph/overlay publication keep their order. This is
  `0.9.3-oneiron.77`. Other comparisons, nested-array equality, fragment Arc
  construction, string interning, allocations and finishing remain opaque;
  heap-floor, native work-budget and hard-time coverage remain PART. No new
  clock, quota, cap, default, refusal policy or corpus/timing claim.

- `6ebcc621644403589fd6206bd9856a1cbf06aa39` reads token-bearing old-value fragment text directly from its
  existing borrowed Arrow string through the same literal copier. This removes
  the temporary text Arc before the final owned String, without changing the
  stored overlay representation. The original sparse, dense and run selection
  geometry is shared by scalar and fallible literal reads; point-first,
  reverse-fragment and user-over-computed-over-base priority remain. Missing or
  null payloads still fall through, while a present Empty masks lower layers.
  Nontext values keep the original scalar conversion, including date serials
  and stored error-cell data. Ordinary token-absent reads retain the scalar
  chain. Native cancellation still propagates before the current delta or
  graph update, dropping local text and prepared inputs; prior paid prefixes,
  owned caches and paired graph/overlay publication remain. This is
  `0.9.3-oneiron.78`. Fragment discovery, point lookup, string interning, other
  readers, allocation and finishing retain opaque spans; heap-floor, native
  work-budget and hard-time coverage remain PART. No new clock, quota, cap,
  default, refusal policy or corpus/timing claim.

- `88d93dba77e4c1f1777ed84ff5ff2b3ba3ef922e` checks the same borrowed active token before each original
  reverse-fragment attempt in the old-value reader. It adds no second walk or
  text copy. Points still win first; the first present fragment value, including
  Empty, wins in reverse order; missing or null payloads fall through to the
  same lower layers. Token-absent reads retain their original scalar chain.
  Native cancellation propagates before the current delta or graph update,
  dropping local prepared inputs while preserving paid prefixes, owned caches
  and paired graph/overlay publication. This is `0.9.3-oneiron.79`. Individual
  fragment searches, point lookup, string interning, allocation and finishing
  retain opaque spans; heap-floor, native work-budget and hard-time coverage
  remain PART. No new clock, quota, cap, default, refusal policy or corpus/timing
  claim.

- `8ffa80915667fb3db0a3bef62f36c178f6f54233` checks the same borrowed active token before each cell copied
  from the original spill-clear target slice. The existing paid-prefix flush
  remains first. Cancellation drops the local partial list before snapshots,
  delta recording, graph clearing, overlay mirrors or the change log. The
  single output list retains its original order and capacity request;
  token-absent copying keeps the original slice clone, and missing or empty
  lists keep their results. All later spill-clear operations remain unchanged.
  This is `0.9.3-oneiron.80`. Snapshots, cell reads, clearing, mirroring,
  allocation and other callers retain opaque spans; heap-floor, native
  work-budget and hard-time coverage remain PART. No new clock, quota, cap,
  default, refusal policy or corpus/timing claim.

- `7782a84abc70d33e1d0fa4795477dbc2561cb842` carries the same borrowed token through spill-clear change-log
  snapshot preparation. Caller and snapshot share the original cell-copy helper;
  the snapshot polls its cell reads and output rows and cells. Its fallible
  public cell reader retains the original format lookup, temporal egress and
  normalization. Text clones use the existing cancellable literal copier;
  token-absent and nontext clones retain the original copy. Missing and empty
  snapshots, truncation after copying, cell and rectangle order remain intact.
  Other snapshot callers retain the token-absent wrapper. Cancellation drops
  local preparation before delta recording, graph clearing, overlay mirrors
  or logging; the paid-prefix flush stays first and paired mutation bodies are
  unchanged. This is `0.9.3-oneiron.81`. Hashing, allocation, nontext clones and
  later mutation work remain opaque; heap-floor, native work-budget and
  hard-time coverage remain PART. No new clock, quota, cap, default, refusal
  policy or corpus/timing claim.

- `4baee444bb8a1421ac66b3450573eb95767d766d` prepares both original owned spill-commit value copies with
  the same borrowed active token. Row and cell copies poll it; text uses the
  existing cancellable literal copier. The caller lends token-bearing values
  through the original spill guard, paid-prefix flush and old snapshot before
  either fallible copy. Token-absent calls retain their original first clone
  before entering the callee and second clone at the original commit point.
  Both owned copies remain: one feeds the commit, the other the new change-log
  snapshot. Cancellation drops local preparation before committing; no new
  check splits paired mutations or the later change-log record. This is
  `0.9.3-oneiron.82`. Nested nontext clones, hashing, allocation and later
  mutation work retain opaque spans; heap-floor, native work-budget and
  hard-time coverage remain PART. No new clock, quota, cap, default, refusal
  policy or corpus/timing claim.

- `04d5299c40efb606b8ba9cb2c39e3078b1659555` prepares the original spill-commit change-log target-cell
  list with the same borrowed token before committing, after both value copies.
  It reuses the existing ordered cell-copy helper and moves that owned list
  into the later record. Token-absent calls keep their original post-commit
  clone; calls without a change log make no extra list. Cancellation drops
  local preparation before committing, never between paired mutations or the
  commit and its log record. The spill guard, paid-prefix flush, old snapshot
  and value-copy order remain intact. This is `0.9.3-oneiron.83`. Inner commit
  work, hashing, allocation and nontext clones remain opaque; heap-floor,
  native work-budget and hard-time coverage remain PART. No new clock, quota,
  cap, default, refusal policy or corpus/timing claim.

- `36f1d7710bc8f98d815602e319414332b4ab95ae` passes the same borrowed active token into the old spill-commit
  change-log snapshot at its original preparation point. The spill guard and
  paid-prefix flush stay first; value and target-cell copies still follow the
  snapshot before committing. Token-absent calls keep the ordinary snapshot
  wrapper and its existing error behavior; calls without a change log skip
  the snapshot. The unchanged fallible snapshot retains public format lookup,
  temporal egress, normalization, missing and empty results, truncation after
  copying, and cell and rectangle order. Cancellation drops local preparation
  before committing, not between paired mutations or the later log record.
  This is `0.9.3-oneiron.84`. Hashing, allocation, nontext clones and inner
  commit work retain opaque spans; heap-floor, native work-budget and hard-time
  coverage remain PART. No new clock, quota, cap, default, refusal policy or
  corpus/timing claim.

- `d37377470cbdd6931f612233c4e25fe5d5e3d299` prepares the inner spill-effect commit's owned value copy
  with the same borrowed active token, after its existing spill guard and
  previous-cell snapshot, before current delta records or spill-write invalidation.
  Row, cell and text copies reuse the native cancellable value copier. A private
  call-site selector enables only the already-cancellable spill-effect caller;
  the two ordinary callers and token-absent calls retain the original clone point.
  The prepared copy moves into the existing spill-manager commit. No cancellation
  point splits its planning, core commit, formula-plane or overlay mutations, or
  the later change-log record. Cancellation drops local preparation before
  current mutations; prior reservations and paid prefixes can remain. This is
  `0.9.3-oneiron.85`. Previous-cell copying, old-value reads, comparisons, nontext
  clones, hashing, allocation and later mutation work retain opaque spans;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `7d529d8b27aa6dfffce3ef6d9bbb38174160e053` polls the original previous-spill cell list copy in the
  already-cancellable spill-effect path. The existing ordered cell-copy helper
  checks the same borrowed active token for each cell, with its original capacity
  request. The copy stays after the inner spill guard, before value preparation,
  delta records, spill-write invalidation and the core commit. Missing and empty
  lists keep their results; the two ordinary callers and token-absent calls keep
  their original slice copy. Cancellation drops the local partial list before
  current mutations; prior reservations and paid prefixes can remain. All later
  mutation and change-log bodies stay unchanged. This is `0.9.3-oneiron.86`.
  Old-value reads, comparisons, nontext clones, hashing, allocation and later
  mutation work retain opaque spans; heap-floor, native work-budget and hard-time
  coverage remain PART. No new token clone, clock, quota, cap, operating default,
  refusal policy or corpus/timing claim.

- `99f3a4be170dee2e2dbf0044b5ad9818a64595e9` polls the original inner spill-change detection in the
  already-cancellable spill-effect caller. The previous-cell membership scan
  still runs first and stops at the first missing target; the target scan runs
  only if needed and stops at the first changed value. Each attempted cell uses
  the same borrowed token. New text copies, public old-value reads with format
  and temporal egress, and text equality reuse the existing cancellable
  primitives. Missing/empty values and stored cancellation errors as cell data
  keep their meanings. Guard, paid-prefix flush and prepared-copy precedence
  stay unchanged. Checks precede spill-write invalidation and core mutations;
  no new check splits paired mutations, overlays or the change-log record.
  The two ordinary callers and token-absent calls keep the original expression.
  Native errors propagate, and request collectors finish only after success;
  this change adds no rollback, staging, replay or second walk. This is
  `0.9.3-oneiron.87`. Separate delta loops, each membership lookup, nontext
  clones, hashing, allocation and later mutation work retain opaque spans;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `7a24679469336600b620ae061bdfba4650dff520` polls each original target membership candidate inside
  the already-cancellable spill-change previous-cell scan. It checks the same
  borrowed token before the original cell equality and stops at the first match.
  Empty target slices, the first missing previous cell, and the all-present gate
  into the later value scan keep their original meanings. This replaces the
  membership lookup with one ordered borrowed walk, without a new collection,
  second walk, staging, replay or rollback. Ordinary callers and token-absent
  calls retain the original expression. Checks remain before spill-write
  invalidation and core mutations; all subsequent mutation and change-log bodies
  stay unchanged. This is `0.9.3-oneiron.88`. Separate delta loops, nontext clones,
  hashing, allocation and later mutations retain opaque spans; heap-floor,
  native work-budget and hard-time coverage remain PART. No new token clone,
  clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `35f4706fd6c680557341d64ef45de90d34075d98` polls the original final target-cell copy in the
  spill-manager shim, at the existing graph-commit argument position. Only the
  already-cancellable spill-effect caller supplies the same borrowed active
  token; the two ordinary callers and token-absent calls retain the original
  slice copy at that position. The existing plan and Arrow value-blocker checks
  still precede the copy and retain error priority. The existing ordered cell
  copier prepares the same target vector. Both copy errors and graph-commit
  results pass through the original single lock-release site. Copy failure
  skips the graph core, but prior reservations or spill-write invalidation may
  remain; no rollback is added. The graph core, paired mutations, overlays and
  subsequent change-log record receive no new cancellation point. This is
  `0.9.3-oneiron.89`. Separate delta loops, plan and blocker work, nontext clones,
  hashing, allocation and later mutations retain opaque spans; heap-floor,
  native work-budget and hard-time coverage remain PART. No new token clone,
  clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `a231139cc67c9d1c8a3d071455c5931f04418b4e` polls each original target attempt in the shim's
  Arrow-canonical rectangle-shape and value-blocker walks. The original plan
  remains first. The same borrowed token is checked before each cell's original
  shape or blocker work; anchor, existing-spill and formula skip order stays
  unchanged. A native cancellation releases only that anchor's reservation
  through the existing owner-release method, then returns before the target copy
  or graph core. Token-absent checks are no-ops and preserve ordinary results,
  skips and error order. Existing blocker values and diagnostics keep their
  meanings. Earlier spill-write invalidation or reservations may remain; this
  adds no rollback, staging, replay or second walk. The graph core, paired
  mutations, overlays and change-log record receive no new checkpoint. This is
  `0.9.3-oneiron.90`. Separate delta loops, probe value copies, plan work, nontext
  clones, hashing, allocation and later mutations retain opaque spans;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `d60c68b1d6153cdebc51cbb7e32b761ff9dc9d09` adds a fallible result channel to the raw Arrow value-blocker
  probe in the existing spill-manager shim. The already-cancellable spill-effect
  caller passes the same borrowed active token to the existing Arrow value reader;
  ordinary and token-absent calls retain the original getter and invariant check
  at the original phase. Missing sheets and empty cells remain non-blockers.
  Stored error values, including the Cancelled cell value, remain blocker data;
  native operation errors move unchanged through the new result channel, release
  only that anchor's reservation, and return before the target copy or graph core.
  The original plan and anchor, spill and formula skip order stay unchanged.
  Earlier reservations or spill-write invalidation may remain; no rollback,
  staging, replay or second walk is added. Graph paired mutations, overlays and
  change-log work receive no new checkpoint. This is `0.9.3-oneiron.91`.
  Separate delta loops, nontext clones, plan work, hashing, allocation and later
  mutations retain opaque spans; heap-floor, native work-budget and hard-time
  coverage remain PART. No new token clone, clock, quota, cap, operating default,
  refusal policy or corpus/timing claim.

- `ee0cf6716e2d6e664d6729c6fda163dfeabced5f` polls the same borrowed caller token before each original
  target attempt in the graph plan's shape and conflict walks, and each original
  cell in spill-write rectangle invalidation. The old ordinary plan entry point
  delegates without a token to the same algorithm. Only the existing token-bearing
  spill-manager path selects the cancellable plan; native errors move through the
  original plan-error owner cleanup. The token-bearing plan uses the existing
  value-type discriminator for its Empty-only blocker question instead of
  materializing text, stored errors or nested arrays. Reserved tags retain the
  discriminator's original Empty meaning; all normal-return nonempty values,
  including stored Cancelled errors, remain blockers. Token-absent calls retain
  the original owned value read. The token-bearing tag check bypasses arena
  payload materialization and does not claim malformed-payload panic equivalence.
  Original blocker order, diagnostics and overwrite allowances remain unchanged.
  Earlier reservations or invalidation rectangles may remain after cancellation;
  this adds no rollback, replay, second walk or checkpoint inside graph paired
  mutations, overlays or change-log work. This is `0.9.3-oneiron.92`.
  Hashing, allocation, core mutations and other opaque spans remain; heap-floor,
  native work-budget and hard-time coverage remain PART. No new token clone,
  clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `d89d0d8f1635c2ee2f21209eb8a81b5294c8578a` carries the same borrowed caller token into the graph commit's
  existing preparation prefix. Original resource admission and anchor resolution
  remain first. Only the cancellable shim supplies a token to the new internal
  entry point; the ordinary public entry point delegates without a token to the
  same algorithm.
  The original previous-owner cell snapshot uses the existing ordered cancellable
  cell copier on that path; the copier's body is unchanged and only crate visibility
  is added for this reuse. The two original membership sets check the token before
  each ordered cell insertion attempt, keeping the same coordinate hasher and
  duplicate handling, with a reserve based on input length. Ordinary calls retain
  their original
  snapshot clone and collection expressions; the previously unused set is still
  evaluated. Native errors move through the original single shim lock cleanup
  before any graph mutation. Earlier caller reservations or invalidation rectangles
  may remain; this adds no rollback or all-mutation-absent guarantee. Mutation,
  injected-fault rollback, ownership and subsequent log text remain unchanged and
  receive no new checkpoint. This is `0.9.3-oneiron.93`. Allocation, hashing,
  operation-list and old-value materialization, and the core retain opaque spans;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `4697749111aa4a78570cb6974e9157353a5606fb` polls the same borrowed caller token before each original
  clear-cell, write-row, write-value and old-snapshot operation attempt in the
  graph commit's preparation prefix, including empty write rows. Only the
  token-bearing path reuses the existing per-character text copier at the original
  sheet-name and Text-value clone positions. Ordinary calls keep their exact
  original string/value clone expressions and phase order. Both paths retain the
  original old-value reader before the tuple-key copy, then move the old value
  into its snapshot; stored Cancelled errors remain cell data. Native operation
  errors move through the same single shim cleanup before graph mutation. The
  apply, injected-fault rollback, ownership and subsequent log paths are unchanged
  and receive no checkpoint. Earlier caller prefixes may remain; this adds no
  rollback or all-mutation-absent guarantee. This is `0.9.3-oneiron.94`. The text
  copier allocates capacity before its character checks. Nontext and nested-array
  clones, old-value materialization, allocation, hashing and the core retain opaque
  spans; heap-floor, native work-budget and hard-time coverage remain PART. No
  new token clone, clock, quota, cap, operating default, refusal policy or
  corpus/timing claim.

- `604274aada5a93ed7740d2dd420810661463f5f4` reuses the existing GROUPBY nested-literal copier at
  the graph commit's operation new-value copy position. Only crate visibility
  and a lookup-module re-export are added; the copier body and existing GROUPBY
  callers are unchanged. Token-bearing copies borrow the same full token and
  poll at value, nested-row, nested-cell and text-character boundaries. Ordinary
  calls retain the original value clone at the same argument position. Stored
  errors, including Cancelled, remain cloned cell data; checkpoint failures alone
  take the native operation-error path through the single shim cleanup. The
  original sheet copies, old-value reader, mutation, injected-fault rollback,
  ownership and subsequent log paths remain unchanged. Earlier caller prefixes
  may remain; no rollback or all-mutation-absent guarantee is added. This is
  `0.9.3-oneiron.95`. Error clones, allocation, old-value materialization and the
  core retain opaque spans; heap-floor, native work-budget and hard-time coverage
  remain PART. No new token clone, clock, quota, cap, operating default, refusal
  policy or corpus/timing claim.

- `6fc5cfca1da121a272bd2b48431f491dcf1b11cd` carries the same borrowed full caller token through
  the graph commit's rollback-snapshot value reader at its original preparation
  position. A new internal graph-cache reader retains the original disabled-cache
  instrumentation and sheet, coordinate, vertex and value gates. Missing values
  still become Empty at the caller. A new internal arena reader retains original
  string interner resolution before the existing cancellable text copy; arrays
  keep their original raw-reference copy before row-major, per-row and recursive
  per-cell materialization checks. All other value kinds use the original arena
  retrieval, including stored Cancelled errors as cell data. Ordinary calls keep
  the original public graph getter and Empty fallback. Native errors move through
  the same single shim cleanup before tuple-key copying or graph mutation. Apply,
  injected-fault rollback, ownership and later logging remain unchanged. Earlier
  caller prefixes may remain; no rollback or all-mutation-absent guarantee is added.
  This is `0.9.3-oneiron.96`. Raw-reference array copying, lookups, allocation,
  error-message copies, scalar conversion and the core retain opaque spans;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `ebd9409ffb79928ba5c3e3b26eacdce865e87fb9` replaces only the token-bearing arena array reader's
  owned raw-reference array collection with the original borrowed dimensions and
  element slice. It keeps the native dimensions-then-elements gates, zero-row or
  zero-column empty result, row-major slice arithmetic and the same per-row and
  recursive per-cell checks with the same borrowed caller token. Public arena
  retrieval and raw-reference array getter bodies remain unchanged. The element
  borrow stays live during recursive reads; destination row allocations and
  arena storage remain opaque. A cancellation can precede a later corrupt-row
  panic; no corrupted-offset repair or panic/callback-order equivalence is
  claimed. All earlier rollback-snapshot, key-copy, apply, fault rollback,
  ownership and logging paths stay unchanged. This is `0.9.3-oneiron.97`;
  heap-floor, native work-budget and hard-time coverage remain PART. No new token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing claim.

- `2b50c9ec6fbd99804d2b42e33423960a87e92ed3` carries the same borrowed full caller token through
  the arena error-message materialization at its original value-reader position.
  A new internal fallible error getter retains the original error-reference,
  message-id and direct interner-resolution gates before reusing the existing
  cancellable text copier. The error still contains only its stored kind and
  optional message, with the original empty context and extra fields. Missing
  references retain the original Value cell error; stored Cancelled errors stay
  cell data, while only token cancellation in message copying returns a native
  error. Ordinary arena retrieval and the public error getter bodies stay
  unchanged. No graph, key-copy, shim-cleanup, mutation, fault rollback,
  ownership or logging path changes. This is `0.9.3-oneiron.98`; allocation and
  remaining native spans stay opaque, and full heap-floor, native work-budget
  and hard-time coverage remain PART. No token clone, clock, quota, cap,
  operating default, refusal policy or corpus/timing claim is added.

- `9c0cf828e4bf016c0a17556b8d30f12924787fad` carries the same borrowed full caller token through
  the spill commit's anchor sheet-name copy at its original pre-mutation
  position. The token-bearing path reuses the existing cancellable text copier;
  None retains the original `to_string`. Anchor resolution and resource
  preflight remain before this copy. Previous-cell collection, old-value
  snapshots, apply/fault rollback, ownership updates and logging are unchanged.
  An observed cancellation returns its native error before those later phases;
  empty text has the copier's existing zero-character behavior. This is
  `0.9.3-oneiron.99`, not a heap-floor, native work-budget or hard-time
  certificate; allocation and other native spans remain opaque/PART. No token
  clone, clock, quota, cap, operating default, refusal policy or corpus/timing
  claim is added.

`deny.toml` allows `https://github.com/oneiron-dev/formualizer` in `allow-git`, and CC0-1.0
(owner ruling 2026-09-26) for `tiny-keccak` 2.0.2, which `formualizer-eval` pulls in at build
time through `arrow` → `ahash` → `const-random`. The engine stamps recalculated versions
`oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.99`.

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
