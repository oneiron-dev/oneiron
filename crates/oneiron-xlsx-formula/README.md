# In-process XLSX formula engine

The default recalc of the core's edit round trip. `oneiron::edit_roundtrip` wraps every
host `EditSession` unless the host opts out (`EditSession::recalc_policy` returning
`RecalcPolicy::SessionOnly`): the host keeps its narrow editor, and
`FormualizerEngine::recalculate_xlsx` recalculates every workbook it admits, reading each
package under the host's document limits (`Vault::docedit_package_limits`; the raw
`run_edit_roundtrip` uses the shipped ceilings). The recalculation is the fork's retained
cache writer, `formualizer_workbook::recalculate_xlsx_bytes` (upstream feature
`xlsx-recalc`), run under the stricter of each host limit and its own. One multi-sheet
graph evaluates ordinary, shared and array formulas, dynamic arrays inside their saved
extent, defined names, tables and structured references, and the workbook's iteration
settings. Only formula caches, their value types, calculate-always flags and Excel's rich
error tags change; the package keeps every other byte. This crate depends on
`oneiron-docedit`, never on the core.

The retained writer carries the caller's `Resources` through its cooperative cancellation
token and polls it at formula AST and arena nodes, including reference evaluation, and at
existing cancellation checkpoints. A deadline is only one the caller supplied; no deadline
stays untimed. A checkpoint refusal returns the existing typed `FormulaError::Resource` to
the direct `recalculate_xlsx` caller. The core's current no-deadline recalc and precision
fallback are unchanged. A long builtin that does not poll can still run until its next
checkpoint; this is not a time bound on every builtin.

The matrix builtins MMULT, MDETERM, MINVERSE and MUNIT poll the same caller token
through the existing `FunctionContext` port. Arithmetic order, existing singular/error
results and the MUNIT 2000 cap are unchanged. Input materialization, individual inner
loops and other long builtins still have unpolled work; this adds no hard time bound.

RATE, IRR and XIRR also poll the same token between solver iterations; IRR additionally
polls its bracket probes and initial Brent NPV phases. Cancellation propagates as a typed
error, not a non-convergence result or another solver attempt. Existing guesses,
iteration counts, tolerances and arithmetic order are unchanged. NPV, IRR, XNPV and XIRR
also poll that same token during cashflow/date intake, date truncation and the individual
NPV/derivative scans. Typed cancellation escapes each private helper through its actual
caller, not a NUM result, another solver attempt or a boxed success. Financial builtins
outside the named families, allocation internals and remaining bond/coupon paths still
have unpolled work; this does not bound every financial builtin.

YIELD and ODDFYIELD poll the same token between Newton iterations and before their final
valuations. Cancellation escapes as a typed error before numeric-result boxing. Original
guesses, iteration counts, tolerances, arithmetic order and the YIELD single-coupon path
are unchanged. Coupon price/slope scans use the same token as described below;
bond intake and calendar/schedule helpers still have unpolled work.

MIRR polls the same full token during cashflow intake and its discount/compounding
scan. CUMIPMT and CUMPRINC poll before each payment period, retaining the existing
floating-point summation and numeric helpers. FVSCHEDULE polls during schedule
traversal and returns typed cancellation before numeric-result boxing. These checks
reuse the caller's token; no clock or work quota is added. NPV no longer refuses solely
because its variadic argument count exceeds 255; its minimum arity, coercion, traversal
and cancellation checks are unchanged. Allocation and other unpolled inner work remain
outside this cooperative checkpoint coverage.

ACCRINT, PRICE, YIELD, DURATION and MDURATION also use the same full token inside
accrued-interest periods, coupon-price sums, YIELD price/slope valuations and duration
cashflow sums. Cancellation propagates through the real fallible helpers and escapes
before numeric-result boxing. Numeric formulas, traversal order, solver guesses,
iteration counts and ordinary error results stay unchanged. Calendar/schedule helpers,
allocation internals and other financial builtins still contain unpolled work; this is
not a hard time bound.

NETWORKDAYS, WORKDAY and their .INTL variants poll the same full caller token
while collecting holiday arguments, range slices and cells, recursive array cells,
and each day they visit. Their private helpers return typed cancellation through
all four evaluators, before result boxing. Calendar arithmetic, weekend masks,
holiday coercion and ordinary skipped range errors are unchanged. Holiday sorting,
allocation and other calendar/financial work still have unpolled spans; these are
cooperative checks, not a hard time bound.

DB, VDB and AMORDEGRC poll that same full token in their period-by-period
calculations. Both VDB switch/no-switch paths and its two real helper calls carry
typed cancellation through the evaluator before numeric-result boxing. Numeric
formulas, period/fraction handling, switch rules, rounding and ordinary errors
stay unchanged. Their intake/allocation internals and other financial builtins
remain outside this cooperative coverage.

ODDFPRICE, ODDFYIELD, ODDLPRICE and ODDLYIELD carry the same full token
through coupon-date walks, quasi-period counts and odd-coupon valuations.
ODDFYIELD propagates cancellation from each price and finite-difference slope
valuation, not only between solver iterations. Typed cancellation leaves all
four evaluators before numeric-result boxing. Date rules, coupon arithmetic,
iteration order and ordinary errors stay unchanged. Intake, allocation and
remaining financial work still have unpolled spans.

The twelve database D-functions capture that token once in their four shared
evaluation paths. Header lookup, criteria parsing and row matching poll it at
natural column, criteria and row boundaries. Their sum, product, extrema, mean
and variance passes poll the same token without changing numeric order or
ordinary criteria/error behavior. Cancellation returns through the native error
path before result boxing. Range materialization, individual cell/predicate work
and allocation remain outside this cooperative coverage.

SUMPRODUCT captures that full token once and polls at argument, range-row,
row, column and inner multiplication boundaries. SUMIF, SUMIFS, COUNTIF,
COUNTIFS, AVERAGEIF and AVERAGEIFS reuse it through their shared evaluator's
criteria intake and fallible chunk, column, fallback-cell and matched-error
scans. Cancellation follows the native error path before scalar-result boxing.
The range iterator's separate cancellation flag remains in place. Arithmetic,
criteria, cache and ordinary-error order stay unchanged. The shared evaluator
also polls the same borrowed token for each mask-count value, logical-tail
criterion and scalar-fallback criterion. Mask counts keep the same validity/value
checks and integer cast; logical-tail matching keeps its COUNT-only evaluation
and first-false short circuit. Arrow kernels, individual cell/predicate work,
prior row buffering and allocation still have unpolled spans.

Cached criteria-mask construction carries that same borrowed token through its
existing get/build/memo path. It polls tag, chunk, row and null-fill traversal.
Cancellation returns a typed error; ordinary unavailable masks and Arrow errors
still return no optimized mask and use the existing fallback. Only a completed
build result enters the memo, preserving cached masks and cached unavailability.
Numeric, blank/text, predicate and cache-key semantics stay unchanged. Arrow
kernel internals, individual cell/predicate work, buffering and allocation still
have unpolled spans; this is not a hard time or heap bound.

COUNTA and COUNTBLANK capture the same full caller token once per evaluation.
Their argument, range-chunk, column and cell walks poll it, including cells
inside an iterator chunk. COUNTBLANK also polls before counting the unvisited
logical tail; both functions poll before numeric-result boxing. Cancellation
uses the native error path. Counts, blank/text rules, reference and ordinary
error behavior, closed-workbook precedence and no-token behavior stay unchanged.
This does not cover Arrow kernel internals, buffering, allocation, remaining
builtins or all native work-budget and hard-time spans.

MAP, BYROW and BYCOL capture that full caller token once per evaluation and
poll their natural argument, row, column and cell walks before result boxing.
MAP also polls each input binding; BYCOL polls each row copied into a column.
Their shared private invocation helper propagates native cancellation errors
instead of boxing them as ordinary error cells, including on the final call.
Ordinary errors still become the same cell values. Broadcasting, range-origin
bindings, blank-to-zero and nested-array rules, traversal order and normal
no-token execution stay unchanged. Grid materialization internals, cloning,
allocation and the other LAMBDA helpers remain outside this partial coverage.

XLOOKUP and XMATCH capture the full caller token once for each value or
reference evaluation and borrow it through their local searches. Their empty,
exact, wildcard, approximate and sorted-verification walks poll at each entry;
XLOOKUP also polls its output row and column walks before result boxing.
Native cancellation from argument-range reads stays a typed error rather than
an ordinary error cell. First/last selection, numeric and blank-tail rules,
reference and fallback results, ordinary error cells and no-token behavior stay
unchanged. Existing lookup-index and forward Arrow paths remain in use with
checks around the call, not inside their cache-build or kernel internals.
Individual cell work, allocation, other lookup functions and native work-budget
and hard-time coverage remain partial.

FILTER and UNIQUE capture that full token once after their original input and
shape/flag checks. FILTER polls include flags, rows and every candidate output
column. UNIQUE polls each input line and cell, key construction, retained-line
selection and output transposition. Both poll before final result boxing.
UNIQUE keeps native cancellation from range/flag argument reads distinct from
ordinary error cells, including value-level errors passed to flag coercion.
The range-read guards for UNIQUE, XLOOKUP and XMATCH consult the argument's
cached resolution so a stored scalar cancellation error remains a cell value,
not a new evaluation cancellation; this does not evaluate the argument again.
Selection order, case/numeric keys, duplicate counts, eager ordinary flag checks,
blank and error behavior, fallback values and no-token execution stay unchanged.
Individual cell reads, string conversion, hashing, cloning and allocation still
have unpolled spans; this is not full native work-budget or hard-time coverage.

RANDARRAY and SEQUENCE capture the full caller token once after their original
argument, dimension and generated-cell checks. They poll at each row and cell,
and before final result boxing. SEQUENCE also polls before its outer allocation.
RANDARRAY keeps its single RNG-counter advance and the same row-major draws;
SEQUENCE keeps its original numeric expressions and accumulation order.
Defaults, ordinary errors, existing size guards and no-token behavior stay
unchanged. Individual RNG and cell operations, allocation, coercion and boxing
internals still have unpolled spans; native work-budget and hard-time coverage
remain partial.

TRANSPOSE, TAKE and DROP capture that full caller token once after each
function's original shape and selection checks. They poll before allocating
the output, through the existing row and column walks, and before result
boxing. Native cancellation from the array argument stays a typed error;
a cached stored scalar cancellation error remains a cell value without
another evaluation. Transpose orientation, selected windows, signed counts,
omitted columns, empty results, ordinary errors and regular no-token execution
stay unchanged. Cell reads, range materialization, cloning, allocation and
boxing internals still have unpolled spans; native work-budget and hard-time
coverage remain partial.

HSTACK and VSTACK capture the full caller token once before argument intake and
poll each argument, before output allocation, through their output collection,
and before final result boxing. HSTACK also polls every copied cell; VSTACK
polls each row callback and propagates its typed cancellation error instead of
ignoring it. Native cancellation from a range argument exits before scalar
fallback; stored scalar error values keep their original fallback path. Empty
inputs, shape checks, concatenation order, original buffers and regular no-token
execution stay unchanged. VSTACK's row buffering and cloning, range resolution,
individual cell operations, allocation and boxing still have unpolled spans;
native work-budget and hard-time coverage remain partial.

CHOOSECOLS and CHOOSEROWS capture the full caller token once after their
original argument-count, source conversion and empty-shape checks. They poll
index intake, before output allocation, at each selected row and cell, and
before final result boxing. The original native error propagation from source
and index evaluation stays in place. Index error values, signed indexing,
truncation, duplicate selection, output order, capacities and regular no-token
behavior stay unchanged. Source resolution, cell reads, cloning, allocation and
boxing still have unpolled spans; native work-budget and hard-time coverage
remain partial.

TOCOL, TOROW, EXPAND, WRAPROWS and WRAPCOLS reuse one full caller token through
their materialization, flattening, wrapping and output walks, with checkpoints
at row/cell boundaries and before result boxing. Their private error carrier
keeps native evaluation cancellation distinct from stored error values: only
native cancellation exits as a typed error; stored cancellation errors and all
other errors keep their original result path. Ignore modes, scan order, ragged
blank/pad behavior, omitted sizes, truncation, dimension checks, padding,
original buffers and regular no-token execution stay unchanged. Row buffering,
width scans, individual reads/coercion/cloning, allocation and boxing still have
unpolled spans; native work-budget and hard-time coverage remain partial.

REDUCE, SCAN and MAKEARRAY capture the full caller token once after their
original initial-value, callable or dimension checks. They poll each row and
cell and before final result boxing. Their private invocation helper keeps a
native callable cancellation as a typed error without changing stored error
values or ordinary-error boxing. Uncancelled calls keep the same invocation
order and count, accumulator/shape rules, numeric expressions and buffers.
The existing aggregate invocation and ordering paths are unchanged and remain
outside this slice. Input materialization, individual invocation/read/clone
work, allocation and boxing still have unpolled spans; native work-budget and
hard-time coverage remain partial.

SORT and SORTBY capture the full caller token once and poll criterion intake,
row/cell extraction, ordering, reconstruction and final result boxing. With a
token, a private stable index merge keeps cancellation fallible through each
merge/copy and permutation step. It uses two additional index vectors; their
capacity and native allocation are not a proved heap floor. Without a token,
the original standard stable sort remains in place. Literal ordering, selected
rows/columns, criterion priority, stored errors and ordinary-error boxing stay
unchanged. Native argument cancellation remains a typed error. Date-system
lookups remain at the original comparison sites; no volatile callable path is
changed. Individual comparison/read/clone work, allocation and boxing still
have unpolled spans; native work-budget and hard-time coverage remain partial.

GROUPBY and PIVOTBY capture the full caller token once at entry. Their main key-loop
poll follows the original grid, shape, callable, header, sort/filter and
relative-selection checks. Selected key, membership, aggregation and output
walks poll that borrowed token, and the non-sort aggregation calls keep raw
callable cancellation typed. A private error-origin carrier keeps stored value,
coercion and ordinary errors boxed, including stored cancellation errors. Direct
checkpoints, native argument cancellation and raw non-sort callable cancellation
use the distinct native channel.
Uncancelled invocation count/order, both standard sorts, lazy PIVOTBY totals,
ordinary errors, numeric rules and output shapes remain unchanged. Result
collection and incremental line assembly need not keep identical allocator
specialization or capacities; this is not a heap-floor claim. Sort-path callable
cancellation, input materialization, distinct-key/axis construction, sort-only
columns, individual reads/clones, allocation and boxing retain unpolled spans. Native
work-budget and hard-time coverage remain partial.

Non-sort GROUPBY and PIVOTBY aggregation also passes that same borrowed token
through column construction. It polls before the original row collection, at
each row and before boxing that column; both argument columns retain their
original left-to-right order. Stored cell errors remain values, while a direct
checkpoint error follows the existing native-only channel before invocation.
The original sort-only column builder is unchanged. Collection specialization
and capacities are not asserted equal; individual cell reads/clones, allocation
and sort-path work retain their unpolled spans.

GROUPBY and PIVOTBY retain native cancellation from grid, optional-value and
callable argument intake as a typed error. After the same range resolution,
the existing borrowed cached scalar-error predicate separates a stored error
from native cancellation without evaluating or cloning the argument again.
Optional-number and sort-order coercion errors keep the value channel, as do
stored error cells and every ordinary error. Validation order, omitted values,
header/filter/relative settings and numeric rules are unchanged. Range-row
iteration, individual materialization/read/clone/allocation work and volatile
sort invocation remain outside this native-error intake slice.

GROUPBY and PIVOTBY also borrow that same token through all five grid-intake
calls. After the same range conversion, their local buffered row walk polls
before collection, at each row and cell, then before the existing row clone and
push. It keeps the original row/cell order, buffer capacity/reuse and cell/row
clone count. Direct checkpoint errors enter the native channel; stored cells
remain data and ordinary errors remain boxed. Uncancelled argument and
validation order, both sorts and numeric rules remain unchanged. An individual
cell read, clone or allocation, and sort-path work still have unpolled spans.

GROUPBY and PIVOTBY keep that borrowed token through filter-row selection,
first-appearance key identity, non-comparator parent-position/rank construction,
axis labels and subtotal membership, gathered row membership and PIVOTBY
membership intersections. These checkpoints return native cancellation;
filter cells, length/empty-filter errors and ordinary coercion errors retain
the value channel. Uncancelled key order, filter/header/depth rules, labels,
subtotal placement, numeric expressions and callable invocation order/count
remain unchanged. Both standard key sorts and their lazy aggregate callbacks,
and the pure row-index sort, keep their original bodies. Those sorts,
individual leaf key/string operations, atomic clones and allocations still
have unpolled spans. Result collectors and manual
membership assembly need not keep the same capacities or specialization; this
is not a heap-floor, work-budget or hard-time claim.

Non-comparator parent-prefix scans now poll at each ordered candidate, and
prefix equality polls each zipped key part while keeping its original
short-circuit and left-to-right identity comparisons. Parent rank still uses
the minimum matching position, or zero for no match. Filter-array flattening
polls each input row and moved value in the original order; stored filter
errors still use the value channel during selection. These loops use the same
borrowed token and native checkpoint channel. Sort comparators and lazy
aggregate calls remain untouched. Individual key/string operations, moved-value
or row clones, and allocation are not made interruptible; no new heap floor,
work-budget or hard-time guarantee is claimed.

GROUPBY and PIVOTBY also poll that token while finding grid widths, flattening
and coercing sort specifications, validating each sort column and assembling
header/detail cells. PIVOTBY relative-row copies poll each copied index after
selecting the same source rows. Grid-width maxima, specification truncation,
validation short-circuit, header labels and row-copy order stay unchanged.
Raw argument cancellation keeps its existing native channel; stored spec and
coercion errors remain values, and stored header/detail cells remain data.
New direct checkpoint errors use the native channel. These loops add no
callable invocation, argument evaluation or token capture. Individual
cell/string/coercion/formatting/clone operations, allocation and sort-path work
retain unpolled spans; collector specialization/capacities are not asserted
equal, and heap-floor, native work-budget and hard-time coverage remain partial.

GROUPBY and PIVOTBY also poll the same token before each outer grid-row and
new distinct-key element clone, while initializing order, default sort columns
and position indices, and while copying grand-total key indices. Each stored
cell is cloned once in the same order, including error-valued cells as data.
Grand-total labels are still built before their key copies. Both standard
sort bodies and lazy aggregate callbacks remain unchanged. Recursive
LiteralValue, string and error clones outside these copies, and allocation,
remain unpolled spans. Collector specialization/capacities are not
asserted equal; heap-floor, native work-budget and hard-time coverage stay partial.

PIVOTBY blank header prefixes now poll the same token between copied cells.
They still evaluate one blank seed even for an empty prefix; nonempty prefixes
clone it for all but the final slot, which takes the original seed. The owned
grid-row and new distinct-key copier also polls inside nested array rows/cells
and text characters. Text copies preserve the original UTF-8 bytes in order;
other values, including stored error cells, keep their original data clones.
These checks use the native error channel without another token capture or
callable invocation. Header overwrites, labels, numeric rules and both standard
sorts with their lazy aggregate callbacks remain unchanged. Allocation, error
clones and other materialization/clone/sort paths remain unpolled spans; this
is not complete heap-floor, native work-budget or hard-time coverage.

GROUPBY and PIVOTBY reuse the same nested/text copier for non-sort key, header,
axis-label and detail-output cells, and for cancellable aggregate columns.
Missing cells still yield Empty and stored error cells remain data. The native
copy primitives return checkpoint errors directly; their callers keep the
existing native-versus-value boundary. Aggregate arguments are still built
left to right before the original single invocation. Automatic header
detection borrows the same first two cells, with the same nonempty-text then
number test and short-circuit, instead of cloning their contents. Membership
buckets poll the same token while initializing each empty per-key vector.
Both standard sorts, the original sort-only cell/column/apply path, lazy totals
and numeric/index rules remain unchanged. Other materialization, allocation,
error-clone and sort spans still prevent complete heap-floor, native work-budget
or hard-time coverage; collector capacities/specialization are not asserted equal.


Argument reference-or-value resolution keeps its original resolution and cached
error channels. It populates the value cache only when that cache is empty,
so an already-cached value is not deep-cloned for a cache insertion that would
be rejected. The resolution's own clone and first cache insertion remain;
this does not add a cancellation poll or complete materialization coverage.

Owned-row conversion also borrows its existing full cancellation token into the
row builder and checks it before each cell's format/tag/value conversion.
The original per-row check stays first. Cancellation drops the local builder
before a sheet is published; uncancelled callers keep the original row
format, stored-error codes and lane order. Initial builder construction now
checks the same borrowed token before each column's empty chunk, lane builder,
format vector and count/reserve entry, in the original separate passes.
Deferred provisioning checks it before each column's original six assignments.
The ordinary constructors and appenders still use no token. Raw initial
chunk capacities and the stored minimum-one chunk size are unchanged; vector
capacity/specialization equality is not claimed. Width discovery checks the
same existing token before reading each row's length, with the same maximum
width. Padding keeps the original reserve, one Empty seed, n-1 clones and final
seed move, with a check before each inserted cell; the seed is still made for
zero padding. The original per-row check and subsequent cell conversion stay
in order. The same borrowed token also reaches automatic and final chunk
flushes, with a check before each column is finished. Final sheet construction
checks before each column and each chunk-layout validation iteration. Ordinary
finish and append callers still use no token. Native cancellation drops the local
builder or partial sheet before publication; stored errors remain data. Format-run
construction borrows the same token for its all-General scan and ordered run
encoding pass. It keeps the first-non-General short circuit, run ends and format
ids, while ordinary callers still use no token. Native owned-row text copying
checks the same borrowed token before each original UTF-8 character slice and
closes the single Arrow value once. Without a token it keeps the original single
append. Empty text still creates one entry. Cancellation drops any unfinished
text bytes with the local builder before publication. Ordinary text appenders
remain unchanged. Owned numeric-result normalization checks the same optional
token while scanning columns and array items, including nulls, and before each
row allocation and cell read during rebuilding. It keeps the first-change short
circuit, normalization rule, row-major order, stored errors and linked reference.
Borrowed ranges still return unchanged; without a token the original iterator
scan remains. Shared row-chunk construction and all six typed slice projections
check the same token before each original column's lane, null and overlay work.
Cancellation uses the existing fallible stream and drops the local partial output
vector. Indexes, missing-column branches, base/overlay order and no-token results
stay unchanged. Earlier lazy cache entries remain owned by the original sheet.
Lowered-text slices also lend the same token to each original lower-cache row.
Cache hits keep their fast return; cancellation drops the unfinished local text
builder before cache insertion. With a token, each character is folded by the
same Unicode-simple and sigma mapping and written directly to the text builder,
with a check before each character. The ordinary no-token path keeps its original
whole-string fold and single append. The three ordinary data-returning calls
keep the uncancelled wrapper. Nulls, Unicode case-folding and the original cache
race stay unchanged. All six fallible typed projections lend the same token
to partial-overlay mask and value building, with a check before each original
row. The lowered-text point-scalar fallback also checks before each original
row. Ordinary data-returning selectors keep their uncancelled wrappers.
Precedence, row order, nulls, base fallbacks and overlay statistics stay intact
when not cancelled. The same token also reaches all six overlay layer scans.
Each fragment and point is checked before its original filter or read; sparse
and dense payload rows, run headers and run payload rows are checked before
visiting the original values. The visitor returns native cancellation through
the same single layer walk. Computed/user and fragment/point order stay unchanged. The six
fallible projection guards and selector discovery paths also lend that token to
overlay-presence and full-cover scans. Each original point and fragment is
checked before its filter, with the original short circuits and user/computed
order. Ordinary discovery calls keep their uncancelled wrappers. All six typed
run fast paths now check that token before each original run header and repeated
row append. The value conversion or fold still happens once per run. A fallible
callback returns native cancellation through the same single walk and drops
unfinished local builders before publication. No-token results, nulls, type tags,
row order and statistics stay unchanged; previously owned sheet caches remain.
The dense lowered-text fast path also lends the same token to its materializer,
with a check before each original payload row, including nulls. Its window,
conversion and fold expressions stay unchanged. Cancellation drops the local
unfinished builder before publication, while ordinary no-token results remain
unchanged. Run-text, run-lowered-text and dense lowered-text copies reuse the
existing cancellable text appender. With a token, it checks before each UTF-8
character slice and closes one Arrow value after the copy. Without a token,
it keeps the original single append. Empty entries, nulls and conversion or
folding once per run or dense row stay unchanged.
The two fallible lowered-text materializers also lend the same token to payload
text folding. With a token, each original character is checked before the same
Unicode-simple and sigma mapping is pushed into the local string. Without a
token, the original whole-string fold and ASCII fast path remain. Missing tags,
nulls and non-text conversions stay unchanged. Fragment-layer readers also
lend that token to lowered payload folding. A fallible value provider and
visitor propagate cancellation through the original single walk, preserving
other typed value expressions and computed/user, fragment/point order.
Ordinary no-token results remain unchanged. Point-overlay and point-scalar
fallback text folding now use the same cancellable string supplier as payload
folding, with the same borrowed token and character mapping. Existing scalar
no-token entrypoints retain their results; borrowed scalar lookup, masks, nulls,
computed/user precedence and statistics remain unchanged. Native cancellation
drops local strings and unfinished outputs before publication, leaving prior
sheet-owned caches and stored error-cell data intact. The partial-overlay and
point-scalar fallback selectors also reuse the existing cancellable text appender
for their local string-to-Arrow copies. With a token, each original UTF-8 slice
is checked before writing and each value closes once. Without a token the
original single append remains; empty values, nulls, masks and order stay intact.
The ordinary-text partial-overlay selector also uses that same appender at its
original output-copy site. Existing token threading, no-token selector results,
row checks, slot values, masks, nulls, precedence and statistics stay intact.
The token-bearing old-value reader also checks before each original reverse-fragment
attempt. It keeps the same single walk, point-first priority, first present value
(including Empty), null fallthrough and user/computed/base order. Cancellation
returns before the current delta or graph update, leaving paid prefixes and owned
caches intact. Token-absent reads keep their scalar chain. Individual fragment
searches, point lookup, allocation and finishing remain unpolled spans.

Spill clearing copies its original target-cell slice with the same borrowed token,
checking before each cell copy. The original paid-prefix flush still runs first.
Cancellation drops the local partial list before snapshots, delta recording,
graph clearing, overlay mirrors or the change log. Token-absent copying keeps
the original slice clone; missing and empty lists keep their results. Later
snapshots, cell reads, clearing, mirroring and allocation remain unpolled spans.

The spill-clear change-log snapshot also carries that token through its target
copy, cell reads and output rows and cells. Its fallible cell reader keeps the
public format lookup, temporal egress and normalization, not just the raw cell
value. Snapshot text copies reuse the original cancellable literal copier.
Missing and empty snapshots, the existing truncation after copying, cell and
rectangle order, and ordinary token-absent reads stay unchanged. Cancellation
drops local snapshot work before delta recording, clearing, mirrors or logging;
other snapshot callers retain their token-absent wrapper. Hashing, allocation,
nontext clones and later mutation work still contain unpolled spans.

Spill committing prepares both owned copies of its two-dimensional values with
that same borrowed token before committing. Each original row and cell copy
checks cancellation, and text uses the existing cancellable literal copier.
The spill guard, paid-prefix flush and old snapshot still run before the new
fallible preparation. Token-absent calls keep their original first clone before
the callee and second clone at the original commit point. Cancellation drops
local copies before the commit and its change-log record; no new check splits
paired mutations. Nested nontext clones, allocation and later mutation work
still contain unpolled spans.

The spill-commit change log also prepares its original target-cell list with
that token before committing, after both value copies. It reuses the existing
ordered cell-copy helper and moves the finished list into the later record.
Token-absent calls keep their original post-commit clone, and calls without a
change log do not copy this list. Cancellation drops local preparation before
the commit, never between its paired mutations or before the later log record.

Spill committing also passes the active token into the old change-log snapshot
at its original preparation point, after the guard and paid-prefix flush and
before the value and target-cell copies. Token-absent calls keep the ordinary
snapshot wrapper, and calls without a change log still skip the snapshot.
The existing snapshot keeps its public format and temporal conversion, missing
and empty results, truncation after copying, and cell and rectangle order.
Cancellation drops local snapshot work before the commit; no new check splits
paired mutations or the later log record.

Individual allocations, numeric string conversions and writes, null-array
construction, fragment partition and interval checks, layer value reads and
clones, zip selection, cell clones, Arrow finishes and reserves still contain
unpolled spans.

GCD and LCM poll the same full token through argument reduction and their
Euclidean recursion. COMBIN, PERMUT, FACTDOUBLE and COMBINA poll their product
loops. SUMSQ polls argument and range-cell traversal. SUMX2MY2, SUMX2PY2 and
SUMXMY2 poll their shared numeric input collection and pairwise reductions,
retaining Rust's original sum path rather than a different floating accumulator.
Typed cancellation exits before ordinary result boxing. Numeric expressions,
coercion, limits, rounding and evaluation order stay unchanged. Range/input
materialization, individual cell operations, allocation and other numeric
builtins remain outside this cooperative coverage.

MULTINOMIAL polls that full token through argument and range-cell intake,
value conversion, its original integer-sum path and denominator traversal.
SERIESSUM polls coefficient intake and its original power-series accumulation.
MIN and MAX poll argument, slice, column and error-lane cell traversal before
calling their unchanged Arrow kernels. Typed cancellation leaves through the
native error path before result boxing. Numeric order, error precedence absent
cancellation, coercion, ignored values and result-format selection are unchanged.
The bounded factorial helper is unchanged. Literal-array flattening, Arrow
kernel internals, individual cell/conversion work and allocation still have
unpolled spans.

The recalculation behaves like Excel recalculating at edit time. Its caller passes a
`RecalcClock`: the instant NOW() and TODAY() read (sampled once, so every call agrees), the
local UTC offset their date and time use, and the seed of RAND, RANDBETWEEN and RANDARRAY. The
core takes it from the host session (`EditSession::recalc_clock`), else samples the host's
clock, its local offset and a fresh seed from the operating system when the recalc runs,
which is what the host's own recalc reads. The same clock and seed recalculate the same
bytes. Like the clock, where the workbook was opened from belongs to the host: the caller may
pass a `DocumentLocation`, the folder as Excel for Windows prints it with its trailing separator
and the file's name (`C:\Reports\` and `Budget.xlsx`; `DocumentLocation::from_path` splits
`C:\Reports\Budget.xlsx`), and the core takes it from the host session
(`EditSession::recalc_location`). CELL("filename") then prints Excel's text,
`C:\Reports\[Budget.xlsx]Sheet1` for the reference's sheet, and CELL("address") of another
sheet's cell names the file, `[Budget.xlsx]Other!$B$2`, quoted as Excel quotes it
(ops/excel-hostinfo-probe-20261008.md). Without a location the recalc reads the one Excel last
saved: the workbook's own cached CELL("filename") values, when each names a folder, a file and
one of the workbook's sheets and they agree; a workbook that reads its location and has neither
falls back. OFFSET, INDIRECT (A1 and R1C1 text) and CELL's `col`, `contents`, `row` and `type`,
`address` of a reference written without a sheet and text that is no info type (`#VALUE!`), and
INFO's `memavail`, `memused` and `totmem` (`#N/A`) and text that is no type (`#VALUE!`), read
the workbook alone and recalculate natively. A defined name evaluates for the formula that uses it, as Excel
evaluates it: relative R1C1 text and ROW() in a name read the calling cell
(`Prev = INDIRECT("RC[-1]",FALSE)` in B2 reads A2), and a random call in a name is one more
draw of the calling formula, so the same clock and seed still recalculate the same bytes.

The host's own recalc (LibreOffice headless in production) is the precision fallback for
refused workbooks only. The adapter refuses, before any output:

- the external links the engine cannot read as Excel does with the linked workbook closed (see
  "Linked workbooks" below); `preserve_external_links` refuses host output that alters or drops
  a link;
- a formula, in a cell or a defined name, that reads what only the host knows: INFO's
  `directory`, `numfile`, `origin`, `osversion`, `recalc`, `release` and `system` (the
  application that calculates) or a computed INFO type; CELL without a reference (the active
  cell), with `"format"`, `"color"`, `"parentheses"`, `"prefix"`, `"protect"` or `"width"` (cell
  formatting the engine does not model), with a computed info type, or passed by name
  (`_xleta.CELL`); and CELL with `"filename"`, or with `"address"` of a reference that names a
  sheet or is computed, when neither the caller nor the workbook's caches give the location
  (above). Each reason names the call;
- INDIRECT text that names a workbook (`'[Book.xlsx]Sheet1'!A1`, `Book.xlsx!Total`), literal
  or computed: Excel reads it from that workbook when it is open, this one under the name it
  was saved with, which the recalc does not know. The writer refuses the workbook as soon as
  evaluation meets such text, whatever IFERROR makes of the closed workbook's `#REF!`;
- an Excel function the engine does not implement, after the `_xlfn.`/`_xlws.` prefixes
  resolve as the engine resolves them, where the engine would cache `#NAME?`: a bare name of
  the Excel 2007 file format's functions (with the bare names the fork's list lacks, from
  LibreOffice's and Apache POI's function tables: DBCS, the name a file gives JIS, USDOLLAR,
  YEN, DATESTRING, NUMBERSTRING, the Thai functions and EUROCONVERT), one written `_xlfn.` or
  `_xlws.`, one passed by name (`_xleta.`), or an Excel 4.0 macro function a defined name may
  call (any `GET.` name, `EVALUATE`, `FILES` and the others);
- a call that Excel may resolve through code the file does not carry: an XLL add-in's
  function (`_xll.Foo`), and, in a package holding a VBA project (`xl/vbaProject.bin`, or any
  part typed `application/vnd.ms-office.vbaProject`), any called name the engine does not
  resolve, which Excel with macros enabled would call. Every other called name is outside
  Excel's function list as the file spells it (`IMAGE` without `_xlfn.`, `EOM`, a VBA
  function saved in an `.xlsx`, Google Sheets' `__xludf.DUMMYFUNCTION` and `arrayformula`):
  Excel for Windows reads it as an undefined name, `#NAME?`, whatever the call's arguments
  hold, which IFERROR and the criteria functions see, and the engine does the same natively,
  in a cell or a defined name. Excel saves `ca="1"` on such a formula only when it evaluated
  the call; the writer flags every formula holding one, so a call in an IF branch Excel does
  not take is saved calculate-always where Excel saves no flag, as a volatile call there is
  (the cached values agree);
- a workbook name used as a function: a defined name that holds a LAMBDA, a name passed where
  MAP, REDUCE, SCAN, BYROW, BYCOL, MAKEARRAY, GROUPBY or PIVOTBY take their LAMBDA, a
  defined name called like a function, or a linked workbook's name called as one
  (`[1]!Fn(1)`, as Excel writes an add-in workbook's function). The engine does not resolve
  workbook LAMBDA names yet and would cache `#NAME?`; LET names and LAMBDA parameters stay
  native;
- a shared or inline string whose OOXML escapes the writer's reader (Calamine 0.36) decodes
  differently from Excel: it decodes `_x00HH_` but keeps `_x20AC_` (the euro sign) as seven
  characters. It decodes no escape in a literal `t="str"` value, a cell formula, a defined
  name or its formula, or a sheet, table or table-column name, so any escape there falls
  back (`"_x20AC_"` in a defined name is `"€"` to Excel);
- under "Set precision as displayed" (`fullPrecision="0"`), a number format whose stored values
  the writer does not know: one Excel will not open a workbook with (a lowercase exponent
  `0.00e+00`, `0.0@`, `@;0`, `0;0;0;0`, `# ?/100000`, `0.0 ?/?`, `E+0`, `[Foo]0`, `[Red][Blue]0`,
  three conditions, a bare `g`, more than 126 characters), a scientific format scaled by a comma
  (`0.0,E+0`), a fixed fraction denominator past 32768 (Excel stores those unrounded or by another
  rule), a style or format id the workbook does not define, a section of literal text only
  (`0;"none"`) that a formula's number would show, and a number its format rounds past the largest
  double (Excel saves `#NUM!` for it, yet compares the cell as a number); and a live circular
  reference (Excel keeps the saved values of the cycle and of every formula reading it). The last
  three are refused after evaluation. The writer otherwise stores each formula result as its cell's
  format shows it, as Excel for Windows does, and formulas read the stored value (see below);
- a formula longer than Excel saves (more than 8,192 tokens or 4,096 nested operations; the
  writer evaluates on threads with a stack for the longest Excel saves, 64 MiB in release
  builds), or one the parser cannot read (its own bound stops nesting past 72 frames, where
  Excel takes 200 nested parentheses);
- what the writer cannot write exactly, such as a dynamic array larger than its saved extent;
- a circular reference that only a spill reference's anchor closes (`ROWS(A1#)+1` in A1):
  Excel calculates some such formulas (that one is 2) and finds others circular
  (`SEQUENCE(ROWS(A1#)+1)`);
- a text join past Excel's 32,767 characters whose cut falls inside a character outside the
  Basic Multilingual Plane: Excel keeps half of that character, which the writer cannot hold
  (a join cut elsewhere keeps its first 32,767 characters natively, as in Excel);
- a result the host could not read back under its own limits, such as a worksheet whose new
  caches take it over the XML node limit;
- a recalculation the edit gate would refuse: one that changes `xl/richData/` (the rich value
  of a new `#SPILL!` or `#CALC!`), which the gate passes through byte for byte, or a changed
  worksheet holding a modern function without its OOXML prefix (the writer never rewrites
  formula text).

## Precision as displayed

With Excel's "Set precision as displayed" on (`<calcPr fullPrecision="0"/>`), Excel stores each
formula's numeric result as the cell's number format shows it, and every formula that reads the
cell reads that stored value; constants keep the values the file holds. The writer does the same,
as measured on Excel for Windows 16.0.20430 (532 cases, `ops/excel-precision-probe-20261008.md` in
the calc workspace): General, text (`@`), empty and date or time sections keep 15 significant
digits (`=1/3` is 0.333333333333333; a value exactly halfway goes toward zero, 100000000000001.5 is
100000000000001); a number section keeps the decimal it shows after its percent signs and scaling
commas, rounded half away from zero from the 15-digit value (2.675 under `0.00` is 2.68); a
scientific section keeps one more significant digit than its decimal places, and two more for each
percent sign; a fraction section keeps the whole number plus the fraction it shows (Excel's
continued-fraction convergent, not always the closest fraction; a fixed denominator up to 32768,
`# ?/05` being fifths); a positive value takes the first section and a negative one the second,
whatever their conditions, and the last of two or three sections holding `@` formats text only
(`0;@` stores -2/3 as -1); an empty section passes the value on to the next; a value below the
smallest normal double is 0. Each cell an array formula fills or
spills into is rounded by its own format, and a file's own definition of a built-in format id wins,
as in Excel.

## Linked workbooks

A formula names a linked workbook by its place in the workbook's `<externalReferences>` list
(`[1]Sheet!A1`), and the link's part (`xl/externalLinks/externalLinkN.xml`) keeps the values Excel
last read from it. With the linked workbook closed, Excel for Windows computes from those saved
values, and so does the engine: a saved cell is its value, a cell not saved is blank, a sheet the
link does not name is `#REF!`, and on a sheet Excel could not read at its last refresh
(`refreshError`), or saved nothing for, every cell not saved is `#REF!`. ROW, COLUMN, ROWS,
COLUMNS and INDEX go by the reference as written, and an ordinary formula intersects a linked range
with its own cell, written or returned by INDEX at a computed row. An approximate VLOOKUP, HLOOKUP
or MATCH bisects an open linked range as written (1,048,576 rows for `A:A`), passing over the
unsaved cells, blank or `#REF!`. `[0]` is the workbook itself (`[0]!Rate` is its own `Rate`,
`[0]Sheet1!A1` its `Sheet1!A1`). Such workbooks recalculate natively, and every link part, link
relationship and link content type, and every relationship part with an external target, stays
byte for byte (the edit gate checks the link join and the parts too). Evidence: probes 1 to 5 of
the fork's `ops/excel-extlinks-probe-20261006.md` (Excel for Windows 16.0.20430, 216 cases), the
links2 probes of `ops/excel-links2-probe-20261008.md` (167 cases) and the SpreadsheetBench
workbooks with links (Excel truth recorded with links not updated).

These forms keep the fallback, each with its own reason: a DDE or OLE link; a link part the check
cannot read, or one that links nothing it knows; an external relationship other than a hyperlink, a
link's path or a pivot cache's external source; a link list or link content type the edit gate
cannot join; link markup the engine's reader would read where Excel reads none (it matches the list
entry, the relationship, the cache's elements and their attributes by local name, so a vendor
extension's look-alike `u:cell` would replace a saved value); an OOXML escape in a linked sheet name
or a saved value (`a_x0001_b` is three characters to Excel, nine to the reader), or a saved value of
a type the reader takes otherwise (`t="s"`, a number that is not one); a reference by file name or
to a link the list does not hold; a name defined in the linked
workbook (`[1]!Rate`, `[1]Sheet1!Rate`); a 3D linked reference; a linked reference in a reference
operator (`:`, intersection, union), directly, through INDEX or through a name; a multi-cell linked
range passed on by a function that returns references (IF, CHOOSE, IFS, XLOOKUP, OFFSET, INDIRECT,
LET), or given to AREAS, RANK or GETPIVOTDATA, or standing as the whole formula; INDEX with one
position into a block (`INDEX([1]S!A1:B5,3)` is `#REF!` in Excel), directly or into what another
INDEX or a name hands on, or at a computed position that may be 0 in a range read only up to its
last saved cell (below) or reaching both edges of the sheet (`$A$1:$A$1048576`, which INDEX hands
on as the open `A:A`); `[0]!Rate` where the workbook defines `Rate` for a sheet too (the engine
reads the sheet's, Excel the workbook's); a linked reference, one cell
too, reaching a criteria function's range through INDEX, IF, CHOOSE, another function or a name
(Excel's `#VALUE!`; the engine computes it), or reaching ROW, COLUMN, ROWS, COLUMNS, ISREF, AREAS,
ISFORMULA, FORMULATEXT, SHEET or SHEETS through IF, CHOOSE or another function that hands it on as
values (INDEX hands on the reference); a linked reference bound to a LET name or a LAMBDA parameter;
and an open or very large linked range, read only up to the last saved cell (plus one `#REF!` on a
sheet with a refresh error), unless its function gives Excel's result from those cells: INDEX at one
cell, ROWS, COLUMNS, MATCH (exact or match type 1), VLOOKUP and HLOOKUP, SUM, AVERAGE, MIN, MAX,
PRODUCT, COUNT, CONCAT, the criteria functions' ranges (`#VALUE!` for any closed linked range), and
COUNTA where the unsaved cells are blank. Counting the unsaved cells, pairing the range with one of
another length, ROW over it, LOOKUP (which reads a result past the saved cells as blank where a
sheet with a refresh error has `#REF!`), XLOOKUP and XMATCH, and a descending MATCH (`MATCH(3,
[1]S!A:A,-1)` over 1 to 5 is `#N/A` in Excel, 5 in the engine, as over a local range) stay the
fallback's. A workbook name that reads a linked
workbook, itself or through another name, is checked where each formula uses it, as if its formula
were written there (`ROW(Chosen)` with `Chosen` holding `IF(TRUE,[1]S!$A$3)` falls back as
`ROW(IF(TRUE,[1]S!$A$3))` does). A name with a relative linked reference anywhere in its formula
(`IF(TRUE,[1]S!$A3)`) falls back wherever it is used, itself or through another name: Excel moves
the reference with the cell using the name, and the engine does not.

A package the retained OPC reader refuses fails outright, as before. Malformed workbook content,
linked or not, fails outright too, as it did before the writer: the adapter reads the workbook, its
relationships, the shared strings, every worksheet and every table a worksheet relates as the old
loader did, and refuses a missing, unreadable, off-grid or repeated cell address, a literal its type
cannot hold (a number that is not one, a boolean other than 0 or 1, a shared-string index past the
table, an inline string without its text), an invalid `date1904` flag, a broken sheet list, a
missing, non-numeric or repeated sheet ID, a repeated defined name or one scoped past the sheets, a
table part that is malformed XML, missing, unnamed, named twice, or whose range is unreadable or not
spanned by its columns, and a link part that is malformed XML. Valid content the writer does not
support (sheet ID 0, two header rows) still goes to the fallback. Every part the writer reads (the
workbook, shared strings, worksheets, each table wherever its worksheet's relationship puts it, each
link part, content types, styles, cell metadata and rich data) must fit the host's XML node and
depth limits, or the workbook fails outright. A relationship part that does not fit goes to the
fallback, as before: the link check fails closed.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.98): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 parts 1 and 3, the third, fourth and fifth parity loops,
stage 2's linked workbooks and caller-context functions, five commits picked from upstream's
`main`, and stage 2 wave 2: linked workbooks, host information, parsing and precision as
displayed), plus cooperative resource checkpoints, matrix builtin polls and financial solver polls, including YIELD and ODDFYIELD (FIX 186).
`docs/ops/forked-dependencies.md` records the fork branch, the rev and the patches.
Nothing of formualizer is vendored here.

The spill-effect path also prepares the inner commit's owned value copy with the
same borrowed cancellation token, after its existing spill guard and previous-cell
snapshot but before current delta records or spill-write invalidation. Row, cell
and text copies reuse the native cancellable copier. The two ordinary callers and
token-absent calls retain their original clone point. The prepared copy moves into
the existing commit; paired graph, formula-plane and overlay mutations stay
unchanged. Cancellation drops local preparation before those mutations; prior
reservations and paid prefixes can remain. Nontext clones, old-value reads,
comparisons, hashing, allocation and later mutation work remain opaque. Full
heap-floor, native work-budget and hard-time coverage remain PART.

The same spill-effect path polls each copied previous-spill cell at that list's
original position, after the inner guard and before the value preparation above.
It reuses the existing ordered cell-copy helper and capacity request. Missing and
empty lists keep their results; the two ordinary callers and token-absent calls
keep their original slice copy. Cancellation drops the local partial list before
current delta records, spill-write invalidation or core mutations. The remaining
steps and the guard and paid-prefix precedence stay unchanged.

The same spill-effect path also polls its original spill-change detection walk.
It keeps the previous-cell membership scan first and stops at the first change,
then scans target cells only if needed. New text copies, public old-value reads
and text comparisons use the existing cancellable primitives and the same
borrowed token. Missing values and stored error values keep their meanings.
All checks stay before spill-write invalidation and core mutations; ordinary
callers and token-absent calls keep the original short-circuit expression.
The separate delta loops, each membership lookup, nontext clones, hashing,
allocation and later mutation work retain opaque spans; full coverage is PART.

Within that previous-cell scan, each original target membership candidate now
checks the same borrowed token before equality. It still stops at the first
match, treats an empty target slice as missing, and stops the previous-cell scan
at its first missing cell. This replaces the original membership lookup; it adds
no second walk or collection. Ordinary callers and token-absent calls still use
the original expression. Separate delta loops, nontext clones, hashing, allocation
and later mutation work remain opaque; full coverage is still PART.

The spill-manager shim also polls its original final target-cell copy with that
borrowed token, at the old graph-commit argument position. Its existing plan and
value-blocker checks still run first. Copy failure and graph-commit failure both
reach the original single lock-release site. The core commit is not entered on
copy failure, but earlier reservations or spill-write invalidation can remain;
this does not add rollback. Ordinary callers and token-absent calls keep the
original slice copy at that position. Plan, blocker, allocation and later mutation
work still contain opaque spans; full coverage remains PART.

The same shim checks the borrowed token before each original target attempt in
its Arrow-canonical shape and blocker scans. The original plan still runs first;
anchor, existing-spill and formula skips retain their order. Cancellation releases
that anchor's reservation through the existing owner-release method and returns
before the target copy or graph core. The token-absent checks are no-ops, preserving
ordinary results and error order. Probe value copies, plan work, allocation and
later mutations still contain opaque spans; full coverage remains PART.

The raw Arrow value-blocker probe now returns a native operation error through
an explicit result channel. Only the already-cancellable spill-effect caller
uses the same borrowed token for the existing Arrow value reader. Native errors
release that anchor's reservation and return before the target copy or graph
core. Missing sheets and empty cells remain non-blockers; stored error values,
including the Cancelled cell value, remain blocker data. Ordinary and token-absent
calls keep the original getter and invariant check at the original probe phase.
The plan, skips and blocker order are unchanged. Earlier reservations or
spill-write invalidation may remain; this adds no rollback. Nontext clones,
plan work, allocation and later mutations retain opaque spans; full coverage
remains PART.

The cancellable spill path also checks the same token before each original
target attempt in the graph plan's shape and conflict scans, and before each
cell in spill-write rectangle invalidation. The ordinary plan entry point still
uses the same algorithm without a token. In the cancellable plan, the existing
native value-type discriminator answers the Empty-only blocker question without
materializing text, errors or nested arrays. Reserved type tags retain the
original discriminator's Empty meaning; stored errors remain nonempty data.
Token-absent calls keep the original owned value read. The token-bearing tag
check bypasses payload materialization and does not claim to preserve malformed
arena-payload panics. Original blocker order and diagnostics remain unchanged.
Cancellation can leave earlier invalidation rectangles or reservations in place;
no rollback or checkpoint inside the graph core is added. Hashing, allocation,
core mutations and other opaque spans remain; full coverage is still PART.

The graph commit's existing preparation prefix now accepts the same borrowed
caller token from the cancellable shim. Its original resource admission and
anchor lookup still run first. The previous-owner cell snapshot then uses the
existing cancellable cell copier. The two original membership-set collections
check the token before each ordered insertion attempt, with the same coordinate
hasher and input-length reserve. Ordinary calls retain their original snapshot
clone and collection expressions. Cancellation returns through the shim's single
lock cleanup before any graph mutation; earlier caller reservations or
invalidation rectangles may remain. The mutation, injected-fault rollback,
ownership and subsequent log paths stay unchanged and receive no new checkpoint.
Allocation, hashing, operation-list and old-value materialization, and the core
itself still contain opaque spans; full coverage remains PART.

The graph commit's operation-list and old-value preparation also poll that same
borrowed token before each original clear-cell, write-row, write-cell and
old-snapshot operation attempt, including empty write rows. Only token-bearing
calls use the existing per-character text copier at the original sheet-name and
Text-value copy positions. Ordinary calls keep their original string and value
clones. Old values still use the original reader before the tuple-key copy and
move into the rollback snapshot; stored Cancelled errors remain cell data.
Cancellation returns through the same single shim cleanup before graph mutation.
The apply, injected-fault rollback, ownership and later log paths are unchanged.
Earlier caller prefixes may remain. The copier allocates before its character
checks; nontext and nested-array clones, old-value materialization, allocation,
hashing and the core remain opaque. Full coverage remains PART.

The operation-list value copy also reuses the existing GROUPBY nested-literal
copier with that same borrowed token. Its body is unchanged; only crate visibility
and a lookup-module re-export are added. Token-bearing copies check at the value,
nested row, nested cell and text-character boundaries. Ordinary calls retain the
original value clone at the same operation argument position. Stored errors,
including Cancelled, remain cloned cell data; only checkpoint failures use the
native operation-error path. Sheet copies, old-value reads, mutation, injected
fault rollback, ownership and logging keep their prior paths. Error clones,
allocation, old-value materialization and the core still contain opaque spans;
full heap-floor, native work-budget and hard-time coverage remain PART.

The token-bearing rollback snapshot also uses a fallible graph-cache reader at
its original old-value read position. The original cache-disabled instrumentation
and sheet, coordinate, vertex and value gates keep their order; missing values
still become Empty at the caller. String materialization keeps the original
interner resolution and uses the existing cancellable text copier. Array
materialization keeps the original raw-reference array copy, then checks each
row and recursively materialized cell with the same token. Other value kinds,
including stored Cancelled errors, keep the original retrieval as cell data.
Ordinary calls retain the original public getter and Empty fallback. Native
cancellation returns before tuple-key copying and graph mutation; no mutation,
fault rollback, ownership or log checkpoint is added. The raw array copy,
lookups, allocations, error-message copies and scalar conversion remain opaque;
full heap-floor, native work-budget and hard-time coverage remain PART.

The token-bearing array materializer now borrows the original arena dimensions
and element slice instead of collecting an owned raw-reference array first. It
keeps the native dimensions-then-elements gates, zero-dimension empty result,
row-major slice arithmetic and same per-row, per-cell recursive checks. The
ordinary arena getter and raw-reference array getter remain unchanged. The
borrowed element slice stays live during recursive reads; destination row
allocations and element storage remain opaque. Cancellation may precede a later
corrupt-row panic; this does not repair corrupted offsets or promise identical
panic or callback order. Heap-floor, native work-budget and hard-time coverage
remain PART.

The token-bearing arena reader also keeps the original error-reference gates
while copying an error's stored message through the existing cancellable text
copier. The arena still reconstructs only the stored kind and optional message;
context and extra fields keep their original empty values. A stored Cancelled
error remains cell data. Only token cancellation during the message copy returns
a native error. Ordinary retrieval and the public error getter remain unchanged,
including missing-reference and original interner-resolution behavior. No graph,
mutation, fault rollback, ownership or logging path changes. Message allocation
and the remaining native spans stay opaque; full heap-floor, native work-budget
and hard-time coverage remain PART.

The corpus rule (default only at or above LibreOffice on the same corpus) is met at fork
rev `f01d8eff`: through the writer, all 2,967 scored fresh-Excel SpreadsheetBench
workbooks (truth recorded on Excel for Windows 16.0.20430; cells downstream of NOW/TODAY/RAND
skipped) are fully Excel-identical (LibreOffice 25.8 matched 2,648 of the 2,951 it was measured
on), and all 811 pinned native Excel goldens (recorded on Excel for Windows 16.0.20430; the
goldens reader resolves Excel's rich-value error caches since 2026-10-03), against
LibreOffice's 753 (the unchanged evaluator scored 754). The comparison uses a pinned UTC
instant; the edit round trip uses the caller's clock (above).

The shipped adapter on the same corpus (2026-10-08, `recalc_native` over the 5,455 saved originals,
3,040 of them with formulas; the retained OPC reader admits their ZIP directory entries): 3,008 of
the 3,040 formula workbooks (98.9%) recalculate natively, none is refused outright and 32 fall back:
15 for precision-as-displayed, 12 for CELL("filename") and 5 over the token bound. The 2,935 native
workbooks with scored cells match Excel (none of their 1,142,727 scored cells differs); the other 73
hold only cells downstream of NOW, TODAY and RAND, which the comparison skips. The 14 that fell back
for a linked-workbook form at 0.9.3-oneiron.11 recalculate natively and match Excel on all 99,158 of
their scored cells: 5 with a linked range INDEX selects at a computed row (444-14, 46444, 55965), 3
with an approximate VLOOKUP over an open linked range (59932, one on a sheet Excel could not
refresh) and 6 with `[0]` in a defined name (31746). The engine's `#REF!` reference operand and
`_xlfn.ANCHORARRAY` (fork `492b432a`) bring 14207 (names written over deleted ranges) and 49667
native too, all matching Excel. Of the 32 that fell back for an unregistered function before, 27
recalculate natively and match Excel on every scored cell, those calling the names too: 6 with
`IMAGE` written without `_xlfn.` (`#NAME?`), 3 with the VBA function `ClrCnt` and no VBA project
(`#NAME?`), 3 with `EOM` in a SUMIFS criterion (0), 6 with Google Sheets' `__xludf.DUMMYFUNCTION`
and 3 with its `arrayformula`, inside IFERROR (IFERROR's value), and 6 whose `TjDAY()` sits in an IF
branch Excel does not take (`""`). Of the 279 formula workbooks with external links or external
relationship targets, which all fell back before, 261 recalculate natively (none of the 621,009
scored cells of the 252 with scored cells differs from Excel) and 18 meet another reason (12
precision-as-displayed, 6 CELL("filename")); none falls back for a linked-workbook form. Of the 274
that fell back for caller context, 260 recalculate natively (the 6 that read the workbook itself
through `[0]` since 0.9.3-oneiron.12); 12 read CELL("filename") and 2 pass the token bound. The
checks for escaped names and formulas, related tables and malformed workbook metadata change no
corpus workbook's decision or output bytes.
CELL("filename") reads the caller's location, else the workbook's cached path (measured at fork
`d890db6d`, before the linked-workbook forms above: 6 of the 12 CELL("filename") workbooks then
recalculate past CELL and stop at the depth bound, and given the file the Excel truth was recorded
from, `recalc_native --location`, the 6 of SpreadsheetBench 342-46 recalculate natively and match
Excel).
The formula bounds admit every formula Excel saves (measured at fork `f01d8eff` before the
linked-workbook forms above, 2026-10-09): the 5 that fell back over the old token bound recalculate
natively and match Excel on every scored cell.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.98`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native
[--location PATH] INPUT OUTPUT` runs the shipped adapter on one workbook, with PATH the file as
the host that opened it names it (`C:\Reports\Budget.xlsx`), else without a location. It
writes the native recalculation and exits 0, or writes nothing and exits 3 when the adapter
refuses the workbook to the fallback, 4 when the engine fails (the round trip falls back too)
and 2 when the round trip refuses the package outright; stdout carries a JSON report with the
reason.
