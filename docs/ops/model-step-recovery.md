# Durable model-step recovery

`ai.steps.submit` checks the actual owner's saved step before it admits a
provider. A saved terminal, including a budget trap still waiting for its
answer, keeps the existing receipt path. The owner can also resume unfinished
work whose response was already saved at `ResponseReceived` or `Logged`, or
whose terminal claim was written before its submission receipt was committed.
Removing the configured model does not make that saved work need a new call.

Recovery matches the same owner's step key and frozen request/retry policy.
The comparison excludes only the host admission fields already bound in the
saved request, including the host-only keyless stamp. It uses the stored step
hash and stored request, not a hash or model binding recomputed from the
current configuration. A different request is not a saved-response hit.

The response is captured in the same write transaction that checks the saved
submission, before the existing attempt is claimed. A miss changes no attempt
or lease. A hit resumes that same attempt through the shared terminal writer
and submission finalizer. The response's original usage stays in its receipt;
recovery is memoized and creates no model backend, meter or budget admission.
Owner erasure still prevents a late terminal or submission from retaining the
response. No placeholder backend or zero-budget guard stands in for admission.

A new step, a Started-only checkpoint, an unavailable saved lookup or a
consumed budget trap with no saved response follows the existing inference
admission path. Exact-model selection, keyless/paid work attribution, the
physical run meter, logical allowance and retry policy are unchanged. No
current-format storage field, migration, default, cap or configuration is added.

## Exact terminal response identity

A finished step carries `StepReceipt` with the original attempt, request hash,
and actual committed terminal claim. Fresh and saved-response recovery use
that terminal writer's returned claim. A memo carries the claim selected beside
its response in the same read transaction. The submission result keeps that
claim; it does not replace it with a later memo-index lookup.

Post-terminal charge tallies, stored results, fallback output pins and wake
settlement retain this full identity. A checkpoint marks `(attempt, hash,
claim)` beside its budget charge in the same writer. A later terminal claim
for the same logical step cannot inherit an older claim's mark. Forgetting a
step's memo still forgets all its logical charge marks; attempt cleanup still
retires them. These content-class markers are not permanent financial facts.

A receipt is correlation data, not permission or proof of payment. A fallback
publication still checks the exact claim's trusted source and actor, active
status, response hash, current policy and stage in the governing transaction.
Pre-terminal outbound effect bindings and their existing checks stay separate.

### Original admitted-call coordinates

A successful native Dreamer admission freezes its original attempt id, native
`attempt_count` and budget line. Its cloned deadlines share one checked invocation
sequence. A fresh durable-step invocation takes its coordinate before requesting a
model lease; schema corrections keep that invocation and use their existing call
ordinal. Transport retries keep the same coordinate. A fresh guard's public lease
id is not a substitute for this original coordinate.

The existing owed-call row retains this coordinate beside the original line and
lease. It still coalesces by attempt and logical step, and ordinary settlement
still retires the attempt's rows. This extra provenance does not make that row an
irreversible paid fact or close the late-call accounting gap.

`BudgetGuard::accounting_snapshot` captures its total and selected native lease
states under one lock. A foreign lease with a matching public id has no
entry on that guard. The snapshot is accounting data, not a grant or proof that a
vault budget charge committed. Callers release the guard lock before any vault
writer runs; no caller callback runs inside it.
A settled lease's amount keeps its native settlement convention. It is not a
billing credit or proof that summing selected lease amounts reproduces a meter
delta, including at counter saturation.

### Retained native NET invoices

A separate private financial row retains each original admitted call by its full
attempt, generation, invocation and corrective ordinal. It is not another funding
reservation. The row freezes the original line, logical request hash and lease
metadata before bytes leave. This best-effort write is independent of the existing
owed-call writer; failure cannot prevent that original writer or the model call.

The physical response producer records `input.total + output.total` before schema
validation or corrective-response aggregation. A known zero stays a zero invoice.
An error without a response stays unknown, not a synthetic zero. Local responses
can have positive native NET usage while their guard charge is zero. These records
retain the quantity the response actually supplied; they do not prove that every
provider-reported or unreported expense is known.

The explicit payment primitive reads the retained line and invoice. Its existing
BUDGET money mutation and paid fact share one writer. It charges the line directly,
not a later generation's reservation or its owed sum. Repeating the same original
call finds its paid fact without charging again. These rows are live financial
state, excluded from checkpoint images, and are not removed by logical memo forget,
step-mark cleanup or ordinary owed-call retirement.

Automatic payment is not activated. Neither the response producer nor the wake
aggregate driver calls that primitive. Before activation, the actual invoice
coverage must travel through each native NET or GROSS producer and its settlement.
A scalar aggregate minus native usage, or a sum of selected lease states, is not
proof of the covered guard delta. The existing driver charge, owed-unit SUM and
logical paid marks remain unchanged; this source does not close the late-call or
continuation-transfer accounting gap.

`accounting_snapshot` also returns the selected leases' first-settlement meter
intervals beside their states and total. Each interval records that guard's actual
global `used_units` before and after its first settlement, under the same lock.
A per-call state may exceed this rise at saturation; an absolute settlement records
only its rise over the watermark. A settled local or zero-growth lease has an empty
interval. Open, aborted, foreign and unknown leases have no settled interval.
Repeated settlement keeps the first interval. A checkpoint rebuilds a fresh guard
with no old leases, so an old lease token is foreign there.

These intervals are data for an eventual exact GROSS inclusion join, not credits.
Callers still need the actual included native lease tokens, a coherent baseline and
current snapshot, and the paid facts checked with the money in one writer. Neither
this data nor the native NET invoices activate aggregate charge subtraction.
