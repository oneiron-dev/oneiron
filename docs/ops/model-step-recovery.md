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
migration, default, cap or configuration is added. The native financial source
association below changes only its private saved-state format.

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

### Native invoice terminal associations

The private saved response now pairs its original source facts with the original
native invocation coordinate, when that invocation came from a native admission.
The source is captured before the call constructor; only that constructor's
coordinate is attached afterward. Recovery does not recapture the actor, run,
frontier, subject or time from a later receiver. The private STATE format is
version 3, with a mandatory nil-or-binary invocation field; no older format is
accepted. The canonical `dreamer.step` claim format is unchanged.

After inserting the actual terminal claim, the same writer binds every retained
physical call of that original attempt, generation and invocation to that claim.
The original logical request hash must match too. Saved-response recovery can
emit another claim for the same physical invoices, so all emitted claim aliases
are retained without replacing earlier ones. The invoice's quantity and paid
state are unchanged. A memo read creates no invocation or association.

This optional association uses a nested savepoint. A binding failure rolls back
only that association and is logged; it never refuses the existing terminal
claim. A failed parent write also rolls back its child association. Missing
original admissions remain missing, not guessed from the latest memo, observed
call, public lease id or response totals. The association is financial correlation
data, not permission or proof of payment. It does not activate the payment
primitive or settle the remaining NET/GROSS coverage and reconciliation work.

### Original native meter-token capture

Each native durable admission keeps its actual issuing guard and opaque lease
clone until the call's existing settlement or abort has run. This holder is
independent of optional wake observation: an unobserved call or an already
claimed observation still drops it. Corrective calls retain their own actual
ordinal and lease. Panic unwinding skips this best-effort write.

At that drop, one accounting snapshot reads the selected actual lease on its
issuing guard. Only a settled interval is copied into its original retained
call row. Open, aborted, foreign and unknown states do not become zero; a known
settled empty interval remains known and empty. The first stored interval is
immutable. Repeating admission, invoicing or terminal association cannot replace
it. The guard lock is released before the private writer starts, and a failed
write is logged without changing the original call's result or settlement.

This retains an original call-to-interval observation, not durable guard identity
or proof that an aggregate charged that interval. It creates no payment, credit,
new funding reservation or extra settlement. The actual executor/driver inclusion
join, paid-fact checks, interval deduplication on the same real guard, and native
House producer coverage remain separate work before automatic payment activation.

### Original House admission in runtime settlement capture

A captured scoped read carries an opaque source from its original pass deadline
and attempt. Carrying the source allocates nothing. A stronger House read draws
its own original invocation only after its native permit and dispatch exist,
before its reader starts. It does not reuse the generated first read's invocation,
request hash, run instance or model-call index. The initial packed read and its
full-vocabulary retries keep their existing single permit and settlement.

The permit keeps the actual issuing guard and opaque lease, not a reconstructed
public lease id. That same newly allocated coordinate and actual lease are also
registered once with the original admitted line's shared native-token inventory;
registration neither allocates another invocation nor creates a financial row.
Its settlement capture attaches that handle only to the captured
runtime receipt clones, after settlement. The host's ordinary receipt sink still
gets the original receipt without the handle. Serialization omits the runtime
attachment because guard and lease tokens do not survive serialization. Missing
original lines and allocation failures remain unknown; they do not refuse the
existing read or become zero usage.

The scoped caller can sample the exact retained lease on its issuing guard. This
is GROSS meter data, not a native NET invoice, paid receipt or durable inclusion
proof. This runtime carrier alone registers no native input hash or NET invoice;
the configured prepared House producer below records those optional facts.
The executor/driver coverage join remains separate work. Automatic payment and
the existing generated-only opening policy are unchanged.

### Registered GROSS inclusion at park/error settlement

The original admitted line now keeps its actual opaque lease tokens through the
attempt lifetime. Registration reuses the already allocated original coordinate;
it does not allocate another call, reserve funds or reconstruct a token from its
public id. Clones share this finite-attempt registry, deduplicated by native lease
equality, including the issuing guard's allocation identity.

At a registered meter's park/error settlement, the registry lock is released
before one snapshot reads that registered guard's total and the selected tokens.
The same total determines the existing charge delta and receipt prefix. Only
settled intervals entirely within that original baseline/current interval qualify.
Foreign, open, aborted, unknown and pre-baseline intervals do not qualify; a known
settled empty interval stays known and empty. A fresh checkpoint guard cannot
qualify the old guard's tokens.

After the existing aggregate charge succeeds, the same money writer records this
GROSS inclusion in the existing private native-call row. Its mandatory coverage
state is either unknown or the original aggregate interval, input charge, actual
settled units and settlement time. It changes neither the invoice nor its paid
fact. A missing reservation records no coverage. An evidence failure rolls back
only its nested savepoint; a parent failure rolls back the charge and evidence.
The original charge, owed-unit SUM, receipts, status and error fallback stand.

The private turn program also captures its actual result meter's absolute total
and selected tokens together at the original result producer. That same total
still repays the shared loan once and supplies its original result. The driver
retains this owned snapshot for the program's Completed, Failed and ParkWithSpend
settlements; it does not resample a current guard to infer what an earlier result
included. The checkpoint writer records coverage only after its original charge,
receipts and lease-fenced park succeed together. Ordinary callers without this
producer capture keep their existing settlement path.

The program's result uses its existing absolute total, while error settlement
uses the registered baseline delta. A result-total equality check only pairs the
capture with its reported result; native membership comes from the producer's
actual selected tokens. The program has no Deferred or Landed result producer,
so those paths gain no invented coverage. Native NET tally coverage, complete House producer coverage,
paid-fact checks and late-call reconciliation remain separate
work. No durable guard pointer is serialized. Automatic native invoice payment
and aggregate charge subtraction remain off; a known empty GROSS interval is not
a zero NET invoice.

### Captured House native input and NET quantities

The original scoped caller also binds its actual vault boot. The admitted handle
keeps that boot, its original line, the actual selected lease's reservation when
known, and its admission time. Missing reservations remain unknown, not zero.
The gate lends that exact handle into the configured prepared House reader before
its tokenizer or completion can send. Ordinary custom readers keep their existing
port and produce no invented source facts.

The prepared reader hashes the same native input-plan bytes it constructed from
its rendered prompts, recipe, endpoints, tokenizer bodies, retry plan and forced
end token. This is a plan hash: the paid tokenizer has not yet supplied token ids,
so it is not a finalized completion-body or wire hash. It is not the generated
first read's logical request hash or a ModelCallRecord semantic evidence digest.
Before the read starts, the existing private native-call row retains this plan
hash with the original admission. The original boot must match the reader's
vault. A failed optional write is logged; the read and its settlement still run.

A complete read or a stopped paid prefix records that native terminal's actual
input and output totals on the same admission. The batch and full-vocabulary
retries still use one permit and one settlement; they do not create per-prompt
financial calls. Errors without a complete native quantity stay unknown. A
failed input registration or invoice write never changes the returned read.
No terminal CONTENT claim is fabricated for a House read. The existing scope,
purpose and extraction egress admission remain, and preparing a captured local
read adds no extraction authorization requirement.

This is optional producer data, not a paid fact, exact aggregate coverage or
complete error-prefix accounting. The native payment primitive stays uncalled;
new funding, aggregate subtraction, automatic payment and the generated-only
opening policy remain unchanged.

### Captured House post-settlement meter intervals

A successful pre-byte input registration also binds a set-once weak reference to
that original vault on the shared admission handle. Runtime receipt clones share
this reference; it does not keep a vault alive, serialize a pointer, or create a
new registry or funding reservation.

The original permit's settlement capture samples that exact issuing guard and
opaque lease after its guard settlement, before keeping receipt clones. It runs
independently of ModelCallRecord evidence, observer attribution and captured-receipt
subscribers. An absent writer, closed vault, different boot, panic unwind or
unknown lease interval records nothing. A known settled empty interval stays
known and empty; it is not a zero NET invoice.

The snapshot releases the guard lock before the existing private native-call
writer begins. No capture-target lock is held over that writer. Failure is logged
without changing the original settlement or receipt forwarding. The hook runs
before any later durable allocation commit and host publication, so this native
meter observation proves neither of those operations succeeded. It records no
extra settlement, charge, NET payment, aggregate credit or fabricated terminal
claim. Reads that never retain an input do not gain invented meter provenance.
