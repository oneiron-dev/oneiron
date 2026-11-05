# Provider token measurements

The normalized `LlmUsage.input` and `output` counters still use zero when a
provider omits a field. Their values and the existing budget charges do not
change. A reported zero and an absent measurement are different facts.

The OpenAI Chat, OpenAI Responses, Anthropic Messages and Gemini adapters now
stamp `ProviderTokenMeasurement` when they parse usage. Each component is an
optional count: `Some(0)` means the provider reported zero; `None` means that
component is unknown. Anthropic input is known only when the uncached, cache-read
and cache-write counts are all present and sum without overflow. Gemini output
is known only when its candidate and thinking counts are both present and sum
without overflow. These paths never fill an absent measurement with zero.

Anthropic output-only stream deltas preserve measurements of input from that
same stream. OpenAI, Responses and Gemini keep measurements with their existing
stored usage objects. An answer with no usage report still has no measurement.

The observations travel in the existing `raw_provider` carrier under the reserved
`provider_token_measurement` key. The native setter replaces this key, including
with explicit unknown when no count was reported. That also shadows any
provider-supplied imitation of the native ladder's nested usage wrapper. The
accessor reads only this typed carrier, directly or through that actual wrapper;
it does not infer measurement presence from ordinary provider JSON or from
normalized totals. The `LlmUsage` fields and serialized type stay unchanged.

A native `Settled` run receipt includes this optional observation inside `usage`
for an answered call. Only typed counts enter the receipt, not raw provider data.
A failed call, an estimate, or a reserved charge does not create a measurement.

## Coverage

This is a provider-report observation, not proof that all physical requests or a
whole spend scope were measured. It does not total partial or cancelled requests,
join child scopes, or settle RSI reservations from these observations. Local
runtimes, peers and captured external-agent runs still need their own real
measurement suppliers. Complete guard-to-scope coverage and non-token budget
accounting remain separate work under FIX 3476 and FIX 9586. Existing native
inference receipts, physical publishers, admission and charges are unchanged.

## Reports on the issuing meter

`BudgetGuard::provider_token_observation` and
`RunAdmission::provider_token_observation` read the provider reports attached to
that actual shared meter's started leases. The run's native Answered settlement
records its typed report before charging the lease. These are provider token
observations, not the line's `used_units` or a conversion from its price unit.
A free call can report tokens even though its paid charge is zero.

Each started lease contributes once. An unsettled lease, a failed or cancelled
call without a report, or an unsupported supplier keeps the affected component
unknown. Addition uses checked arithmetic. A report of zero stays known zero;
an empty meter does not become a provider-reported zero. The read changes no
admission, reservation, charge, dispatch or settlement state.

This is an on-demand snapshot of admitted calls on one guard, not a count of
socket sends, a final run or spend-scope total, or proof that every physical call
was covered. Other guards, future calls, children, failed partial reports, and
local, peer or BYOA suppliers still need their real source and coverage proof.
The native lease end records the present snapshot separately from charged
spend. No RSI settlement consumes it. Ordinary `BudgetRead` and the admission
hot path are unchanged.

## Guard generations

`BudgetGuard::provider_token_snapshot` and
`RunAdmission::provider_token_snapshot` pair that same observation with the
actual guard's opaque 16-byte generation. Every fresh `BudgetState` mints one
identifier. Guard and run clones retain it because they share that state. A
restarted guard mints another even if its attempt and lease strings repeat.
The identifier is observation data, not an entity reference or authority.

The generation is immutable. The snapshot getter captures its observation
and a native monotonic `observation_id` while holding that guard's lock. This
orders captures within one generation without treating paid charges, token
counts or call counts as a version. It also orders free calls whose paid
charge stays zero. The old snapshot-free getter uses the same observation
fold. Ordinary budget reads, admission and financial charges are unchanged.

This identifies the source of a durable guard-to-scope record; the snapshot
getter itself does not write it. Reading every row that happens to be present would
still not prove that a crashed or unrecorded generation was covered. No
whole-scope completeness or RSI settlement is inferred from the generation,
lease strings, scope closure or a successful charged-spend flush.

## Present scope records

After its existing financial booking succeeds and its once-only booked
watermark advances, `LiveLease::book_rest` records the actual guard capture on
that lease's native scope. The record is best-effort: failure logs a warning
without changing the booked watermark, recharging the scope or failing the
completed money booking. These observations are not a second money ledger.

Each scope and guard generation keeps its greatest native capture identifier.
That identifier is minted under the guard lock with the observation, so a
stale writer cannot replace a later capture. Paid charges, token counts and
call counts do not order captures. Free calls therefore remain observable
without inventing tokens from their zero charge. The new named side table is
checkpointed as unclassified data and restored as historical content, like
the spend-scope records; neither record grants authority.

`vault.research.budget` keeps its existing controller check and adds
`provider_token_observations`. It resolves the campaign's recorded native
runs to their actual spend scopes in one read snapshot, grouping runs that
share a scope so captures are not duplicated as per-run charges. Scope or
snapshot absence is unknown. An empty recorded list is not a measured zero.
Observation-read failures leave the original budget and reservation response
available and do not change settle or refund behavior.

These are present historical records, not a complete generation inventory,
a physical-send count, exact per-run attribution, current health, or a final
scope total. A crash before a flush, an unrecorded guard, an unsupported or
partial provider report, a child scope or an unmetered run can remain unseen.
Even all-present known rows do not prove completeness. No captured value or
identifier settles RSI, overrides its reservation, or authorizes a call.

## Native reports retained by failed calls

A failed lease also keeps the native inference receipts its physical requests
published, including measured partial reports before an error or cancellation.
The snapshot's `failed_call_reports` carries each receipt's optional prompt and
output counts separately. It never copies normalized usage, a reservation, or
spend accumulated by earlier attempts. A reported zero stays zero; an absent
count stays unknown. Two retained receipts remain two entries even when their
counts match. Requests that published nothing remain uncovered.

These reports travel through the existing guard capture and scope record to
`vault.research.budget`. They are data, not a sum or proof of complete failed-call
usage. The complete observation's input and output still remain unknown for a
failed lease. An empty report list is not a known zero. No report changes
admission, abort, charges, receipt events, refunds or RSI settlement.

The real native publisher must run at the physical send. The pending Anthropic
transport producer in #5613 provides one such source; it is not assumed to be
merged by this consumer change. A second publisher on a retrying decoder wrapper
would duplicate those observations and is not added.

## Scoped code-mode call captures

A code-mode model call carrying a native `LiveLeaseState` scope now records
its actual run meter's observation when that call's run is constructed. This
happens inside `CodeModeBackend::generate_on`, not when a backend or a
`ScopeMeter` is opened. The affordability probe therefore records no source.
The first capture means the scoped host entered its model-call path. It does
not mean a permit was admitted or that a provider received any bytes. An empty
meter still reports unknown input and output, not measured zeros.

The scoped receipt sink forwards the original receipt first and takes another
capture on `Admitted`, `Dispatched` and `Settled`, including a settlement that
never dispatched. The existing dispatch receipt is emitted when the call ends
or is dropped, not at its first send. A settled capture includes the native
answered or failed-call reports recorded before that receipt. The sink forwards
budget-hit hooks too. The unscoped path still uses its original funded run and
receipt sink.

Every capture uses the actual run's guard and the native lease's scope, with
an owned handle to that same vault. The guard lock is released before the
separate observation write. A write failure only logs a warning; it does not
change the original receipt, model answer, caller error, money booking or
budget watermark. The sink performs no drop-time finalization and uses no
background queue. Existing entry-end financial booking remains unchanged.

These rows make this executed code-mode source visible before entry-end
booking, and retain its later reports even if money booking later fails.
They are still partial historical captures. A failed initial write, a crash
before a later receipt, other guards, child scopes and unbound or unsupported
suppliers remain uncovered. Receipt completion is not whole-guard or
whole-scope finality. Scope, generation and capture order do not attribute
usage to one native run or decision call, and do not settle RSI reservations.

## Native permit identity and end readback

Each recorded scope/guard generation also keeps content-free permit observations
keyed by the actual `RunReceipt.instance` and lease string. Another run can reuse
a lease string; it cannot replace this pair. `admitted_receipt` and
`dispatched_receipt` report only which native receipts were recorded.
`answered` comes only from the actual `Dispatched` receipt, or stays unknown.
It is not inferred from usage presence, charge, capture order or a run label.

A recorded `settlement` means that native permit ended, including an admitted
permit that never dispatched. Its `answer` copies only the optional explicit
provider measurement. Its `reports` retain each native inference receipt's
optional prompt and output values, including partial failed requests and equal
reports from separate requests. Missing values stay unknown and reported zeros
stay zero. Normalized counters, prices and reservations never supply a value.
The native merged `reports` list does not retain physical-report finality.
Separate `observed_slots` data preserves the native publisher's slot and report
stage at that same settlement capture, as described below. Neither list certifies
complete physical use or sums the reports into a total.

Receipt stages merge independently of capture order. A stale concurrent capture
can still add another permit or its settlement. A later financial-booking
capture preserves the permit records; a late admission or dispatch receipt
cannot erase a recorded settlement. All readback remains on the existing
controller-gated `vault.research.budget` path and its one read snapshot.
The scope's listed research runs are not an attribution of each permit to one
attempt. Missing receipts, generations and child or unbound sources remain
uncovered. Neither a permit's end nor all-present records close the scope,
consume measured RSI tokens, or revise the existing reservation settlement.

## Scoped model entry and future return

`run_observations` identifies actual scoped `RunAdmission` instances, including
an invocation that admitted no permit. `entry_recorded` means the scoped host
constructed that run on its model-call path. It does not mean admission, provider
bytes, or a measured zero. `model_future_returned` records that the code-mode
ladder future returned, whether it answered or failed. The planned branch keeps
its original successful `planned.answered` call, then records the marker before
the existing handoff and response processing. Its original error still returns
unchanged. Unscoped calls keep the original funded path and do not write these
scoped markers.

The marker uses the same native run instance, current guard generation and
actual lease scope as its entry and permit records. Entry and return merge
independently of capture recency; a failed entry write does not prevent a later
return record, and an absent entry stays absent. The guard lock is released
before the warning-only data write. There is no drop-time write or background
finalizer. Cancellation or a crash before this marker leaves return unknown.

A future's return is not a seal on its `RunAdmission`; it does not prevent a
clone admitting later work. It does not certify all physical reports, every
source, child scopes, whole-guard or whole-scope closure, or an RSI token total.
The existing charged-spend and reservation settlement paths remain unchanged.

## Native publisher slots at settlement

The native settlement captures its lease's publisher slots once, under the
collector lock. Every registered slot remains in `observed_slots`, including a
publisher that recorded nothing. The old merged inference receipts are derived
from the nonempty observations of that same capture, in the same order, using
the unchanged merge. They are not sampled a second time. Content matching in the
merged receipt list is not used to identify the separate publisher slots.

A slot index is local to the actual run instance and lease. It is not a global
request identifier, a collector address, or the separate `physical_attempts`
counter. An empty slot's `observation` is null: it does not prove provider bytes,
zero tokens, or a completed request. A present observation retains only the
native Partial/Final status as `final_observed` and its explicit optional prompt
and output measurements. Missing counts stay unknown; reported zero stays zero.

These slots pass through the actual `Settled` receipt and its existing scoped
sink to the recorded permit settlement and `vault.research.budget`. They are
separate data, never extra inference receipts, charges or totals. The original
receipt is still forwarded first. No wrapper publisher or extra send is added.

This is the publisher state at that capture, not a promise that every physical
source registered or that no publisher can report later. Counter-only and
unsupported suppliers can have no slots; an empty list stays unknown coverage.
Even all-final observed slots do not seal a run, close a guard or spend scope,
join children or assign measured tokens to an RSI reservation. Existing failure
reports, admission, answers, errors and financial settlement stay unchanged.

## Executed caller attempt identity

Scoped model entry, future-return and permit observations carry an optional
`owner_attempt`. The resident pump supplies its executed `status.attempt.id`
before it lends the entry's lease. A reader child supplies its own `job.attempt`,
never the parent's id. The lease state copies that typed identity into the same
model run's sink and both source-stage records. No scope string, run label,
receipt instance, capture identifier or token count supplies an attempt id.

`vault.research.budget` exposes the recorded owner in hex beside each native
run or permit observation. An absent owner stays unknown. Unscoped calls keep
their original path, and other native sources still need their actual supplier
threaded before their records can name an owner.

The outer read still groups recorded research attempts by their spend scope.
Several attempts can share one scope. The new field names only the caller of
that individual recorded run or permit; it does not assign the guard snapshot's
aggregate counts or failed-call report list to that attempt. It does not cover
unrecorded sources, join child usage, prove finality or produce an RSI total.
The controller check, receipt forwarding, charges and reservation settlement
remain unchanged.

Scoped pattern-start captures use that same lease state too. A resident entry
lends its already-bound lease; a live-run action supplies its actual leased
attempt id before lending the action's lease. Both paths keep the original
guard, payer, listed models and once-only booking ledger. A host that cannot
construct a lease-aware backend still takes its original backend before any
generation begins. This factory fallback is not a retry of a paid or captured
call. The affordability probe constructs no observed model run, and unscoped
starts keep their old path. Compaction and speech sources are not covered by
this pattern-start port.

## Scoped workflow captures

Workflow steps and wave planners use the `StepRunner` vault cloned from the
same native `Arc<Vault>` supplied to their pump. The runner derives its local
vault borrows from that owned handle. When the attempt has a native spend scope,
the existing funded run records observations with that scope and the actual
`AttemptRecord.id`. Unscoped steps keep their original funded path. The guard,
payer, request sources, work context and financial booking are unchanged.

The plain model path records future return directly after its ladder future
returns, whether it answered or failed. A secret-use conversation records return
at that same point for each actual model future. A retained tool iteration,
`HookPending`, a checkpoint-only save or a replayed saved answer does not create
a new future-return marker. The saved-answer path also creates no model run.
One run instance can span several tool rounds; a return marker never seals it.

These are partial historical observations of the executed native workflow
caller, not provider coverage, per-attempt token totals, child-scope closure or
measured RSI settlement. Original receipt forwarding and warning-only capture
handling stay in place. Other native suppliers still need their own real ports.
