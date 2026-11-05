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
