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
measurement suppliers. Durable guard-to-scope flushing and non-token budget
accounting also remain separate work under FIX 3476 and FIX 9586. Existing native
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
No scope persistence or RSI settlement consumes this snapshot yet. Ordinary
`BudgetRead` and the admission hot path are unchanged.
