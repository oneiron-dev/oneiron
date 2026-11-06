# Measured serving offers

Generative paired eval legs keep the exact host offer used by the successful
call. `EvalLegRecord.serving_offer` contains its canonical binding fingerprint
and its actual native `UnitRate` prices. It does not use a model registry's
backend name or catalog list price as a substitute for the constructed route.
Credential names are not copied into the measurement; they stay behind the
binding fingerprint.

The producer reads the immutable single picked rung on the same admitted
ladder passed to `generate_exact_within`. That call has no fallback. The
measurement keeps the evidence only when the call answers. Existing clock,
budget, source-row, scoring and failure behavior is unchanged. Non-generative
execution paths leave this evidence unknown.

`EvalMeasurement::serving_offers` returns the incumbent and candidate offers
only for a Final measurement whose settled cases all name the same pair. The
incumbent retest must name the same offer too. A missing or mixed identity is
unknown. `EvalServingOffer::matches` compares that historical identity and its
rates with an actual current constructed `OfferBinding`.

This evidence is not permission to call a model or switch a binding. It does
not prove local files, download-card acknowledgement, current policy, current
cohort validity or sufficiency. Automatic application is not implemented by
this producer. Manual approval, training and the existing cards remain as before.

The stock-offer request also snapshots the incumbent and candidate constructed
offers in `requested_offers`, in that order. The existing named request encoding
includes this data in the measurement key. A changed route, payer, credential
binding, catalog revision or rate therefore requests a fresh measurement even
when the model/revision and cohort are unchanged. If either exact offer cannot
be read, this snapshot is unknown. Helper-skill requests and non-generative
seats leave it unknown.
This snapshot adds no call refusal and is not evidence of what a later call
actually served. Only successful per-leg records supply that evidence.

## Monetary evidence on a measured leg

Lease-unit rates are not currency prices. A generative measured leg can now
keep `call_price`: the existing usage meter's quote and counts from that exact
physical call. The scoped capture uses the same run instance and the meter's
prepared settlement bytes. It does not create another price table or wait for
a ledger write. The snapshot keeps the currency (or the meter's existing
free-in-any-currency case), price-table snapshot, all input/output/cache rates,
all four measured token counts, amount, run instance, lease and source rows.

The leg keeps a snapshot only for one native prepared event matching its
actual constructed binding's offer, model, route, catalog revision and payer.
It also requires the successful response's host-stamped permit instance and
lease to match that same native event; a concurrent call on the same run and
binding is not interchangeable. Provider payloads cannot supply this stamp.
An unbound meter, absent quote, unpriced usage, decode failure, multiple calls
or a mismatched route leaves `call_price` unknown. The original answer, scoring
and error paths do not change. Incumbent, candidate and incumbent retest use
this same path. Non-generative seats remain unchanged.

This is historical evidence. It is not a current price quote, loaded-file
proof, policy authority, a durable-ledger receipt or an automatic switch.
Comparing fewer tokens is not a money comparison. Automatic approval still
needs the current policy and bindings, current quality and sufficiency, the
download-card rule, and both monetary quotes repriced on the same workload.
