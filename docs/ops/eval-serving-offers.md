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
