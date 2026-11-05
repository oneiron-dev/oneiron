# Decision cost receipts

A completed Big reading can report `DecisionReceipt.cost_per_thousand` from the
registered price of the **model that answered**, including an owner's fallback.
The configured seat's model and a later route resolution are not price sources
for that answer.

## Basis

One Big `DecisionCall` reads one typed question over one state. Its paired reading
shares that measurement. The reported rate is the catalog quote applied to the
completed response's token usage, multiplied by 1,000 decisions. It is not the
input-token price per thousand tokens, an allocation-unit rate, a currency
conversion, or a provider invoice.

The calculation uses uncached input, output, cache-read and cache-write tokens.
Cache tokens are subsets of total input; reasoning tokens are inside total output.
It uses the same arithmetic as `PricedModelBackend::cost_receipt`. A cache used
without a registered cache price has unknown cost.

## Unknown remains unknown

No row, no currency, an invalid quote, inconsistent usage or arithmetic overflow
leaves the cost absent. Big text readings also leave it absent when either input
or output totals are zero: adapters can represent an unreported counter as zero,
so that does not prove a free reading. An actually zero-priced quote with reported
input and output usage can report zero.

The in-memory `ProviderDecision.cost_per_thousand` distinguishes three cases:

- `None`: the provider supplies no per-answer measurement. Its existing
  provider-level rate still applies.
- `Some(None)`: this measurement's cost is unknown. No provider-level fallback
  replaces it.
- `Some(Some(amount))`: this measurement supplies the rate, including known zero.

This carrier is not serialized. The existing durable receipt field holds the rate
only when a rung answered. Unknown cost never rejects or delays an answer.

A tournament's chunk quote is not its complete cost. A separately asked person
question can also have a different currency or be shared by a pack. These
composite readings retain their answers and mark measured cost unknown until a
combined, currency-aware quote is available. Providers that do not supply the new
per-answer measurement keep their existing rate behavior.

This does not change trial backend pins, billing settlement, capture, deadlines,
model selection or provider fallbacks. Other provider-level rates are not made
usage-measured by this carrier.

## Native label readings

A native decision reader keeps each question's distribution with that question's
catalog-priced token cost estimate before the pack's usage is summed. The quote
uses the same fixed engine model and bound host as the read. It includes both
attempts when a top-k answer needs a full-vocabulary retry. It does not divide a
pack's total cost among questions or compare a returned launch alias with the
engine model. A joint paired read shares its question's measurement.

A third-party native answer needs positive reported input and output counters and
a known cache-read count. A reported zero cache read is known; a missing or
inconsistent cache count is not zero for pricing. Missing counters or prices,
an invalid quote or overflow leave measured cost unknown. The old settlement
values are unchanged: an unknown cache read still contributes zero to its token
counter, and a zero output count still retains the one-position accounting floor.
Those accounting values are not evidence for a known cost estimate.

As before, a model served on this host, or a reader without a bound vault,
reports no registered native cost.

Native measured unknown is `Some(None)`, not the old input-token-rate fallback.
Non-finite or negative per-answer prices also stay unknown without rejecting an
otherwise valid answer. This does not change answer probabilities, paired
marginals, person-question handling, retries, receipts or lease settlement.

This is a catalog quote, not an invoice or proof of a financial charge. Generic
`GeneratedRung` provider rates are a separate remainder; this native path does not
establish their actual answering-model identity or change their pricing.
