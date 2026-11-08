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
