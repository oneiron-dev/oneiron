# Research token settlement

The research continuation records the token-denominated spend its finished
run's native spend scope reports. It records the whole amount, including a
charge above the RSI reservation. A settlement records spend already made; it
does not authorize more work. New reservations still use the configured RSI
line, campaign lease, shares and suspension state.

A missing scope, or a scope in another unit, supplies no token spend total.
The continuation finishes its normal result processing and writes the terminal
`Unknown` RSI receipt. It does not substitute the reservation or zero for the
missing total. Both the campaign and the RSI line keep that reservation's
original amount under `reserved`, not `spent`. It still counts against the
same commitment and share pool as before. A terminal unknown receipt is not
refunded or replaced with a guess on replay.

Recorded zero native token spend is distinct from an unavailable total. The
existing `Spent`, `Exposure` and `Refunded` receipts keep their meaning. The
exposure line still refuses exposure above its reservation; unknown token
receipts are not valid on that line.

## Remaining work

This change does not bind dispatches to a new token lease. The existing launch
intent, dedupe, parent budget, admission and run behavior are unchanged. A
reservation-bound token lease must preserve those contracts, including a
parent in a different unit and a dispatch recovered after enqueue but before
the continuation saved its run id.

A native scope reports its budget's recorded charges. That is not necessarily
provider-measured token usage: a started call with unavailable usage can book
its reserved estimate upstream. This receipt does not turn that estimate into
a provider measurement. A complete token-usage meter remains separate work.

A descendant can also settle after its research run ended. Native scope totals
can then grow, while the RSI receipt remains the total seen at the research
settlement. Revising that receipt from the same durable scope is still open.
FIX 3476 and FIX 9586 therefore remain partial.
