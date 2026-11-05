# Research token settlement

The research continuation records the token-denominated spend its finished
run's native spend scope reports. It records the whole amount, including a
charge above the RSI reservation. A settlement records spend already made; it
does not authorize more work. New reservations still use the configured RSI
line, campaign lease, shares and suspension state.

A missing scope, a scope in another unit, or an inherited retry scope supplies no
individually attributable token spend total. Whole-scope attribution uses only the
actual run's own scope id, read in the settlement's write transaction.
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

## Durable native settlement

The first settlement, its actual scope-to-reservation binding, the campaign
receipt and the continuation advance commit in one write transaction. The writer
rechecks the persisted continuation, including its running reservation and run,
before it changes any of them. The binding lives only in the existing vault-local
RSI reservation row; it is not a second ledger or a spend-tree handoff field.

A descendant can also settle after its research run ended. The existing native
closed-scope hooks revise the bound RSI receipt and campaign receipt to the whole
new scope total in that same write transaction. Closing the run's own scope also
updates a binding recorded before closure. Repeated hooks do not add the total
again, and smaller totals never reduce recorded spend. Missing lines and unbound
scopes remain unchanged. A late update does not recreate a missing campaign row.

The public settlement door still accepts only an identical repeated settlement.
Only the native bound-scope path can revise this total. No correction changes
admission, holds, caps, suspension, or exposure accounting. Unknown receipts stay
reserved, not falsely measured or refunded. These are still native budget
charges, not provider measurements. FIX 3476 and FIX 9586 remain partial.
