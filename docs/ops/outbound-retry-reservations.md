# Outbound retry reservations

Admission reserves each logical outbound send's connector budget before
transport. Confirmed delivery settles that reservation; reported actual cost
still reconciles a preauthorized spend estimate through the existing path.

A definite non-delivery or provider rate/quota refusal now releases the budget
while that send waits for retry, only when its ledger has no earlier delivery
uncertainty and its reservation contains only key-budget rows. Mixed and
charter-backed reservations retain their existing behavior: re-stamping a
charter resets positional usage, which a retry must not revive. The ledger
stays Pending and keeps the same frozen request,
provider wait and retry rules. Its budget receipt reads `released` during this
interval.

The actual retry claim restores the original debit multiplicity and marks the
reservation `reserved` in the same writer that clears the retry permit. It uses
the original charge timestamps, not a new window or a fresh admission charge.
Native rolling/calendar pruning still removes expired entries before usage is
summed. Restore does not emit a new ladder event.

A send with prior possible delivery keeps its reservation even if the latest
try certainly failed. Accepted remote tasks keep their existing Deferred
handling. An owner stop, erase or dedupe takeover does not release an already
released reservation a second time, and an abandoned retry never restores it.
All of these changes commit with the existing ledger outcome transaction.

This slice does not split `EffectorBudgetRead` into reserved and settled usage
or move the ladder's warning time. Charter-backed release also needs a real
charter-generation binding before restoration is safe. These remain follow-up
work. Budget limits,
defaults, authority, transport, provider clocks and window geometry are unchanged.
