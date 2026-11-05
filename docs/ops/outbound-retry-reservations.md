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

The actual retry claim first checks every still-live debit against its current
owning key row's budget in the same writer. Repeated debits of one row are
counted together, including co-actor and shared-pool usage. Only if all rows fit
does it restore the original debit multiplicity, mark the reservation `reserved`
and clear the retry permit and provider wait. It uses the original charge
timestamps, not a new window or a fresh admission charge. Missing usage rows
stay gone, expired debits are not restored, and no new ladder event is emitted.

If another send has used the released capacity, a count-bound `refuse` row waits
for the existing window to have room. This includes the original retry debits'
own expiry, which may precede newer usage. A Spend refusal still denies; an
owner-configured `suspend` still suspends the actual owning key, including a
catalog pool key. These blocked claims keep their Pending non-delivery permit,
`released` receipt, provider wait and usage unchanged. The existing retry path
can claim again when capacity or the owner's setting changes; there is no new
timer, budget override or default refusal.

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
