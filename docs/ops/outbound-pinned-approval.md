# Pinned outbound retry approval

The primary pinned approval is private metadata on the existing outbound intent
ledger record. The first Gate admission selects the original proof. Its family,
original intent id and effect digest commit with the spent press, decision and
Pending insert in the same writer. There is no separate primary proof table or
post-commit primary keeper.

This does not add a keeper failure gate to the first send. The co-actor's separate
operation-keyed keeper and `KEPT_PRESS_WRITE_FAILURE_CONTINUES = true` policy stay
unchanged. That co-actor path is not made crash-atomic by the primary carrier.

All primary retry readers use the canonical ledger row. They require its original
proof's intent, family and digest to match the current effect. Ordinary retries
also retain their frozen request and actor checks. The current Gate, grants,
scoped authorization, connector setting and delivery checks still run. A spent
marker, a Pending row or a matching content hash alone is not approval.

A later AlwaysAsk press writes its original typed proof back to the actual stored
row in the press's own writer. It preserves the stored payload, including its
private placement, and every other record field. A missing or erased request is
not recreated. An actor's canonical erase clears the pinned proof with the
request; checkpoint and restore carry only the canonical intent record.

Ledger schema 6 requires the explicit `pinned_approval` key: nil or a canonical
family plus the full original intent/digest proof. The content digest covers it.
There is no old-format reader or migration. The proof is not in frozen transport
calls, Debug output, SDK inputs or HTTP inputs.
