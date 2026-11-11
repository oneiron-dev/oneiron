# Repairing undecodable usage rows

The existing `vault.usage.events.undecodable` verb lists undecodable stored events and pending
settlements in the vault scope bound by the serving host's usage meter. It includes every billing
owner in that scope. A caller does not choose another vault or provide a storage prefix.

Each row has an opaque `rowRef`, its byte length, a BLAKE3 `hash`, and a typed reason:
`stored_event_decode_failed` or `stored_pending_decode_failed`. Pending settlements use the same
decode, event-validation and key/scope checks as redelivery. A valid settlement is not listed just
because delivery has not finished. The list returns no event contents or raw storage keys.

After reviewing a listed row, pass its exact `rowRef` and `hash` as `expectedHash` to
`vault.usage.events.remove_undecodable`. Listing alone does not authorize removal. Each verb uses
the caller's own live owner proof, or its own live Grant from a live owner naming that verb.

Removal checks the hash and current decodability again in the same writer that admits the caller.
Changed or now-valid bytes are not removed. An accepted removal deletes only that row and keeps
one receipt in that write. Event removal also marks its billing owner's rollup stale. Pending
removal does not: pending bytes have not been folded into a rollup. A retained in-memory settlement
blocked by that pending key can then stage and deliver on the existing retry path.

`vault.usage.repair.receipts` reads the kept receipts. A pending removal is labelled
`undecodable_pending_removed`; an event removal stays `undecodable_event_removed`. No row is
automatically evicted or replaced. Removing undecodable bytes does not reconstruct missing usage
facts, charge a wallet, or change the retry schedule, source-erasure checks or idempotency rules.
The opaque locator names its current row family; no old-format locator reader or migration exists.
