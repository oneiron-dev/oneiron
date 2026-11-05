# Mesh organ ask receipts

The asking node keeps each callback's receipt before running the handler. The
receipt includes the ask's real id and any signing prehash the handler records.
It stays in `AskHandlers::asked()` when the callback panics, the connection fails,
the call is cancelled, or a final peer reply never arrives. This is in-process
retention, not a crash-durable journal or protection against process termination.

## Delivery observations

- `not_run` is the serving host's record that the ask was not run.
- `not_sent` records a decided answer or refusal that was not sent. On the asking
  node it also covers failure before the mesh answer send was attempted.
- `unknown` is the asking node's record that it attempted to send the mesh answer,
  but has no final serving-host receipt confirming delivery to the organ. Neither
  a successful send nor a send error proves that delivery.

Without a final peer receipt, answer fields describe the local handler's result,
not confirmed bytes lent to the organ. Signing facts are retained independently
of delivery, including a prehash recorded before a key failed.

When a final peer receipt arrives, its order, refusals, answer bytes, fetch facts
and timing remain authoritative. Matching signing evidence identifies a peer
occurrence before any unsigned candidate is considered, and each peer occurrence
is used at most once. An unsigned match needs a unique identity on both sides;
conflicting positive signing evidence is never overwritten. When repeated
identities leave an occurrence ambiguous, local evidence stays separate rather
than being attached to an earlier refusal. Unmatched local lines are appended
only after matching is complete, then stable ask-id order is restored for that
one serving call. The returned successful `CallReceipt` and the lines retained
by the supplied handlers use the same reconciled records.

## Attempt identity and rollout

A mesh attempt uses a fresh connection and serves one organ call. The serving
call id and ask id travel together in `PeerAsk`; ask ids restart at 1 for each
call. Reconciliation is local to that attempt, never a global id deduplication.
Router retries retain their own segments in the handlers' records. Give each
caller its own `AskHandlers` when its receipt lines must stay separate.

Roll out matching engine/organ-host builds on both mesh peers. `PeerAsk` now
requires the real `call` and `id` fields, and receipt readers must understand
`unanswered: "unknown"`. There is no old-peer fallback or fabricated identity.
The mesh ALPN and organ process protocol version are unchanged. No organ binary,
SDK, configuration or stored-format migration is required by this change.
