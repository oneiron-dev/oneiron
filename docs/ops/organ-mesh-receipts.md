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
one serving call. The lines retained by the supplied handlers are these
reconciled records. The returned successful `CallReceipt` keeps the serving
host's own ask lines, exactly as the serving machine signed them (below).

## The serving machine's signature

The serving node signs each successful call's `CallReceipt` with its machine key
(`signed_by`: the machine and its Ed25519 signature under the domain
`oneiron/organ-call-receipt/v1\0`, over the receipt in the organ codec without
that field), through the vault's `MachineSignatures`, the one key path pass 33's
job submit and job receipt use too. The asking node reads the machine its
handshake proved (`Vault::mesh_peer_machine` on the connection's endpoint key)
before it sends anything, and refuses a node not proven as the machine it
dialed. Before it takes any output it checks that the receipt is signed by that
machine, against the machine key its MACHINE row holds in this replica. An
unsigned receipt, another machine's, or one that does not verify is
`ReplyInvalid`: the call ran there, so it is not retried on another node. A
serving node that cannot sign answers the call as failed, never as an unsigned
success. A call this machine runs itself carries no signature.

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
SDK, configuration or stored-format migration is required by this change. An
asking node with the signature check refuses every success from a serving node
without it, so both peers take the signing build together. A receipt written
before it reads with no `signed_by`.
