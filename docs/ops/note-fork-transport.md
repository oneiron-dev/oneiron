# Large pending NOTE forks on the owner document lane

Replica-local pending fork uploads and authority-to-device fork states keep the
same native fork identities, command digests, receipts and pending-set semantics.
The original owner-only upload and own-device downlink rules still decide which
forks can travel. This does not add replica-local bundle uploads or other-actor
fork eligibility.

A logical NOTE_FORK_UPLOAD, NOTE_FORK_STATE, NOTE_FORK_SET or NOTE_FORK_RECEIPT
can exceed one document frame. Its sender keeps the original logical bytes and
uses the existing ordered PART document envelope only when needed. Each wire
part obeys the existing document frame geometry. Small frames keep their old
bytes. The client sends large uploads outside a node batch, on the same socket.

The server checks the current owner connection and NOTE subscription before it
accepts each upload part. Selector-scoped NOTE operations do not authorize fork
uploads. The receiver verifies the complete contiguous payload and digest before
running the original whole-fork admission, native write, receipt or pending-set
settlement. No prefix imports or settles a fork.

Before each outbound part, the sender rechecks the original complete logical
frame's destination policy. The authority also repeats the current owner and
credential check for fork downlinks; the existing transport still checks
revocation while queueing and flushing. Fork-state citation checks see the whole
fork state, not PART metadata. If release changes after a prefix, the sender
closes the socket, so the incomplete assembly cannot be reused. The device's
original durable upload marker remains owed until its complete native receipt.

This is framing, not a total-memory bound. Fork operations, snapshots, logical
payloads, decoded values and Loro state can still be whole in memory. There is no
new logical-size cap, timer, default, migration or old-format reader.
