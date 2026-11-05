# Mesh organ ask and answer envelopes

Organ calls between an owner's nodes use `oneiron/organ/1`. Each ask and
answer stream carries an encoded `Carried` envelope, just as the call and
result streams do. The payload is the complete encoded `PeerAsk` or
`PeerAnswer`, including its value, refusal and signing receipt.

Payloads up to the existing 64 KiB inline threshold travel in the envelope.
Larger payloads use the existing blake3-named staging files and piece transfer;
the transport's 1 MiB message limit is not an ask-value or answer-value limit.
Answer data keeps its own existing staged reference inside `PeerAnswer`.

The serving node offers ask bytes for the asking node to get. The asking node
puts answer bytes on the serving node before sending their staged reference.
Both receivers lease staged envelope bytes from their existing memory floor
before reading them back. The asking node keeps its lease through the handler
and answer send. The serving node keeps answer leases through the organ call.
Staging keeps its existing disk-floor admission and connection-lifetime cleanup.

Update both participating nodes together. This changes the ask and answer
stream envelope, without an old-format reader or an ALPN change. Handler
grants, signing receipts, call deadlines, cancellation, inline thresholds and
piece sizes are unchanged. This is not a new total-heap accounting guarantee.

A staged returned output keeps its original machine-floor lease. Immediately
after the transfer completes, that same lease records the returned vector's
actual capacity as allocated, before receipt hashing or another admission.
Inline outputs keep their existing no-separate-lease path. This is post-allocation
bookkeeping, not a new reservation, wait or pre-allocation accounting guarantee.
