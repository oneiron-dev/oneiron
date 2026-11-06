# Queued tagging identity hints

A base witness marks its turn in the same write transaction. The marker keeps
its existing turn/checkpoint/stack dedupe key and the existing live/bulk class,
lease, backoff and retry chain.

The witness also carries its original optional identity-hint reader. The stored
reader represents only a plain on-device `Memory` read: the actual actor and
actor class, plus every effective fact of the original bound verified read proof. A host-action lane, room-turn lane or non-on-device destination
or a caller with no bound read proof is not represented by this reader. Such a
caller carries an explicit unknown,
not the internal hint aggregate and not a reconstructed owner key.

At save time, the worker rebuilds the supported reader through the ordinary
native read-key builder. Actor binding, current grants and proof liveness are
checked there. Source TURN/MESSAGE contributions and candidate entities are
checked again by the scoped hint helper in the saving transaction. A missing
read grant leaves the full candidate set in place. Expiry or revocation is
checked by the native live-proof guard for each source and candidate: a false
result supplies no hint, while an error is not treated as an absent grant. No hint text is returned. Other reader failures record a
`hint_read` failure code and use the marker's existing retry path; they are not
silently treated as an absent hint.

Deduplication does not make one caller's reader stand for another. Internal
bookkeeping does not clear a carried caller reader. Equal caller contexts may
share it. Distinct captured contexts remain distinct in the marker payload;
when more than one is carried, this implementation uses no optional hint. If the marker's
context changed after the worker prepared its read, the saving transaction
uses no optional hint. Retry successors carry the current persisted payload,
and a checkpoint rekey carries its current caller context too.

Internal-only markers retain their existing aggregate hint selection. Shadow
mode does not open an optional hint reader. This does not serialize a general
`ScopedRead` or room roster, and it does not complete durable composed
room/peer/guest/host-action context support.
