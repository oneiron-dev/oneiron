# Queued tagging identity hints

A base witness marks its turn in the same write transaction. The marker keeps
its existing turn/checkpoint/stack dedupe key and the existing live/bulk class,
lease, backoff and retry chain.

The witness also carries its original optional identity-hint reader. The stored
reader represents the original `Memory` read: the actual actor and actor class,
an explicit authority position, and the original destination ceiling. A
credentialed position keeps
every effective fact of the original bound verified read proof. An
uncredentialed position uses the native grant-bound reader. If the same witness
write already held a native Owner reader for its assertions or held tags, or
already opened a native Owner key to admit a quote, it records that Owner
position instead. Capturing the position opens no new read.
A host-action lane carries an explicit unknown, not the internal hint aggregate.
A room-turn reader also needs that witness's already-opened native assertion,
held-tag or quote key. Capturing it opens no new read. Its room, caller, thread
and personal/held position travel as private data, beside an opaque reference
to the original shared monotonic turn terms in this vault open. No room roster,
peer read key or authority is serialized.

The live reference is weak: a queued job does not extend the original turn's
lifetime. If that original position is gone, or the vault has reopened, the
worker keeps the full candidate set. This supports only a still-live original
room turn, not complete durable room context. While it exists, the worker uses
the native room/thread constructor and its current standing, roster and peer
keys. It meets the current terms into the SAME original shared terms, never a
snapshot or a fork. Later narrowing observed by the original turn therefore
still binds the queued reader. The saving reader holds those shared terms
through its native per-row checks. Weak entries are pruned on capture and open;
no strong queued turn, new retention cap or writer refusal is added.

The destination keeps its original on/off-device flag and every carried machine
and proof key, including unknown destinations and proof facts not yet used on
device. The worker reapplies that ceiling through the ordinary native handle.
Each saving snapshot revalidates the carried machine keys and the current world
recipient settings. Stored destination facts confer no read or machine authority.

An uncredentialed reader's fresh native Owner kind must match its captured
position. A grant-bound position cannot become an Owner reader after a
promotion. An Owner position cannot be replaced by a later grant-bound reader.
Either mismatch supplies no optional hint. Without an already-held reader or
quote key, an uncredentialed Owner remains unsupported and supplies no optional
hint. Stored
positions never construct an Owner key: every supported reader goes through
the ordinary native read-key builder again.

Before saving, the worker rebuilds every supported captured reader through the
ordinary native read-key builder. Actor binding, current grants and proof
liveness are checked there. In the saving transaction, an optional hint counts
only source TURN/MESSAGE contributions and candidates that every captured
reader admits through the native scoped checks. An unknown or missing reader
leaves the full candidate set in place. Expiry or revocation is
checked by the native live-proof guard for each source and candidate: a false
result supplies no hint, while an error is not treated as an absent grant. No hint text is returned. Other reader failures record a
`hint_read` failure code and use the marker's existing retry path; they are not
silently treated as an absent hint.

Deduplication does not make one caller's reader stand for another. Internal
bookkeeping does not clear a carried caller reader. Equal caller contexts may
share it. Distinct captured contexts remain distinct in the marker payload;
each must admit a hint's sources and candidate in the same saving snapshot.
A hint never combines permissions from different readers. If the marker's
context changed after the worker prepared its readers, the saving transaction
uses no optional hint. Retry successors carry the current persisted payload,
and a checkpoint rekey carries its current caller context too.

Internal-only markers retain their existing aggregate hint selection. Shadow
mode does not open an optional hint reader. This does not serialize a general
`ScopedRead` or room roster, and it does not complete durable composed
room/peer/guest/host-action context support.
