# Context-pack input workers

The shared context-pack path resolves the optional reader profile, room audience
and interlocutor set on a dedicated `context-pack-inputs` thread. HTTP context-pack
and the Context Board use that same path. The remaining query validation, media
embedding, audience narrowing, assembly and disclosure flow are unchanged.

`[limits] context_reads` bounds outstanding input workers. Its default is 2,048,
held in `CONTEXT_READS`; this is an operator-overridable lane choice recorded as
open in the owner's calls ledger, not a canon-mandated number. The existing fair
work line rotates among authenticated caller keys and asks the typed
`limits.context_reads` question when the line crosses the configured value. A
caller waits asynchronously for a permit without a new deadline or count
refusal. Cancelling that wait removes the caller's place before a thread starts.

One original scoped reader transfers its exact state and vault identity into the
worker, then returns to the same borrowed vault. Its authority, ceilings and
caches are not rebuilt. A session-overlay reader cannot be detached by this base
transfer. The complete request moves into the worker and back; only the already
authenticated `CoreAuth` value is cloned for the worker's synchronous calls.

The oneshot receiver belongs to the caller. Its sender detects caller drop before
work and between reader, room and interlocutor stages. This does not interrupt a
native read already executing. A failed thread start, unwind, failed delivery or
dropped receiver releases the work and its turn. An undelivered result drops
before the turn that admitted its worker. No worker uses Tokio's shared blocking
pool for this prefix.

The already-allocated interlocutor controls stay on the server's physical-memory
line while queued, in the worker and through pack assembly. The retained request
owns its third-party vector backing, every party string and the voice-session
string before its lease drops. This records actual capacities after allocation;
it neither pre-admits JSON decoding nor charges copies made by later resolution.

For the worker's principal-contact and explicit `ContactRef` lookups, each final
retained canonical claim body owns a separate lease for its relationship-set
vector capacity. The ordinary claim read still selects history projections and
reports errors before accounting starts. The contact fold moves only the value
out of each body; its relationship set drops before that body's lease. Leases do
not accumulate across contacts or across bodies already consumed by the fold.
This is post-allocation accounting, not admission. Channel-pair and voice-roster
lookups, ignored heads and intermediate history allocations are not covered.

This change does not complete contact-read or pinned-reference memory admission.
Canonical CLAIM decoding, history/projection scratch, other retained collections,
other request storage, auth clones and response-byte custody still need their own
physical-memory accounting. Future untimed memory waits must use this caller's
stop condition. There is no full-Q, runtime or throughput claim here.
