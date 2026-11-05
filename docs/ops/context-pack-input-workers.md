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
work and between reader, room and interlocutor stages. Ordinary native computation
already executing is not interrupted. A relationship-set memory wait uses the
same sender's closed state to leave its original memory line. A failed thread start, unwind, failed delivery or
dropped receiver releases the work and its turn. An undelivered result drops
before the turn that admitted its worker. No worker uses Tokio's shared blocking
pool for this prefix.

The already-allocated interlocutor controls stay on the server's physical-memory
line while queued, in the worker and through pack assembly. The retained request
owns its third-party vector backing, every party string and the voice-session
string before its lease drops. This records actual capacities after allocation;
it neither pre-admits JSON decoding nor charges copies made by later resolution.

For the worker's principal-contact and explicit `ContactRef` lookups, the single
canonical CLAIM decoder validates relationship ids at their original wire
position, then completes every native field check before admitting typed
relationship-vector storage. It reserves the wire array's typed slots on the
same server memory line without a new deadline, allocates the canonical set and
settles its actual capacity. The MessagePack DOM has already been allocated and
is not admitted by this step. Unbound readers use the same validator without a
memory wait.

The ordinary claim read keeps its history, fold and successor selection. At its
terminal history projection, it transfers the already-owned birth through the
same field updates instead of cloning another relationship set. The borrowed
projection door stays unchanged. History intermediates remain unadmitted; the
final projected body owns its own post-allocation capacity lease. The original
body keeps its own guard until it drops, including while a replacement is built.
Contact reads retain only each live head's predicate index and value for the
fold. Moving the value out releases that body's unused relationship set before
its private lease, before the next claim read can wait. The fold still sees the
first duplicate only after every claim has been read, so a later native read
error retains its original precedence. Ignored heads release their own guard too.
Before each admitted allocation, the memory floor includes the request controls
still held by this worker. This is distinct pinned input, not a second ledger
charge or a sum of other workers' leases. An impossible required peak returns
the original typed floor. Channel-pair and voice-roster lookups stay unbound.

Native store and validation errors retain their existing response mapping. A
memory floor is `MEMORY_FLOOR` (507, with `needed` and `available`); a stopped
memory wait is `MEMORY_WAITED_OUT` (503, with `needed` and `waitedMs`). Both use
the existing core error envelope and keep the original refusal distinct.

This change does not complete contact-read or pinned-reference memory admission.
MessagePack DOM decoding, retained claim values, history/projection scratch,
other retained collections, other request storage, auth clones and response-byte
custody still need their own
physical-memory accounting. Future untimed memory waits must use this caller's
stop condition; the relationship-set wait above does so. There is no full-Q,
runtime or throughput claim here.
