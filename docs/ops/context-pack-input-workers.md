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
position and completes every native field check. Its value-only terminal then
passes borrowed predicate and evidence to the same native history selector as
the full-body reader. It retains only the selected head's predicate, lifecycle,
stale flag and guarded value. It never materializes the raw relationship set
that this consumer does not use, so this door has no typed-relationship wait.
The full-body terminal still reserves the wire array's typed slots on the same
supplied memory line without a new deadline, allocates the canonical set and
settles its actual capacity. The MessagePack DOM has already been allocated and
is not admitted by either terminal. Unbound readers use the same validator
without a memory wait. The Store-only contact reader keeps its original
no-history selection, through the same value-only terminal.

The ordinary claim read keeps its history, fold and successor selection. At its
terminal history projection, it transfers the already-owned birth through the
same field updates instead of cloning another relationship set. The borrowed
projection door stays unchanged. History intermediates remain unadmitted; the
final projected body owns its own post-allocation capacity lease. The original
body keeps its own guard until it drops, including while a replacement is built.
Contact reads retain only each live head's predicate index and value for the
fold. The value owns a separate post-allocation lease on the supplied line.
The canonical decoder charges the current value's actual heap capacities before
the terminal selector; a selected history projection records its own value too.
The selector preserves actor observations, history-presence reads, successor
author checks and their error and short-circuit order. Source-collecting reads
use that same selector and visitor; ordinary reads retain no source-id list.
Strings include both valid UTF-8 String backing and invalid UTF-8 byte backing,
through the pinned rmpv capacity accessor. Arrays, maps, binary and extension
buffers use their actual capacities; nested values are counted once by borrow.
Moving a projected body's head out transfers only its value guard and releases
that body's already-allocated unused relationship set before its private
relationship lease. The raw value-only terminal never allocates that typed set. Guarded values stay in the head array through the last
borrow by the same canonical field decoder. No paid value is extracted to build
an unguarded map. The stored-map decoder keeps its original key checks and uses
that same field validator.

A memory-bound contact lookup returns an opaque `CounterpartyContactRead`, not
an unguarded `CounterpartyContactRecord`. The common field decoder validates by
borrow, using the record's same scalar invariants and note checks. The read keeps
the original counterparty value and notes array, including their actual backing
and guards, until its last use. It returns strings by borrow and notes through a
borrowed iterator; it does not allocate a second string or a typed notes vector.
Only the eight scalar fields are copied. The party opt-out fold runs through the
same store hook on the actual counterparty and scalar state, and still changes
only `opt_out` and `updated_at`. Original unbound record APIs keep owned results.
Their private conversion checks that the retained values have no memory guard,
including a zero-byte guard, before allocating an unguarded record.

The server's principal-contact check consumes only existence. Explicit
`ContactRef` resolution reads status and first-touch, then moves the original
counterparty value and its guard into a private shared label holder. Both Active
and Revoked entries retain that backing. Cloning an interlocutor set or a
disclosure context shares this immutable label; it does not copy its string or
claim that an input guard accounts for a different allocation. Public ordinary
label constructors retain their owned-string behavior. Debug, equality and
serialization still use the same label text.

The shared holder's own allocation is not admitted here. Stamps, notices,
receipts and response serialization still produce distinct output strings or
bytes; the retained label's guard does not account for them. The borrowed
contact terminal and label transfer add no allocation admission or memory wait.

The server response keeps a separate post-allocation lease for its own
interlocutor stamp vector, each speaker string, and the disclosure assembly's
mode, notice, emit stamp and stamp vector. It counts actual vector slots and
string capacities, including the non-serialized emit stamp. The response owns
these fields before its guard drops. Its Board embedding moves that same
response; it does not copy a charge onto independently cloned assemblies.

HTTP context-pack and context-board encode through an owned JSON byte writer.
Each append records the encoded vector's actual capacity after allocation.
The transport's shared byte owner keeps that same vector and its lease through
the last body-byte clone. A serialization failure keeps axum's existing 500,
plain-text content type and error text, with a separate charge for that error
buffer. Internal typed Board callers still receive the same `Json` response.
The standing-budget check uses the same byte owner while counting its JSON,
inside the original recording transaction and with the same error mapping.

This is output custody, not pre-allocation admission. Serialization may still
allocate before its capacity is recorded, and reallocation may temporarily
hold old and new backing. Independent MEMORIES disclosure clones, reply JSON
values, prompt strings, other response fields and byte-owner bookkeeping are
not covered by these selected disclosure and wire-buffer leases. No memory
wait, deadline, cap or refusal is added by this output path.

The fold still sees the first duplicate only after every claim has been read,
so a later native read error retains its original precedence. Ignored heads
release their own guards too. Where the full-body terminal admits relationship
storage, its memory floor includes the original caller's request controls,
earlier retained values and the current value still held by that caller.
These are distinct pinned inputs, not second ledger charges or a sum of other
workers' leases. An impossible required peak returns the original typed floor.
That check alone does not resolve FIFO waits behind an earlier request that
needs retained inputs released. Removing the contact door's unused-set wait
removes that particular hold-and-wait edge, not the wider admission problem.
Channel-pair and voice-roster lookups stay unbound.

Native store and validation errors retain their existing response mapping. A
memory floor is `MEMORY_FLOOR` (507, with `needed` and `available`); a stopped
memory wait is `MEMORY_WAITED_OUT` (503, with `needed` and `waitedMs`). Both use
the existing core error envelope and keep the original refusal distinct.

This change does not complete contact-read or pinned-reference memory admission.
MessagePack DOM decoding (including allocation before a value is charged),
history/projection scratch, other retained collections, other request storage,
auth clones and the remaining response-byte copies still need their own physical-memory
accounting and admission. Retained-input FIFO progress remains open. Future untimed memory waits must use this caller's
stop condition; the full-body relationship-set wait does so. There is no full-Q,
runtime or throughput claim here.
