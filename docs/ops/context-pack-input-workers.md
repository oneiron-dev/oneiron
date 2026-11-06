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
projection door stays unchanged. History intermediates remain unadmitted. The
selected birth's value and predicate acquire post-allocation capacity leases
after its native decode and initial-weight check, before the fold consumes it.
The original body keeps its own guard until it drops, including while a
replacement is built.

The machine-history fold decodes its birth from the authenticated signed birth,
not the mutable target row. Its private event states borrow that same body and
still compare full birth values when joining branches. The history reader moves
the decoded birth into the final owned projection; the borrowed fold door makes
one copy for its returned projection. Branch grant maps and other fold scratch
still allocate and remain unadmitted. This transfer does not establish retained-input
FIFO progress or custody for a later typed copy.
The selected birth's unchanged value and predicate keep those same charges
through the fold, carrier checks, successor selection and owned projection.
The selected head takes those charges without remeasuring or copying either
field. A carrier-check error drops the projection before its storage charge;
a successor bypass drops the unused birth before releasing its charge. This
does not admit history decoding, fold scratch or scope-map growth.
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
the original counterparty string backing and notes array, including their actual
backing and guards, until its last use. It returns strings by borrow and notes through a
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

Hydrated context entities move their already-redacted JSON object into the
response field map. They do not clone that object's strings, arrays or nested
objects before collecting its same entries. Redaction and wire fields stay the same.

HTTP context-pack and context-board encode through an owned JSON byte writer.
Each append records the encoded vector's actual capacity after allocation.
The transport's shared byte owner keeps that same vector and its lease through
the last body-byte clone. A serialization failure keeps axum's existing 500,
plain-text content type and error text, with a separate charge for that error
buffer. Internal typed Board callers still receive the same `Json` response.
The standing-budget check uses the same byte owner while counting its JSON,
inside the original recording transaction and with the same error mapping.

Receipt and presence-notice construction append directly into their final
string. They no longer build a per-entry string vector or a joined intermediate.
Receipt labels retain the same uppercase percent encoding for reserved ASCII
and control-character UTF-8 bytes; other Unicode characters stay verbatim.
Presence text and non-owner ordering are unchanged. The four-byte control
scratch is UTF-8 scalar storage, not an engine size limit. Final strings and
any reallocations still occur before the response's capacity capture.

The `ai.reply` request fingerprint no longer needs a deep-cloned request. Its
owned message vector temporarily includes the exact route prompt for the
canonical request hash and ordered system-message digest. Both reads finish
before that one inserted message is removed. The ladder then receives the same
original request and still prepends its route prompt once. A fingerprint error
still ends the call before any provider send. Lower ladder request clones,
prompt strings and independent JSON values remain outside this custody slice.

In the stable-history layout, the prefix hash is computed before the owned
prefix string moves into its system message. The compact dynamic JSON object
also moves directly into the context user message before the caller's original
user message. The previous single-block placement trimmed this already-trimmed,
nonempty object and copied it; the message text and order remain the same.
The independent dynamic JSON value and lower request clones remain outside
this local buffer transfer.

After the provider answers and the original credential-live check passes,
`ai.reply` consumes the response's text parts in their original order. Its final
reply owns the first text buffer and appends later text directly, without a
borrowed-part vector or a separate joined string. Non-text parts stay excluded;
no text or only empty text still follows the original unavailable result.
Appending can reallocate and is not pre-admitted by this transfer.

Before building the dynamic JSON value, `ai.reply` moves the standing compiled
text into a local owner, then reuses that owned string for the prefix by appending
the same separator and evidence. It does not first copy the standing text into a
second prefix allocation; appending can still reallocate. The standing option and
its object fields remain present until the original JSON key removal, with an
empty compiled-text field. This avoids copying that discarded text while
preserving the original key positions and removal order, including an
insertion-ordered JSON map. The pack option, L2 extraction and removal order
are unchanged; the discarded pack value and standing metadata still allocate.

For that same internal reply response only, the discarded pack's result and
neighbor rows release their hydrated JSON field maps and stored vectors before
serialization. Row ids, counts, order, edges, other pack metadata and the L2 base
stay intact. The pack option and original key-removal sequence remain unchanged.
Normal HTTP and typed Board responses do not use this internal reply step.
The other discarded pack fields and the independent MEMORIES value still copy;
this does not admit or account for their allocations.

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

## Retained exact generation requests

An exact picked-model generation can keep one owned request through admission,
provider dispatch, wire fallback and cooling repasses. The shared generation walk
uses temporary read-only call views. General and source-projected generation keep
their original copied requests; streaming keeps its existing owned APIs.

The retained path binds the rung in place. It moves aside the original model,
locality, cache descriptor and segment manifest. It restores the original view
for the same post-admission route, on-device, source and probation checks, then
reinstates the already-admitted bound view without binding twice. The exact
original cache value is swapped back, not shifted down after a saturated index.
An empty configured rung prompt is still inserted. Successful replay capture sees
the original messages, as it did before. Drop restores that same original view.

The gate still derives and checks its admitted dispatch digest before starting
the permit. Borrowed concrete adapters use their real wire builders and preserve
digest-selected responses/chat routing. The local runtime has a required borrowed
generation operation. Own-server transports pass the actual serialized wire bytes
into their original runtime task or cancellable HTTP thread, not a cloned request.
Owned generation and streaming interfaces remain available with their old behavior.

This removes a deep request copy on the retained exact path. It does not admit
provider JSON or wire allocations, shifted prompt/manifest storage, request-vector
reallocation or other independent response memory. General fallback and streaming
copies remain. It is not a full memory-accounting or runtime proof.

When that gate carries a caller release, borrowed generation keeps it too.
Its released entry has the same entry-only default as the owned API; that
default is not proof that every transport rechecks before every physical send.
The OpenAI adapter forwards the actual release through its existing released
transport operation. Both the managed native transport and native-only local
transport carry it through shared shaping into the existing native wait,
session, plain-resend and send checks. The native-only path never gains an HTTP
fallback. Unrecorded capture and settlement behavior from the shared caller
remain intact. Other transport-wide release coverage is not claimed here.


## Reply prompt buffer custody

`ai.reply` keeps a separate lease on the server's same physical-memory line for
its owned route-prompt fingerprint string, taken standing text, assembled prefix,
compact board JSON and outgoing egress text. It records
each actual string capacity after allocation. Growing the standing prefix records
only the capacity increase; moving prefix and board into request messages keeps
their existing charge. It does not treat a move across a module as a drop.

The early layout moves the outgoing text into its system message, rather than
cloning it. After the original route-prompt removal, the egress check borrows that
same first text message. The stable layout keeps its separate outgoing string.
Both layouts retain their original text, roles, order, hashes and egress sequence.
The early layout releases its now-unused prefix and board before returning their
charges. An omitted whitespace-only stable prefix is dropped in the same way.
The temporary route prompt drops at its original post-fingerprint removal. The
separate stable-layout outgoing text drops after the original device-local egress
check has finished reading it. Request message text, including the moved early-layout
outgoing text, stays charged until the consuming exact-generation
await has returned and its original request has dropped, on both success and error.
The lease is declared before the owning locals and future, so an early return or
cancellation drops those buffers before their charge.

This is post-allocation custody only. It adds no admission, memory wait, cap or
refusal. Serialization and string growth can still allocate before capture and
can temporarily hold old and new backing. The independent dynamic JSON value,
MEMORIES copies, caller message, message-vector slots, provider/ladder copies,
configured rung prompt and other request or response allocations are not covered
by this string lease. They are not charged as if they shared these buffers.


## MEMORIES response buffer custody

The final Board response keeps its original MEMORIES section and a separate,
non-serialized capacity holder. The section drops before that holder. The caller
creates the holder before either raw producer and keeps it through the raw
assembly tuple. Each producer records the final section's capacities
before its next await: the retrieval path before advancing observations, and
the pins-only path before recording delivery. The same holder moves into the
response without another charge. The retrieval path also records its initial
successful projection, refreshed visible-row snippets, fallback pins-only
metadata, and successful explicit and manifest pin changes. Each update resizes
the same holder to the current section's actual capacities; it does not add a
second holder or charge. A later error drops the section before the caller
releases that holder. The public section type, optional wire field, response
schema and tuple payloads are unchanged.

This holder records the version string, actual row-vector slots, each row's id,
short id, content hash, asset reference, world, snippet and hook strings, and the
six optional companion strings. The section's own disclosure clone uses the same
stamp/disclosure capacity calculation as pack disclosure, but its independent
buffers have their own charge. All counts use actual vector or string capacities.
Other metadata's possible internal allocations are not inferred from its type.

Recording a Board turn still clones the section before the callback mutates the
response's turn receipt. That independent clone has a separate holder, declared
before the clone and populated from the clone's actual capacities. The callback,
recording transaction, refusal and rollback behavior are unchanged. It never
inherits the original response's charge.

These holders provide post-allocation custody, not admission. The producer's
final section stays charged through observation or delivery recording, raw tuple
moves, later board assembly and the response's last drop. Errors and cancellation
drop the producer or board payload before the caller's holder. A missing or
filtered-out section has no backing to charge. The independent turn-record clone
still needs its own holder.

The pins-only producer also records its initial metadata and each successful
explicit, manifest and hook pin change through the caller's same holder. If no
row survives, the empty section drops before its charge is cleared. The HTTP
caller keeps that holder through the response. The MCP caller uses a holder
from the same server memory account, declared before producing the raw section.
It drops only after that section has been rendered and dropped. The separately
allocated rendered sections do not inherit the raw section's charge.

Each pin operation also refreshes that same holder before propagating its
original mapped error. This records row backing left by an operation that
mutated the section before failing. On success, the ignored read-receipt vector
drops before this refresh, as it did before. The section still drops before the
caller releases its holder on an error.

Projection and pin construction scratch, allocation and reallocation peaks,
dynamic JSON copies, serializer buffers and other metadata backing remain
separate work. Section backing is recorded after a pin operation returns, not
while the operation is still building or replacing it. No clone is claimed
covered because it came from a charged source. No memory wait, size cap,
deadline, refusal, policy or format version changes here.

The pinned-row delivery receipt has a separate holder for the actual capacity
of its `Vec<EntityId>`. It never inherits the raw section's charge. Its private
constructor uses the same server memory account as the HTTP, MCP or run caller.
The delivery ids are stored before the holder, so they drop first. An in-place
receipt filter keeps the original vector and its capacity charge. Recording
moves the whole receipt into the existing blocking job, including the holder;
the charge follows that job's ids, not just the outer future awaiting its result.
Receipt order, error mapping and idempotency handling are unchanged. This holder
does not count the receipt's channel set or interlocutor internals, construction
peaks, or the independent vectors copied by later consumers.

The HTTP board's separate observation-id vector has a local holder on that same
server memory line. It records the vector's actual capacity after collecting
MEMORIES ids and after each extension with capability hits and named board rows.
The vector stays charged while the session lock is awaited and while the read set
observes those ids. It drops after the original observation block, before its
holder. Errors and cancellation also drop the ids before the holder.

The read set uses a separate local holder for each native point-read vector and
returned row batch, on that same server memory line. The capacity callback returns
the holder after recording the original id-only collection before the row read.
After a successful read, another holder records the returned vector's actual slots
and each owned body byte-vector's capacity before the original loop consumes them.
Each holder is declared before its buffer, so the buffer drops first on success,
read failure or unwind. These holders do not accumulate freed batches for the rest
of the request.

The same callback follows the private lifecycle path into each successor lookup.
It records that lookup's own target vector before its read, then its returned
batch after a successful read. Both holders stay inside that lookup; the original
kind filter, ambiguous-successor return and receipt restriction are unchanged.
Ordinary public observation methods use a no-op callback and keep their signatures
and behavior.

Each successor lookup also records the actual inbound-edge vector slots and each
present short-id string's capacity after the original edge query returns. Its
holder lives in the scope that consumes the original edge vector through the
same filter, map and collection. That scope ends before the resulting target
vector gets its holder. This does not assume that collection allocates a new
buffer: an allocation reused for the targets is not counted by both holders at
once. Temporary overlap during collection remains outside this post-allocation
accounting. Both observation reads construct only id targets. Their scoped-read
constructor sets `ReadRow.deletion` to `None`; missing or withheld rows yield an
empty slot rather than a deletion shell. Deletion metadata's optional request-id
string belongs to the separate short-reference read path, not these batches.
Decoded records, edge-query scratch, retained maps and later replay vectors remain
separate allocations. Allocation and reallocation peaks are not covered by these
holders.


## Chat capture buffer custody

The chat capture has its own capacity holders for the selected, settled MEMORIES
clone and its rendered fingerprint string. They use the server's same physical
memory line and record those allocations' actual capacities after construction.
The section uses the same selected version, row-slot, row-string, companion and
disclosure calculation as the Board response; it does not inherit the response's
charge. The capture payload drops before its trailing holders.

Settling starts with the same cloned version, companion and disclosure metadata,
the same copied budget, and an empty row vector. It clones only the rows the
original selection keeps, instead of cloning every input row and clearing those
copies first. The foreign/pinned/shown selection, ordering, row indices and
unmatched-render result are unchanged. Temporary per-section filter vectors
remain separate storage.

The existing live-turn and queued-action paths move that same capture into the
frozen context, then into the detached answer-recording task and its blocking
record callback. No consumer clones the holders onto different allocations.
The original no-record, unmatched-render, error and cancellation behavior stays
the same. The final record callback still borrows the original captured section.

This is post-allocation custody only. Temporary clones while settling rows,
filter scratch, world sets, auth, layout candidates, temporary emit assembly,
copied record text and other record-building allocations are not covered. Earlier
assembly internals, allocation and reallocation peaks, and retained-input FIFO
progress remain separate work. No memory wait, admission, cap, deadline,
refusal, policy or format changes here.


## Frozen chat receipt buffer custody

A capture carries a private handle to the same memory line its producer used.
Freezing uses that handle to create an empty lease before constructing the
receipt fields. It does not re-upgrade a queued action's weak server pointer or
add a new liveness branch. The freeze signature and both callers stay unchanged.

After construction, the frozen context records the actual capacities of its
receipt field strings, optional strings, activated-id vector slots and each id
string, plus its own request-digest string. These are independent allocations
from the capture's section and fingerprint. The frozen payload fields drop
before their trailing receipt holder through the same async and blocking owners.
A failed freeze still keeps its capture and omits only the receipt, as before.

This covers only the final frozen receipt tuple after allocation. Its temporary
system-message JSON, prompt stamp, hash serialization, later receipt-map copies,
record text and request-digest copies remain separate storage. No memory wait,
admission, cap, deadline, refusal, policy, schema or caller behavior changes.

## Escaping board row-ID buffer custody

Each final `ServedRows` row, replay-admission and source vector has its own
immutable payload owner. The owner records the actual vector capacity on the
producer's original server memory line after construction. Its vector drops
before its holder. An empty default has no backing or holder.

The keyed response still clones the entire extension and moves the same three
fields into its cached response. Each cloned vector receives a fresh holder for
its own actual capacity on the original memory line. No lease or source byte
count is copied to a different allocation. Replay still reads the same slices,
and a cached response reconstructed from storage captures its newly decoded
row vectors and moved source vector on that request's server memory line.

Both chat board paths move the row owner, not a naked vector. The live-turn
admission clone owns its separate row buffer. The queued-action path returns the
same owner to its existing caller, which reads the same source slice. The
admission and device-local release decisions are unchanged.

Converting a cached response to a stored entry still stringifies its rows and
admission list and moves its original source vector into the source stamps.
The local source owner keeps the holder while the stored entry is built. The
completed stored-entry wrapper owns that holder after its entry field, so the
source vector remains charged through the original synchronous settlement call
and drops before the holder on its return, error or unwind. The durable entry
and replay formats are unchanged.

These holders cover only the final row-ID vector backing after allocation.
Producer growth, temporary overlap, encoded and decoded entry buffers, newly
stringified row/admission lists, cached body/header copies, source-set copies,
allocation peaks and retained-input FIFO progress remain separate work. No
memory wait, admission, cap, deadline, refusal, policy or format changes here.


## Caller-bound canonical CLAIM DOM allocation

A canonical CLAIM read with `ClaimScopeReadMemory` uses the same owned
MessagePack parser, marker dispatch and depth checks as an unbound read. Its
allocation context borrows the caller's original memory line, cancellation
signal and distinct pinned-input count. Unbound reads still use the original
push and `take(...).read_to_end` allocation paths and create no context.

The bound path reserves each complete requested backing before its explicit
allocation or growth. A replacement reservation includes the new backing while
the old backing and any decoded child are still live. After the reserve, it
records the actual native capacity and retires the old backing. Collections
start empty and grow from their current capacity, bounded only by their actual
declared element count. Byte backing keeps the existing initial preallocation
bound, then grows explicitly; short reads and interrupted reads keep their
native decoding behavior. Strings and invalid UTF-8 move the same byte backing.

The DOM holder lives through canonical validation. After the top-level iterator
has dropped its keys, discarded fields and container backing, it measures the
remaining predicate, value, evidence, scope, session tag and raw relationship
backing. Splitting the value's and predicate's allocated charges creates their private
field holders without changing the shared ledger or making another admission.
Remaining DOM inputs stay held through history selection and typed relationship
allocation; that allocation's floor includes the original total across these
separate holders. The full-body terminal then transfers the evidence, scope and
session-tag backing into another trailing holder. Those fields drop before their
holder. The value-head terminal drops its unused metadata with the DOM instead.
The history-selected value and predicate record their actual capacities after
the birth decode and keep the same backing charge through their final consumer.
Unused projected metadata and relationships do not acquire a head charge. This
does not pre-admit the history decoder. Decode errors and allocation refusals
keep their distinct native result variants.

This reserves requested backing, not an allocator's unobservable excess capacity
before allocation. Excess capacity is recorded after allocation. It is not a
hard allocation-bound or multi-holder FIFO-progress proof. History projection
scratch, later typed copies and other consumers still need their own allocation
and last-use custody. No new
memory cap, deadline, default, wire format or refusal policy is introduced.


## Contact duplicate-head input retirement

The Vault contact-head collector still canonically reads every claim in the
original transaction and order. On the first duplicate live family predicate,
no selected value can contribute to a successful contact fold. It drops that
duplicate value and every previously saved value, including their original
memory holders, before the next claim read. The pinned-input sum then contains
none of that discarded backing; the caller's original pinned inputs remain.

The collector retains the duplicate flag and keeps all later native reads,
validation and history selection. A later read error still wins. If those reads
finish, it returns the same duplicate-head error before missing-field or typed
field validation. The Store-only collector and the nonduplicate path keep their
existing behavior. The collector is a private child module so the parent does
not cross the giant-file threshold.

This removes only input that is already useless once duplication is known.
Valid contacts still hold required values across later canonical reads. Their
retained-input FIFO progress, scalar staging, allocation peaks and other
remaining custody work are not solved by this change. No cap, deadline,
refusal, default, authority or wire-format policy changes.

## Contact scalar-head input retirement

The Vault contact-head reader parses identity, first-touch, status, creation and
update timestamps, revocation timestamp, opt-out, and promotional consent into
scalar results as their live heads arrive. It drops each scalar's original canonical
Value and read guard before reading the next claim. These results contain no
string, array, map, or canonical backing. Later reads pin only the retained
counterparty and notes values, in addition to the caller's own pins.

Scalar failures remain deferred. Every original canonical read still runs;
a later read error wins over duplicate-head, missing-head, and field errors.
If reads succeed, duplicate and missing checks precede the original field-error
order. The notes wire-type and first content passes still precede state
validation, and the second content pass still follows it. Opt-out parsing uses
stack key-validation scratch sized from the existing key array. Its result is
reported at the original field position. The body decoder uses the same
validator; the Store-only reader keeps its original collection and decoding path.

This retires scalar input backing, not all retained inputs. Counterparty and
notes can still remain live while another canonical read needs memory.
It does not establish FIFO progress, a global heap bound, or custody for a new
owned copy. The full retained-input and typed-output findings remain open.

## Stored claim source ownership

`Vault::stored_claim_body_in_txn` keeps the original stored row through an
`EntityRowSource` carrier. A base row borrows the same read transaction. A staged
single-valued row borrows from the same immutable overlay snapshot, retained with
the actual accessor keyspace and the caller's copied entity id. It no longer
clones that row's `Vec` before readability and canonical decoding. `body()`
borrows the carrier, not a transaction loan into a local owned buffer. The
existing callback still immediately decodes that body.

The borrowed lookup preserves Present, Tombstone, Passthrough, and clear-base
classification. The original dupsort branch runs before taking a read view and
keeps its existing owned-or-borrowed result. Existing owned `get` and snapshot
lookup callers keep their behavior. The source carrier captures only one read
view; it does not retry, reread base on a tombstone, or replace an error with a
captured-view fallback.

This port preserves the original readability, header, type, grammar, and history
order. The carrier itself establishes only stored-row readability and type,
not canonical grammar, a selected machine-history birth, or a grant. It holds the
whole snapshot and its native lease until the carrier drops, not just the desired
row. A changed writer preview can still allocate a snapshot `Arc` and grow the
native held-state list. Removing this row copy does not establish zero-heap
reads, free memory credit, retained-input/FIFO progress, or typed-output custody.
The contact collector's retained counterparty and notes remain separate work.


## Machine-history raw control reads

History control rows use `EntityRowSource` from the same accessor read position.
Base rows borrow the original read transaction. Staged rows retain the same
immutable overlay snapshot instead of cloning the raw `Vec`. The
`ControlRows::row` result still ties its lifetime to both the row provider and
the existing read transaction. A carried hit borrows its original bytes; only a
carried miss reads the same store row as before. No extra raw `to_vec()` copy is
made before canonical decoding.

The index, trusted pin, header, canonical decoder, shape, hash, signature,
handoff chain, and fold still run in their original order. Each source carrier
stays local to the original read scope. The owned advance cache and all decoded
and projected claim backing remain unchanged. In particular, a stored target
row is not a replacement for the history-selected owned birth or a grant.

A staged carrier holds its whole snapshot and native lease until it drops.
Changed writer previews can still allocate a snapshot `Arc` and grow the native
held-state list. Removing the raw row copy does not admit the decoded history
allocations or establish the contact collector's retained-input/FIFO progress
and typed-output custody.


## Contact existence and label projections

The server principal-contact existence check and core `ContactRef` label resolver
use a private contact projection. They keep the selected counterparty string and
its original lease, plus scalar state. Neither consumer needs notes after their
validation. The shared collector runs the original notes wire-type and content
checks, retains their exact typed result, then drops the notes array and its
lease before the next canonical claim read. Later reads pin only the input still
held by this projection.

Every original canonical read, current/history selection, live-head filter and
party opt-out fold still runs. Later read errors precede duplicate, missing and
field errors. The staged notes result surfaces at its original field position,
before state validation. The immutable notes already passed the same content
check, so the full decoder's repeated final pass cannot add another failure.

The public full memory-bound reader still retains its complete notes iterator.
Ordinary record APIs still return an owned `Vec<String>`. This projection does
not replace either capability or allocate a second notes vector. It removes only
unused notes backing from these two callers. Counterparty input, canonical
decoding and history allocations can still remain live across later memory
waits. Full retained-input FIFO progress and typed-notes output remain open.
