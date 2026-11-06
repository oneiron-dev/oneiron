# Native copied media-query memory

A native pipeline owns separate copies of a media query's space string,
embedding vector and kind-filter vector. These copies are distinct from the
returned seed storage described in `media-seed-memory.md`.

A host can supply its existing memory line through `media_query_memory` on a
pipeline or context-pack builder. The server context-pack route supplies its
own line before adding media queries. Each push records the actual retained
outer-buffer capacity increase and the new query's owned inner capacities.
The concrete element sizes are used. This is post-allocation accounting, not
admission before allocation.

The private owner keeps its query buffers before its accounting fields, so the
buffers drop before their charge. A deep clone records that clone's actual
capacities on a separate lease on the same supplied line. Context-pack L2 and
neighbor plans and retrieval-loop plans keep their own copied storage charged
until those owners drop. Reads, hashing and trace inputs still borrow the same
query fields.

An unbound native builder remains usable. It gains no global memory line,
refusal, configured limit, wait, floor or timeout. Binding this owner does not
change media embedding, validation, authority, ranking, cuts, results or
receipts.

Core query supplies its existing server memory line to seeded retrieval. The
MCP adapter borrows that same host-supplied line and forwards it through its
fresh actor-bound reader to both seeded query and context-pack construction.
An adapter built without a line keeps its previous unbound behavior. The query
helper lives in the adapter's `media_query` child; its native search and error
handling are unchanged apart from this resource argument.

When bound, the adapter also records the actual capacity of the separate
borrowed tuple-view vector made by its seeded query helper. Only the vector's
backing storage is counted. Its space, embedding and kind-filter references
borrow the seed buffers; those buffers and the pipeline's owned copies stay
with their separate owners. The view drops before its local lease on both
success and error, including unwinding. An unbound adapter remains usable.

Opt-in replay capture also records the actual backing capacities of its
temporary media-list, kind-override, BM25-field and vector-evidence
`Vec<Value>` buffers. Each temporary stays alive through its existing JSON
serialization and drops before its local lease, including the vector-evidence
buffer moved into the existing serialization expression. These charges use the
same supplied line and leave an unbound capture usable. They cover vector slots
only, not the temporary objects' inner storage or the retained replay JSON.

An `AnyOf` corpus replay also records the backing capacities of its temporary
hex-ID vector and each owned hex string. The existing ID expression stays at
its JSON field, so field evaluation order is unchanged. The vector moves into
the serialization temporary while the enclosing arm keeps the lease alive.
The source IDs and copied retained JSON are outside this charge.

Sorted access-factor override and community-session usage replay also record
the actual backing capacities of their temporary vectors and each newly owned
hex-ID string on that line. Their borrowed factor or count values and source
maps are not owned by the temporaries. The existing collections, sorts and JSON
field evaluation stay in place. Each lease survives its returned vector's
serialization temporary, but does not cover the retained replay JSON.

World-authority replay records its two temporary hex-ID vectors and optional
owned default-claim hex string on the same line. Only those new backing
capacities are counted. Source authority sets, source claim IDs and retained
JSON are separate. The existing field order and authority values are unchanged;
the enclosing serialization scope keeps the lease past its ID temporaries.

Replay also records owned temporary strings used for a single corpus ID,
debug-rendered input fields, canonical repository references and metadata-hash
hex values. Each string is counted by its actual capacity on that line. A local
accounting closure moves the same string onward; its lease stays outside the
closure until the capture ends. Source IDs, source hash buffers and retained
JSON are separate owners.

The shared replay identity also holds the actual backing capacities of its
media-space vector and two copied metadata hash buffers on that line until the
native attempt releases the identity. Each hash copy is recorded immediately
after its existing read, so a later read error also releases its charge after
the buffer drops. Each successfully decoded space declaration's owned ID
string is also recorded once on that lease, separately from the query's own
space ID. Its buffers are declared before the private lease. The space
declarations' sets and maps remain outside that charge. Native declaration
checks, floors, hashes and capture gates stay unchanged.

Replay capture also records the actual capacities of the two copied query and
corpus-snapshot reference strings. A private per-attempt lease stays after the
payload fields and moves into the pack before its replay-input local. A retry
replaces the old payload before its old lease. The original strings remain
charged through replay metadata patches, record construction and borrowed
writes, until that original payload drops. Public replay types, their deep
clone and serialization behavior stay unchanged. The provisional writer's
detached record clone owns different backing and is not covered by this lease;
neither are serialized row bytes or later decoded rows.

The original captured replay config records its actual owned string capacities,
array slot capacities and recursively owned children, including object-key
strings. These are the retained `Value` buffers, not the distinct transient
serialization inputs. Object-map buckets and number internals remain unpriced.
The private per-attempt accounting owner measures the final config after all
capture joins. Each of the two later policy metadata assignments keeps its
existing evaluation and error behavior, then measures the updated config after
the replaced value drops. It records the new extent before releasing the old
tracked extent, so repeated patches neither release live backing early nor
accumulate stale charges. Reference-string charges stay separate within the
same lease. No config walk or new memory line is added to an unbound capture.
The detached record clone's config remains separate from this original owner.

The canonical provisional writer separately records those same two reference
capacities and the config's known backing on its deep-cloned record, using the
same optional supplied line. Both config owners use the replay-data type's
shared capacity calculation, but each measures its own actual buffers after
construction or cloning. The cloned config's charge does not inherit the
original's capacities or lease. Its private owner keeps the whole cloned
record before that separate lease and moves by value into the detached write.
Staging consumes the whole owner, so neither an unstarted write nor a write
error can release the lease before the cloned payload. The clone's object-map
storage, number internals and other record fields remain outside that charge.
Existing queue behavior is unchanged.

The detached clone also records the actual slot capacities of its signal,
result-ID, score-breakdown and degradation vectors on that same private lease.
Each uses its native element size. Each cloned score-breakdown entry also
records its component vector's actual slot capacity, separately from the outer
score-breakdown vector. Component fields and degradation variants have no
owned inner storage. These are separate buffers created by the record clone,
not the original pipeline's vectors. The slot charge applies even when the
cloned record has no replay inputs, provided the caller supplied the line.
The same clone also records the actual capacities of its optional query-expander
ID and empty-reason strings. These are outer record fields, separate from the
two nested replay references and config strings. Absent fields and strings with
zero capacity add no string backing; no length estimate or extra copy is used.

A present cloned trace records its per-channel vector's actual slot capacity,
each channel's candidate vector and the candidate vectors in its fused,
blended, reranked and final stages. Each candidate vector includes its entries'
component-vector backing, using the same capacity calculation as the cloned
record's top-level score breakdown. These cloned buffers are distinct even
when their entries describe the same results. All extend the same private
lease and single materialized charge. An absent trace adds no trace backing;
an unbound caller performs no added accounting walk. Serialized row bytes and
later decoded records remain separate.

A present cloned policy trace also records its decision vector's actual slot
capacity using the native decision size, on the same private lease and
materialized charge. Each decision's state, action and tier are inline within
those slots; they own no separate backing. The policy identity and envelope,
and the record's state, turn, action, quality and confidence adjustment also
own no separate backing. An absent policy trace adds no decision backing.
This does not price serialized or later decoded copies, config map storage,
number internals or construction peaks.

The canonical detached provisional stage separately records the actual backing
capacities of its encoded retrieval-row key and value after encoding, once on
that same private lease. It uses the existing typed staged-row writer without
re-encoding or copying either buffer. Both encoded buffers stay alive through
the native put and drop before the cloned record and its lease, including write
errors and unwind. An unbound caller keeps the original direct put path without
added accounting. This covers only the encoded key and serialized value on that
bound detached path. Serialization scratch, keys and values of marker, index,
session and other unbound writes, finalized rows and later decoded records are
separate allocations outside it.

Before the provisional stage's original retrieval-row put, the same optional
caller lease also records its original lookup key's actual capacity. A found
existing row still triggers direct by-turn deletion, followed by the original
trace-fork cleanup. The direct turn delete records its original encoded key's
actual capacity before the same operation; a record without a turn still does
nothing. The fork cleanup reuses its existing capacity accounting on that same
lease, including its original fallback scan when required. No extra lookup,
scan, encoding, copy or lease is added.

The pre-put lookup still propagates errors, unlike the fork helper's existing
error-to-scan fallback. The existing-row scope, cleanup order, validation and
later puts are unchanged. Native keys and cleanup buffers drop before the
caller lease, which conservatively keeps their known charges until it drops.
An unbound stage uses the same native operations without capacity accounting.
This key and cleanup accounting does not cover the separately decoded
existing row and trace, raw value copies, overlay copies, database pages,
transaction scratch, allocation peaks or a full working-set bound. Other
pre-put and marker/index allocations remain separate.

When that original pre-put lookup finds an existing row, the same optional
caller lease separately records four stable parts of this owned decode before
cleanup: the actual slot capacities of its signal, degradation and
policy-decision vectors, using their native element sizes, and its optional
query-expander ID string's actual capacity. These are the existing row's own
buffers, not the incoming record's fields or the finalizer's separate decode.
No extra decode, copy, scan or lease is made. An unbound stage adds no capacity
work, and absent optional fields add no backing.

These four buffers stay unchanged through the original cleanup and drop at the
end of the existing-row scope, before the caller lease, including errors and
unwind. Their known charge stays conservative until that same lease drops.
The lookup's error propagation, validation, cleanup order and later puts are
unchanged. Raw value copies, allocation peaks and a full working-set bound
remain outside this charge.

That same existing-row measurement also includes its result-ID vector's actual
slot capacity, its score-breakdown vector's actual slots and each entry's
component-vector backing. A present trace adds its per-channel vector's slots,
each channel's candidate vector, and the fused, blended, reranked and final-stage
candidate vectors, including each candidate's component-vector backing. Each
outer buffer uses its native element size; inner component backing is counted
separately, once. Matching results do not make these distinct vectors share
storage. No vector is copied or changed for this measurement.

These buffers are part of this same owned decode and stay unchanged through
cleanup until the existing-row scope drops before the caller lease. Their known
capacities join the same materialized observation and stay conservative until
that lease drops, including errors and unwind. An unbound stage adds no walk.
The same observation also includes the existing empty-reason string's actual
capacity and any replay query and corpus-reference string capacities. Replay
config backing uses the lower native calculation: string capacities, array
slots at the native value size, and recursive child values and object-key string
capacities. These are this decode's own buffers, not the incoming record or a
separate finalizer decode. Absent fields add no backing. No extra read, clone,
lease or config mutation is made.

This known replay backing excludes object-map storage and number internals.
The measured buffers stay unchanged through cleanup and drop before the same
caller lease, which conservatively retains their charge until it drops.
Remaining decoded backing and the fork helper's separate decode remain outside
this charge, along with raw-read and overlay copies, database pages,
transaction scratch and allocation peaks.

At that bound provisional stage's original false-branch marker put, the same
caller lease separately records the typed staged row's actual encoded key and
value capacities. The main retrieval-row put only reborrows that lease, so it
remains available for the marker. Each row is encoded once and reaches the
same declared-table admission and VaultMeta write. The marker's native value
remains the same literal byte. No source record or encoded buffer is copied.

The marker's staged buffers drop in their original branch scope before the
caller lease, including put errors and unwind. Their known capacities stay
charged conservatively until that lease drops. The published branch and
unbound direct puts are unchanged. Encoding allocation peaks, overlay copies,
masked values, database pages and transaction scratch remain outside these
charges; this does not establish a full working-set bound or a compiler or
runtime result.

A bound context pack also carries that same supplied host-memory handle through
its run and deferred-pack owners after the pipeline is consumed. Each terminal
passes it to the original canonical or session finalizer. The canonical
detached finalize owns its original payload and an optional private lease in
one self-consuming owner, with payload fields before the lease. Session-overlay
and admitted-base finalizers lend their local optional lease only inside the
original synchronous write. The session route, saver admission and discard
behavior remain unchanged.

At the existing finalized retrieval-row put, that lease separately records the
actual backing capacities of the native typed staged row's encoded key and
serialized value, once. The same staged buffers reach the same put and drop
before the lease on success, error and unwind. An unstarted detached write
keeps its payload and lease together. An unbound terminal keeps the original
direct put without an added accounting walk or a new memory line.

The canonical detached finalizer also records the actual backing capacity of
its existing copied surfaced-ID vector, using the native ID element size. It
creates the same optional lease before that copy and records its capacity after
the copy. The queued owner keeps the vector before the lease and consumes the
whole owner when staging, so the copied input drops before its charge even
when the write never starts or fails. The caller's original IDs, the separate
provisional record and the later decoded record are not this allocation.
Session-overlay and admitted-base finalizers borrow their caller's IDs without
making this copy, so their input handling is unchanged.

The original surfaced-ID vectors in the structured, projected, post-filter and
serialized pack terminals have their own optional local leases on the same
supplied host-memory line. Each lease is declared before the original vector
collect or serializer call. After that same operation, it records the vector's
actual capacity using the native ID element size. The original vector or
serialized telemetry owner drops before the lease, including on an earlier
finalization error. Serialized results return bytes and stats or a receipt,
not the telemetry's ID vector. No input copy or borrowed-slice charge is added.
Unbound terminals add no capacity work. These original allocations remain
distinct from the detached input copy and later decoded-record copies.

The serialized terminals also lend that same optional caller lease to the
private telemetry serializer. After the original prepare call, it records the
actual capacities of the prepared results and neighbors group vectors and
each group's entity vector, using their native tuple and entity slot sizes.
The prepared groups are consumed inside serialization and drop before the
caller's earlier-declared lease. Their initial observed extent is retained
conservatively until that lease drops; no earlier shrink or extra lease is
added. The returned ID vector is distinct and gets its existing post-return
observation on the same caller lease.

That same initial observation also records each prepared entity's owned ID
string capacity and field-vector capacity, using the native `(String, Value)`
slot size. Each surviving field adds its own key-string capacity and known
value backing. The shared lower-store value calculation records owned string
capacities, array slot capacities and recursively owned children, including
object-key strings. Inline entity and field slots are not counted twice.
These are distinct prepared copies, not the source pack's buffers. Empty
buffers and primitive values can add no deep backing.

The initial known extent stays conservatively charged until that same caller
lease drops, with no early release or extra lease. Object-map storage, number
internals, sanitized pack copies, internal preparation and rebudget scratch,
later growth and replacements, L2, stats, output bytes and construction peaks
remain outside this observation. No capacity walk runs when unbound. Public
serialization entry points and the original preparation, dispatch and output
operations are unchanged; the private serializer and its two callers only
pass the existing optional lease.

After the existing finalizer decodes a retrieval row, the same optional lease
also records four stable parts of that decoded record: the actual slot
capacities of its signal, degradation and policy-decision vectors, using their
native element sizes, and its optional query-expander ID string's actual
capacity. These buffers stay unchanged until the decoded record drops inside
the staging call, before the caller's lease. They are distinct from the
original capture, detached provisional clone and encoded final-row buffers.
An absent field adds no backing, and an unbound finalizer adds no walk.

The first observation uses the same known-backing helper as the pre-put and
trace-fork lookups. In addition to those stable fields, it includes this
decode's result-ID and score vectors, component vectors, all trace vector
backing, empty-reason string, replay reference strings and known config
backing. Later old-buffer measurements retain byte counts for their existing
retirement steps; they do not add those already charged buffers again.
Unbound finalizers still perform no added accounting walk.

After its existing surfaced-ID assignment, that finalizer also records the
actual backing capacity of the newly copied result-ID vector, using the native
ID element size. The assignment still drops the old decoded ID vector first;
that discarded backing is not included in this charge. The new vector remains
unchanged until the decoded record drops before the caller's lease. It is
separate from the canonical detached input copy and from borrowed caller IDs.
The existing copy, remaining mutations and row writes are unchanged.

After the existing score and trace mutations finish, the same optional lease
records their current backing capacities. This includes the new surfaced-score
vector, its entries' component vectors, the retained per-channel vector and
candidate/component vectors, and each fused, blended, reranked and final-stage
candidate/component vector. Outer slots use their native element sizes; inner
component buffers are counted separately, once. The final-stage clone and the
surfaced-score vector own distinct backing even when their entries match.
That postmutation count excludes discarded decoded score vectors and the
components removed by the existing retains. The current buffers remain unchanged
until the decoded record drops before the caller's lease. An unbound finalizer
adds no accounting walk.

After the existing empty-reason move and replay-pack metadata assignment, the
same optional lease also records the current empty-reason string, replay query
and corpus-reference strings, and the replay config's known backing. The config
uses the same lower capacity calculation as the original and provisional
owners, but measures this decoded record after its last mutation. Its actual
string and array capacities and object-key strings include any moved pack
metadata and newly inserted pack key. No extra input copy is made or charged.
That postmutation count excludes the old decoded empty-reason string and
replaced pack metadata, which have already dropped. Absent replay inputs add
no replay backing, and an unbound finalizer performs no added walk.

The same lease also records two old decoded buffers before their existing
replacements: the result-ID vector, and the top-level score vector with each
entry's component vector. Each uses its actual capacity and native element
size. The result-ID charge is released after its original assignment drops the
old vector, before the existing new-ID postcount. The old score charge starts
before the surfaced-score collection and is released after that collection
replaces and drops the old score vector. The existing current score and trace
postcount stays separate. Neither old buffer's charge is released early or
counted twice. An unbound finalizer adds no accounting walk.

These old-buffer charges do not cover the simultaneous new allocation during
replacement or the new score collection's construction peak. The original
copies, replacement order, failures and row writes stay unchanged.

The original surfaced-score collection also records its actual outer vector
capacity immediately after allocation. Each original entry clone records its
new component vector's actual capacity before the entry enters the collection.
Those known backings stay on the same lease through construction and the move
into the final record. The original collection reserves for the surfaced-ID
count and pushes at most once per ID, so its outer backing does not grow during
this loop.

The later current score/trace measurement still records all of its original
buffers. Only after that measurement does the lease release the remembered
construction charge for the same top-level score backing. This add-before-release
transfer keeps the live backing covered and leaves no duplicate final charge.
It briefly counts the transferred backing twice, rather than releasing it
while live. The separate final-stage clone remains in the current trace charge.
Unbound finalizers add no capacity work. Allocation internals before the new
post-allocation measurements, pre-growth admission and a full construction peak
remain outside these charges.

The decoded trace's known backing joins that first observation. Immediately
before the original trace mutations, a shared local calculation remeasures its
already charged old extent: per-channel slots, every channel and stage
candidate vector, and each candidate's component vector. It uses the same
capacities and native element sizes as the current-trace measurement, without
adding the old charge again. These trace buffers are distinct from the
top-level score vector, canonical inputs and provisional record clone.

The original retains keep candidate-vector backing while dropping removed
entries' component buffers; the original final-stage assignment drops its old
candidate and component buffers. The remembered old trace extent stays charged
through these operations. The current top-score and trace measurement adds its
unchanged known total first, then releases only that old trace extent before
the existing surfaced-score construction transfer. This conservatively holds
freed backing until the transfer and briefly counts retained backing twice,
without releasing live backing early or leaving a duplicate final charge.
An absent trace contributes zero and an unbound finalizer adds no trace walk.
Initial decoding, clone allocation internals, pre-growth admission and a full
construction peak remain outside this charge.

The canonical detached finalizer also records its original owned empty-reason
string and pack metadata before queuing the existing write. The string uses its
actual capacity; the same lower replay calculation measures the pack value's
known string, array-slot and object-key backing. These finalization inputs own
separate storage from the captured replay config, the provisional record clone
and the later decoded record. No input copy or new lease is made, and an unbound
caller performs no added accounting walk.

A private byte count travels with those same inputs and their existing lease.
After the original moves into the final record, the existing current-record
measurement adds its full known backing before releasing only that carried
input count. This briefly counts moved backing twice without leaving a live
gap or a duplicate final charge. Unused pack metadata drops at its original
assignment before its input charge is released. On a missing row or an earlier
error, the original payload still drops before the same lease. An unstarted
write retains both in the same owner.

Synchronous session-overlay and admitted-base finalizers also observe their
owned empty-reason string and pack metadata on their existing optional local
lease, before the original row lookup and decode. The admitted path keeps its
original admission first. Both use the same actual string-capacity and known
pack-backing calculation as the detached input charge, carry that measured
extent into the shared staging body, and retire it only after the current
record's full known backing is added. They do not charge the caller's borrowed
surfaced-ID slice or make another input copy. Missing rows and earlier errors
drop the original owned payload before the local lease; unbound calls add no
walk. The detached path's already-paid inputs are unchanged.

The first decoded-record observation also includes the old empty-reason
string, both replay-reference strings and the config's full known string,
array-slot and object-key backing through the same lower calculation. Before
the original empty-reason and pack replacements, the finalizer remembers that
full old extent without adding it again. This includes the retained pack key
and other unchanged replay fields; it is not just the discarded pack value.
Absent fields add no backing.

After the same original assignments, the lease adds the full current known
empty-reason and replay extent first, then retires the full remembered old
extent, then the original input-backing charge. Unchanged replay references
and config buffers remain paid throughout this transfer. The old empty-reason
and replaced pack values have already dropped, while retained backing may
briefly be counted twice without a duplicate final charge. These decoded
buffers remain distinct from the incoming finalizer inputs, original capture
and provisional clone. An unbound finalizer adds no walk. This remains
post-allocation accounting, not construction-peak, config-map, number-internal
or full-working-set coverage.

The finalizer's private trace-membership scratch uses a separate copied ID
vector, sorted and deduplicated only for membership lookup. The caller's ID
order, retained candidate order and final-stage clone stay unchanged. This
replaces the former temporary hash set; it is not the canonical detached input
copy or the final record's result-ID vector.

When bound, the same lease records that scratch vector's actual capacity using
the native ID element size immediately after copying, before sorting or trace
filtering. Deduplication keeps its backing capacity. The vector drops at the
end of the original trace scope, then only its remembered byte count is
released before the current score/trace measurement. No zero-byte release is
added for an absent or empty allocation. On unwind, the local vector still
drops before the caller's lease. An unbound finalizer keeps the membership
behavior without capacity accounting. This prices known vector backing, not
allocator internals, the copy's allocation peak or a performance result.

The same bound finalizer also records the actual encoded key and value
capacities of its by-turn and trace-fork index puts. Each uses the original
typed table's staged row once, then the same native put. The turn index still
skips a record without a turn, and the fork index still skips an unknown hash.
An unbound finalizer and other existing fork-index callers keep their direct
put paths. The original turn-index, main-row, fork-index and provisional-delete
order and errors stay unchanged.

These temporary index buffers drop inside their original write scopes before
the caller's same lease, including write errors and unwind. Their known
capacities stay charged conservatively until that lease drops. Session-overlay
copies and other storage made by the put are separate allocations, not these
staged buffers. Provisional-delete keys, other index and retention buffers,
encoding allocation peaks and a full working-set bound remain outside this
charge. No new memory line, refusal, wait or configured limit is introduced.

The same bound finalizer records the actual encoded provisional-marker key
capacity at both its missing-row delete and its final delete. The native typed
delete makes its original key once and reports that buffer's capacity before
the original database match. The same caller lease records those bytes even
when the row is absent or the database operation returns an error. This does
not estimate a key length, encode a second key or allocate another lease.

The unbound finalizer keeps its ordinary delete call, and all existing deletes
share the same native key construction and database branches. Return values,
errors, the missing-row exit and the original finalization order stay unchanged.
The key drops inside the delete before the caller's lease, including error and
unwind; its capacity stays charged conservatively until that lease drops.
This separate charge does not cover overlay key copies, database pages,
transaction scratch, key construction peaks or a full working-set bound.

The retained finalizer also records the actual encoded key capacities of its
provisional-marker read before pruning and its finalized-row read before aging.
Each typed contains call creates its original key once, reports that buffer's
capacity before the same raw read, and keeps the original presence result and
errors. The same optional caller lease is reborrowed for both reads and the
intervening finalize; no new lease or resource owner is made.

These are separate key buffers from the delete and staged-put keys. Their
capacities stay charged conservatively until the caller's lease drops, after
the native read keys have dropped, including absent rows, errors and unwind.
An unbound finalizer keeps ordinary contains calls. Pruning, finalization,
aging and the original clock read keep their order and conditions. Any owned
value copy made by the raw read, overlay storage, database pages, transaction
scratch and key construction peaks remain outside this key-only charge.

The retained finalizer also records the actual encoded key and value capacities
of its age-ordered and by-run age-index puts. After the original old-age cleanup
runs once, each bound put stages its original typed row once, records the sum
of that row's actual key and value capacities on the same caller lease, then
performs the same native put. The age-ordered row still precedes the by-run row.
An unbound caller keeps the direct typed puts. The retained finalizer's presence
condition, clock read, cleanup, write order and errors stay unchanged.

Each staged row drops inside its write scope before the caller's same lease,
including write errors and unwind. Its known encoded capacities stay charged
conservatively until that lease drops. The old-age lookup and deletes remain
outside this put-only charge, as do overlay copies, database pages, transaction
scratch, encoding allocation peaks and a full working-set bound. No extra
encoding, memory line, admission, wait or configured limit is introduced.

Separate from those put buffers, the bound retained finalizer records the
actual encoded key capacities of the old-age lookup and its two conditional
deletes. The typed lookup makes its original key once and reports its capacity
before the same raw read and decode. A found capture time still deletes the
age-ordered row before its by-run row; each delete reports its original key's
capacity before the same database operation, including false or error returns.
A missing lookup skips both deletes, and the original errors still stop aging.

All three known key capacities use the same existing caller lease. Native keys
drop before that lease on success, absence, errors and unwind; their capacities
stay charged conservatively until the lease drops. Ordinary unbound lookups,
deletes and cleanup keep their original behavior through the same shared native
bodies. This key-only charge does not cover raw-read value copies, decoded
values, overlay copies, database pages, transaction scratch or key construction
peaks. It adds no key copy, encode, lease, admission, wait or configured limit.

The bound retained finalizer also records the actual outer allocation of the
age-index key vector collected before retention pruning. After the original
successful scan, its capacity times the native size of `(u64, RetrievalRunId)`
is recorded once on the same existing caller lease. The consuming iterator
owns that backing through the original delete loop and drops before the caller
lease on completion, early break, error or unwind. The charge stays conservative
until that lease drops. Unbound pruning keeps the same shared native body.

The policy lookup, reserve, clock, cutoff, deletion order and errors stay
unchanged. This charge covers only the post-scan outer vector backing, not scan
construction peaks, cursor storage, raw row copies, individual delete buffers,
overlay copies, database pages or transaction scratch. It adds no scan, copy,
lease, admission, wait or configured limit.

During the bound retention-prune loop, each run deletion also records the
actual encoded key capacities of its final provisional-marker and primary-run
deletes on the same caller lease. Each delete makes its original key once and
reports its capacity before the same database operation, including false or
error returns. The provisional marker still precedes the primary row. These
native keys drop before the caller lease; the known capacities stay charged
conservatively until that lease drops. Ordinary unbound deletion uses the same
shared body without recording capacities.

The preceding age-index cleanup also forwards the same optional caller lease
to its existing shared helper. It records the original by-run lookup key and,
when a capture time exists, the age-ordered delete key followed by the by-run
delete key. Each native key's actual capacity is recorded once before its
original database operation. Missing rows still skip both deletes; false and
error returns keep their original behavior. These keys drop inside cleanup,
before the final two delete keys and the caller lease, including errors and
unwind. Their known capacities stay charged conservatively until that lease
drops. Unbound cleanup keeps the same shared body without capacity accounting.

The first turn-index cleanup also forwards the same optional caller lease.
After its original successful scan, the collected typed-row vector records its
actual capacity times the native row size once. After the original run-ID
filter, the filtered key vector separately records its actual capacity times
the native key size once. Both vectors move into their original consuming
loops and drop before the caller lease. Each selected row's original encoded
delete key also reports its actual capacity once before the same delete,
including false or error returns. The full scan still completes before any
delete, and keys for other runs are not deleted. Unbound cleanup shares the
same native body without capacity accounting. Known capacities stay charged
conservatively until the caller lease drops.

The second trace-fork cleanup forwards the same optional caller lease. Its
original direct lookup records the encoded key's actual capacity once before
the same read. Lookup errors, missing or mismatched records, absent traces and
unknown hashes still fall back to the original full-family scan. A known trace
still deletes its one fork key and returns; that delete records its original
key capacity before the same operation, including false or error returns.
The native lookup result, record and trace keep their original scope and drops.

Before the original run-ID, trace-presence and known-hash filters, a successfully
decoded lookup record also records its known backing on the same optional caller
lease. It uses the same native capacity formula as the pre-put existing-row
observation through one shared helper. This is a separate owned decode. When the
pre-put stage calls this cleanup, its first decoded row is still alive; counting
both allocations does not count the same backing twice.

A shared observer returns the original lookup result without moving any field
before the original let-chain. Errors and absent rows still add no decoded-record
charge and fall back as before. Mismatched IDs, missing traces and unknown hashes
also retain their original fallback. Their decoded buffers drop at the original
chain failure before the full scan. On the fast path, the record and moved trace
drop on the original return, including delete errors and unwind, before the
caller lease. Known charges remain conservative until that lease drops; this is
not exact early release or an allocation-peak bound. An unbound caller adds no
capacity walk. No extra read, decode, clone, lease or admission is added.

On the fallback path, the original successful scan's typed-row vector and its
distinct filtered key vector each record their actual capacity times their
native element size once. The same consuming loops retain and drop those
backings. Each original selected delete key records its actual capacity once
before the same delete. Keys for other runs are not deleted. These temporary
buffers drop before the same caller lease, which conservatively retains their
known charge until it drops. Ordinary unbound cleanup keeps the same native
operations without capacity accounting.

The third outcome cleanup records its original run-prefix vector's actual
capacity on that same optional lease. The prefix drops before age cleanup,
as before. After the original successful full-key collection, the typed table
reports the collected vector's actual outer backing and each retained full
key's actual capacity once, before the first delete. It keeps the original
borrowed-key loop, database branches, error behavior, order and returned count.
All collected keys drop before the caller lease, including errors and unwind;
their charge stays conservative until that lease drops. Unbound callers share
the same native body with a no-op capacity observer.

Other turn-index buffers and remaining trace-fork and outcome cleanup storage
remain outside these charges. The full cleanup order and errors stay unchanged,
as do exclusions for decoded values, transient raw values and unretained row
copies, overlay copies, database pages, transaction scratch and allocation peaks. No extra encode, copy, lease,
admission, wait or configured limit is introduced.

The pre-put and direct trace-fork retrieval-run lookups also record any owned
raw read buffer before decoding it. The typed table reports the original
encoded key's actual capacity before its one database read. If that read returns
`Cow::Owned(Vec<u8>)`, it reports that vector's actual capacity once before the
same decode. Session-overlay present rows can return this distinct owned copy;
base and passthrough reads borrow the transaction's bytes and add no raw-buffer
charge. Capacity is read from the actual vector, not inferred from its length.

The initial retained-finalizer lookup uses the same observer for its original
encoded key and owned raw buffer. Its missing-row marker cleanup and return,
mutable decoded record, mutations, writes and errors stay unchanged. The
pre-put lookup still propagates its read or decode error; the direct trace-fork
lookup still falls back to its full-family scan. A missing row or storage error
adds no raw-buffer charge. A decode error records an owned buffer before
returning the same error.

Each lookup uses the same optional caller lease, with no new read, copy, decode,
lease or admission. The raw buffer drops after decoding, before the decoded
record reaches its caller. The encoded key stays alive through the decode and
drops at the typed method's end. Their known charge remains conservative until
the caller lease drops; it is not an exact early release or an allocation-peak
bound. Decoded records have distinct backing and keep their existing accounting.
Unbound calls keep their existing behavior without recording capacities. Other
raw-read families, overlay storage, database pages and transaction scratch
remain outside these charges.

These finalization charges do not cover remaining backing, input construction
before its first measurement, other mutation copies, config-map storage,
number internals,
serialization scratch, other marker/index/retention keys and values, construction
peaks or pre-growth admission. They do not establish a full working-set bound
or a compiler/runtime result.

Other pipeline buffers, remaining trace serialization storage, provider
storage, construction and return gaps, pre-growth admission and a full
working-set bound remain open.
No runtime, compiler or performance result is implied by these source changes.
