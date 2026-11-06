# Owned code-run replay publication

An owned replay save records whose reply content it holds in the same transaction as the replay row. The host supplies the content run and actor. A summary response uses its own job run and the admitted spawning actor; that caller binding is separate from the storage ordering described here.

## First publication and actor erasure

For canonical storage, the save validates the expected replay generation before it writes the owner descriptor. It then stamps the owner before the existing erase fence reads it. The first stamp still stands, and a deleted or erased owner stays so. The fence can therefore see an actor erased before the first replay publication, even when the replay has no live-run binding. It applies the existing erased-reply projection and releases the named reply-body occurrences before the replay row is put.

The owner stamp, fence, replay row, optional heal tally and after-save callback share one writer. A generation conflict stamps nothing. An error before commit rolls back the entire writer, including the owner stamp. Saves racing actor erasure serialize through that writer: an erase before the save is visible to its fence; an erase after it can discover its committed owner descriptor.

The generic after-save callback still runs after the replay and heal rows. Continuation inheritance, wait consumption and turn-program settlement keep that ordering. The preparation callback is storage-private and is used by the native owned-save path for its owner stamp, not as a global reorder of after-save work.

## Kept, Deleted and Erased

Each owner row and each wait membership is in one of three states.

- **Kept**: the record holds its replies for the stamped actor.
- **Deleted**: a soft delete of the actor took the replies (FIX 15532). The delete runs the response scrub in its own writer, before it truncates the actor's body. The scrub puts each record in its erased form and releases its reply bodies. The row keeps the actor and the bodies it released, but no reply bytes and no preview. The actor stays only so that the actor's hard erase still finds the row (FIX 6591).
- **Erased**: an erase took the replies. The hard erase retires the bodies that a Deleted row names, then marks the row Erased. The row names no actor.

Deleted and Erased both read as erased. No later write or retry brings the replies back.

A later record write, a wait delivery and a connector caller's settle check the row in their own writer. When the actor is gone, they write the erased form. They write Erased only when the actor's hard erasure is complete: the actor holds the hard-delete marker, which the erase's writer puts beside its retirement. No later erase runs for that actor, so a Deleted row of that actor also becomes Erased. Every other gone actor gets Deleted, with the bodies released: a soft-deleted actor, and an actor whose row a pending delete removed (a `df:` or `pt:` fence without the marker). The later hard erase retires those bodies. A marker that cannot be read is an error of the writer.

The erase also releases reply bodies that a run holds but its record does not list, such as a raw put's (FIX 7365). It does this only when the record shows that the run can append no more: the record lists a terminal marker, and the run did not resume from the latest one. A live run can publish a body, such as a team-start receipt, before it records the bridge call. The erase skips those bodies. The run's next record write meets the fence, and the run's release takes the rest.

A record that is stored but does not decode can no longer append, because each writer that appends to it decodes it first and fails. The erase counts it as closed. It releases the reply bodies of the run that the record's owner row names, which need not be the replay key: each descriptor of that run at a code-run output path that holds reply content, outside `replay/`. A soft delete keeps their digests on the owner row as Deleted evidence, and the hard erase retires them.

A descriptor stored before the code-run origin field existed has no origin. A re-publication compares descriptors without that field, so the stored row stays as it is. The erase's sweep of unlisted bodies does not find such a descriptor; the run's release takes it.

## Session storage

An on-record session save validates the generation in its routed transaction, stamps the base owner, then runs the same base erase fence and puts the replay row. It keeps the existing participant and route checks.

Off-record overlay saves keep their existing behavior. They do not stamp a canonical owner or read the base erase fence. This change does not establish global actor-erasure coverage, add missing ownership to other callers or prove runtime behavior.

The owner-fence ordering itself needs no replay format, setting, limit, default or public API change. Deploy the ordinary engine build; no worker, SDK, migration or configuration change is needed.

## Large direct team-start receipts

A direct native team start records only host-generated membership facts. Its producer
carries the same known-empty source witness that the native team-start row already
records. Planned starts and recorded team results keep unknown source witnesses and
stay on their original inline path.

When a witnessed direct start exceeds the existing inline reply threshold, its guest
JSON is stored before the bridge call is recorded. The internal outcome retains an
explicit team-start receipt kind and the normal result card, not a second full copy of
the member list. The ordinary sweeping sink, occurrence allocation, name binding,
secret marks, taint and result facets still apply.

Actor erasure keeps that receipt's outcome, preview and body only when the canonical
record joins the typed Team effect to its actual owned output, occurrence reference,
handle and byte count. The same join governs later owned reads. A matching hash,
path prefix or caller-supplied card alone grants no exemption. Missing or unreadable
records cannot prove the classification. Source withdrawal and secret or taint checks
remain independent.

Checkpoint retirement keeps its existing erased-image projection, including for native
team receipts. A whole-vault result archive still does not carry bridge calls and is
not a complete execution-history or receipt-kind round trip. These paths do not gain
an exemption from their existing custody rules.

The guest JSON and result-reading protocol are unchanged. Native Rust code matching a
Team outcome now reads its answer from `SelfTeamResult::answer`; its source witness is
internal. No guest rebuild, SDK regeneration, migration or configuration change is
needed for this carrier.
