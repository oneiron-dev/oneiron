# Owned code-run replay publication

An owned replay save records whose reply content it holds in the same transaction as the replay row. The host supplies the content run and actor. A summary response uses its own job run and the admitted spawning actor; that caller binding is separate from the storage ordering described here.

## First publication and actor erasure

For canonical storage, the save validates the expected replay generation before it writes the owner descriptor. It then stamps the owner before the existing erase fence reads it. The first stamp still stands, and an erased owner remains erased. The fence can therefore see an actor erased before the first replay publication, even when the replay has no live-run binding. It applies the existing erased-reply projection and releases the named reply-body occurrences before the replay row is put.

The owner stamp, fence, replay row, optional heal tally and after-save callback share one writer. A generation conflict stamps nothing. An error before commit rolls back the entire writer, including the owner stamp. Saves racing actor erasure serialize through that writer: an erase before the save is visible to its fence; an erase after it can discover its committed owner descriptor.

The generic after-save callback still runs after the replay and heal rows. Continuation inheritance, wait consumption and turn-program settlement keep that ordering. The preparation callback is storage-private and is used by the native owned-save path for its owner stamp, not as a global reorder of after-save work.

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
