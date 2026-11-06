# Owned code-run replay publication

An owned replay save records whose reply content it holds in the same transaction as the replay row. The host supplies the content run and actor. A summary response uses its own job run and the admitted spawning actor; that caller binding is separate from the storage ordering described here.

## First publication and actor erasure

For canonical storage, the save validates the expected replay generation before it writes the owner descriptor. It then stamps the owner before the existing erase fence reads it. The first stamp still stands, and an erased owner remains erased. The fence can therefore see an actor erased before the first replay publication, even when the replay has no live-run binding. It applies the existing erased-reply projection and releases the named reply-body occurrences before the replay row is put.

The owner stamp, fence, replay row, optional heal tally and after-save callback share one writer. A generation conflict stamps nothing. An error before commit rolls back the entire writer, including the owner stamp. Saves racing actor erasure serialize through that writer: an erase before the save is visible to its fence; an erase after it can discover its committed owner descriptor.

The generic after-save callback still runs after the replay and heal rows. Continuation inheritance, wait consumption and turn-program settlement keep that ordering. The preparation callback is storage-private and is used by the native owned-save path for its owner stamp, not as a global reorder of after-save work.

## Session storage

An on-record session save validates the generation in its routed transaction, stamps the base owner, then runs the same base erase fence and puts the replay row. It keeps the existing participant and route checks.

Off-record overlay saves keep their existing behavior. They do not stamp a canonical owner or read the base erase fence. This change does not establish global actor-erasure coverage, add missing ownership to other callers or prove runtime behavior.

No replay format, setting, limit, default or public API changes are required. Deploy the ordinary engine build; no worker, SDK, migration or configuration change is needed.
