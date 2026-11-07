# Historical secret-lift accounting

The historical lift sweep runs when the owner enables masking or asks for a run.
Its native writer doors, retry rules, busy-stream waits and page cursor are unchanged.

## Stored and served counts

`secret_lift:contribution:v1:` stores the canonical count contributions for each run.
Each row groups one family and one canonical set of proven source entities, or
explicitly unmapped sources. Single-source groups keep their existing representation;
a `Multi` contribution uses key marker `2` followed by the BLAKE3 digest of its
sorted, distinct, full 16-byte entity ids under
`oneiron/secret-lift/contribution-sources/v1`. This keeps the database key bounded
without capping the source set. The contribution value stores every actual source id;
the digest only groups rows and never establishes a source's identity. It counts every census read, including clean rows, and the committed masked,
proposal and failed outcomes. A multi-source contributor is counted once, not once per
source. A run stores its cursor and retry membership, not another copy of
these totals. A completed run stores completion metadata. The public progress and
receipt totals are projections of the same contribution rows.

Contribution rows use the same LIVE restore class as the run and receipt metadata.
There is no old-format reader or migration.

## Destination projection

On-device status includes all contributions. Off-device status uses the existing
source-entity destination filter. Native producer keys establish the source for ordinary
entity records, typed-body documents, typed-body forks, office-body forks, codebase
snapshots, note proposals and repo-mutation proposals. A codebase snapshot's source is the
CODE_ARTIFACT entity id that its native writer validates and uses as the table key.
A typed-body fork's source is the first entity id in its native `(entity, fork)` key:
its writer validates that entity's live typed-body head before storing the fork
snapshot. Both key ids must decode; the fork nonce is not treated as a source.
An office-body fork's source is the first entity id in its native `(artifact, fork)` key:
its deck writer validates that artifact's live headed typed body before storing the fork
row, and its checkpoint owner is that artifact. Both key ids must decode; the fork nonce
is not treated as a source.
A note proposal's source is the first entity id in its native `hex32(note):hex32(head)`
ASCII key: its writer validates that NOTE's live core before storing the proposal
document. Both key ids must decode; the fork head is not treated as a source.
A repo-mutation proposal's source is its own same-writer admitted journal CLAIM entity id:
its native writer admits that CLAIM in the same transaction before storing the proposal
row keyed by that claim id, and landing requires the same claim id, predicate and producer.
No source is assigned to repo-mutation oplog or snapshot hash keys.
An LFS object's source is the manifest ASSET in its actual live native object record,
read in the same transaction as the census, outcome, retry or proposal projection.
The native writer admits that ASSET and binds the object record to it in one transaction.
The OID is a content hash, not an entity id; chunk ASSETs are not substituted for the
manifest-defined object's source. Missing, deleted or undecodable object records remain
unknown. Booked contribution sources survive the object's deletion, but a proposal has no
stored source: once its object record is gone, even a closed proposal passes as unknown.
No historical source is reconstructed from a hash, attachment owner or aggregate count.
A message-stream seed's source is its live MESSAGE continuation in the same transaction:
the stored seed must carry the continuation flag and its message id must resolve to a
live MESSAGE-typed row in the census, outcome, retry or proposal projection snapshot.
A pre-admission (fresh) seed, a missing or undecodable seed, a seed whose message id
names no row or a non-MESSAGE row, and a terminal-deleted seed (finished, erased,
abandoned or retired) remain unknown. Booked message-stream contribution sources survive
the seed's deletion, but a proposal has no stored source: once its seed row is gone, even
a closed proposal passes as unknown. No historical source is reconstructed from a stream
receipt, saved text or run totals.
An eval case views the content of its native attempt receipts and inherits its parents'
content. The lift reader follows actual same-seat, same-family case links in the same
transaction, resolves each native receipt and uses its original frozen, complete read set.
It visits each case once without a depth cap or recursive call stack. Missing, malformed
or mismatched parent rows contribute nothing and do not cancel other known dependencies. It does not use the case's mutable `source_rows`,
which erasure can shrink, or treat a case id, label, actor or receipt spelling as source
authority. Only live native entity ids from those proven sets enter the contribution.
Missing, malformed or source-unknown receipts add no known dependency. They and unknown
labels never cancel a dependency another receipt proves. If any proven source is withheld,
the row, its outcome, its retry and its proposal are each omitted once. On-device counts
still include every contributor once. This is a set of known dependencies, not a claim
that every dependency is known. Label-only sources, synthetic sources and other untraced
dependencies remain unknown. Booked sources stay durable;
a proposal uses current case and receipt bindings and becomes unknown if those disappear.
The same verified mapping projects pending retry counts and newly booked
contribution rows. Existing unmapped contributions are not reattributed. Other attempt, side-row and carrier
sources remain unmapped and pass unchanged; this is not a complete source
attribution claim for every carrier format.

The proposal list and its open/closed totals use these same known source mappings.
The status reader collects and projects one content snapshot, so a later committed
row cannot enter the result without its known source being included in the judgment.
No source ids are added to the public status or receipt shape. These are diagnostic
projections, not a change to admission, masking, erasure authority or recovery rights.
