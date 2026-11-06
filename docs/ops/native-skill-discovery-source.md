# Native discovery-proposal sources

`pending_edit_proposals` reads the `EDIT_PROPOSAL` table in its original eager
key/decode order. Its primary is the u64 judgment sequence, not the proposal's
minted row id and not an ENTITY row. The canonical scan retains that full physical
key and the original stored MessagePack body. It adds no judgment-revision,
displacement or revision-fence read: the original decoder consults none of them.

## Original producer placement

`run_attribution_projector_with_position` is the original attribution pass with an
explicit `SkillEditProposalReadPosition` supplied on the proposal-producing request.
The real lower `SkillEditProposal` and its strict custom Raw codec carry that
position. It contains the full Scope, kind band, relationship/private axes,
body worlds/facets and shared writer anchors. The SKILL, actor, payer, receipt and
row id infer none of those axes and confer no read authority.

Ordinary projector entries and the amendment minting door supply no position.
An unchanged re-minted row retains its original position. Changed contents lose
that position; a later request cannot restamp a standing row. The native format
requires an explicit `read_position` field, including nil for unknown. There is
no old-format reader or migration.

`GateReadAnchors` and `GateThreadAnchor` are shared contract data. Their existing
store exports, private fields, serde representation, constructors and accessors
remain the same. Upper gate-decision scrubbing still checks exactly the original
thread root/turn, reached, room and world ids.

## Original Coach capture and heal

The Coach's original read request reaches the discovery scan before the brief's
skill/DEV filters. Grant-clock preparation precedes body pins and the custody
guard; those precede the source transaction. Every decoded proposal must pass
full live native admission under the original key in that same transaction.
Optional capture failures leave the original values and candidates unchanged.
Original scan and decoder failures still propagate in their original order.

A typed discovery source binds the physical sequence/key, minted row id and
BLAKE3 of the exact stored body. A completed scan also binds its prefix and every
member in order, including rows later filtered out. These hashes retain no raw
source bodies in the terminal receipt. They join the same typed attempt-source
carrier, not an entity-only id list or another ledger.

The heal consumer reopens the actual canonical point or complete scan in its own
source transaction. It compares the physical witness and applies the current
reader's full native predicate, including placement and body disclosure checks.
Missing, changed or withheld sources are unavailable context, not new ordinary
optimizer refusals. A factory or a captured source never grants a later read.

Discovery and verdict captures are still partial brief data. The Coach's complete
model-source declaration remains unknown until all real source families compose.
This source work does not activate FACT/attempt capture or claim compile, runtime
or privacy verification.
