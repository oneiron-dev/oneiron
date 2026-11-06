# Generic calendar claim writes

The public embedded `Vault::put_claim` door keeps its normal validation, admission,
row identity and transaction. For a raw passport claim with no `src` or `evidence`,
it also reconciles a single matching raw passport head in that same writer.
The match is the same EVENT, system and UID, with identical scope and sensitivity.

The calendar feed rules decide which head remains current:

- A change between source presence and absence replaces the previous head.
- A higher SEQUENCE, or the same SEQUENCE with a different content hash, replaces it.
- An older SEQUENCE, or the same SEQUENCE and hash, leaves the previous head current.

The native supersession path keeps the other assertion as readable history at its
original id. It records the normal supersession edge and lifecycle change. A failed
transaction commits neither the assertion nor the replacement. The UID index still
uses its existing repair-on-miss path.

This is not full generic-calendar routing. Attributed or evidenced claims, different
scopes, multiple matching heads, pending or stale claims, `calendar.origin`, and all
batch/actor-bound writes keep their existing paths. Typed calendar import and invite
writers are unchanged. These cases need their own scope-aware projector or CAS work;
they are not refused by this change.

No configuration, limit, stored format, migration or deployment step is added.
