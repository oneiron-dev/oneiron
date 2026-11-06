# Erasing copied owner-pair questions

A hard actor erase captures affected owner-judged contribution pairs in its
own write transaction before the actor and pair scrubs remove their provenance.
The read-only candidate list is not erase authority. The deletion continuation
still owns the actual `ActorErasureWriter` and the original owner act.

For each of the three reserved question/answer MESSAGEs, the capture verifies:

- The MESSAGE has the native protected `contribution_pair_question` type and
  the exact canonical companion envelope: visible, order zero, no parts or
  import metadata, the pair handle and part name, and the reserved text digest.
- Its only `PartOf`, `BelongsTo`, and `AuthoredBy` peers are the reserved TURN,
  reserved conversation, and fixed Coach actor.
- A TURN is included only when its body is the original assistant shell, its
  only `ChildOf` peer is that conversation, and its only `PartOf` child is the
  verified MESSAGE. Another child keeps the TURN, not the verified MESSAGE.

The private pair permit protects the native MESSAGE type at write time.
Mutable graph edges or metadata alone do not prove ownership. This producer
has no persisted Coach RowBirth, so capture does not require one. It also does
not rerun issuance checks for a Reserved pair, live owner, current membership,
reach, or an unsettled ask: cleanup must work after those states change.

The existing pair callback keeps its original selection, pair deletion, ask
retirement, and receipt rebind order. After the normal actor scrubs, the native
soft-erase path scrubs verified MESSAGEs before their sole-child TURNs. It uses
the same writer and actual owner act, or the existing authenticated restore
continuation's `None`. Native legal holds, protected-row guards, custody,
model-call cleanup, projections, vectors, and canonical empty shells still
apply. The shared conversation is never erased.

This covers recoverable, exactly verified native copies. Undecodable fork rows
cannot supply presentation identities. Missing, replaced, or unverified copies
are not inferred from labels, and a mixed TURN is not erased. Those cases are
not a claim that every copy of an owner's contribution has been removed.
