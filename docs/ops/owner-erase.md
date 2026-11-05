# Owner erase and ordinary hard deletion

`vault.records.erase_confirm`, execution of its completed shared-vault `erase`
act, and confirmed lift-hold-and-erase requests use the native `owner_erase`
reason. A waiting lift-and-erase request retains that reason through its due
retry. These paths keep their existing owner proof, preview, grant revocation,
legal-hold and shared-vault veto checks.

Ordinary `user_hard_delete`, policy deletion, archive and soft deletion keep
checkpoint payload leaves for their existing restore window. Owner erase and
GDPR deletion instead mark every entity-owned checkpoint payload incarnation
erased and stage leaf retirement through the existing checkpoint payload
custody machinery. This does not enable checkpoint payload custody or change
its activation setting.

Thread audience edits retain their existing special erase behavior: the live
edit keeps its operation and order, but its identifying content and retained
revisions are rewritten. The explicit lift-and-erase path records the actual
owner-erase reason; GDPR callers retain the GDPR reason. Unlike a deleted
record, this still-live edit must remain in later checkpoints, including its
content-free access-control operation and order. Its rewrite rolls the active
checkpoint generation in the same writer. The old generation retires only
after a kept checkpoint names a later generation containing the sanitized edit.
The receipt binds this pending old-generation obligation before its retirement
intent is staged, so an unsealed replacement cannot count as completed erasure.
The ordinary record-delete rail's GDPR-only audience-edit exception is unchanged.

New checkpoints also seal each live audience edit's content-free operation in
an independently keyed compartment. It keeps the original TURN id, header
times, thread binding, person and operation, but no editor or other prose.
This leaf does not roll with the entity tree's authored history. On restore,
the original entity wins whenever it opens. Only an independently opened,
strictly validated operation whose original root also stands can replace an
unavailable entity tree. Its existing About edges and order are kept; no new
edge or erase authority is inferred from a missing leaf. Whole-owner erasure
retires every incarnation of this operation's compartment too. The native
actor and room-person erasure sweeps still apply after restore. A capture
re-proves the live operation and root in its minting writer, so an erase
between the snapshot read and first mint cannot create this new leaf.

This is forward capture, not a retrofit of sealed artifacts. An older artifact
without the independent operation cannot recover that operation after its
entity-tree leaf retires. Peer replay and whole-vault erase closure remain
separate work.

The initial erase receipt binds staged entity-tree, attachment-occurrence and
audience-operation checkpoint leaf retirements by their native custody names. A receipt is not
proof that the leaves have been destroyed. Retirement runs after commit and
retries through housekeeping; legal holds and custody faults can defer it.
The existing final receipt waits for the bound retirements and any sweep.

An execute retry with its own act's receipt reports `owner_erase`. An unclaimed
act must complete on the store clock before a hard-delete marker can return an
applied result. If the target has both a marker and no active deletion scope,
the acting writer re-proves the actual erase act, starter, vault, live owner and
current holds, then retires the retained local checkpoint payloads. It claims
the act with that retirement's signed receipt and request in the same writer.
A marker whose active residue still remains keeps its ordinary hard-delete
result. Neither a marker nor an empty scope grants owner-erase authority.

This already-deleted-target fulfillment is local: it does not republish or
replace the earlier ordinary hard deletion's marker, request or wire reason.
It proves no peer checkpoint retirement or global replay closure. The receipt
binds the local retirement and its historical sweep; it does not prove key
destruction. Retries use the act's bound request and receipt without repeating
the operation.

The tombstone reason byte for `owner_erase` is **6**. The tombstone value stays
25 bytes. Reserved and unknown reasons keep their existing hard-delete effect
and retain checkpoint payloads. Actor-facing `SafeDeleteReason` inputs do not
accept the new reason; it is selected by the native owner-erase paths, not by a
caller-supplied string. Short-id hydrate and erase receipts report the actual
reason.
