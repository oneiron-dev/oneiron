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
owner-erase reason; GDPR callers retain the GDPR reason. Their checkpoint
settlement runs in the same writer as the rewrite. The ordinary record-delete
rail's GDPR-only audience-edit exception is unchanged.

The initial erase receipt binds staged entity-tree and attachment-occurrence
checkpoint leaf retirements by their native custody names. A receipt is not
proof that the leaves have been destroyed. Retirement runs after commit and
retries through housekeeping; legal holds and custody faults can defer it.
The existing final receipt waits for the bound retirements and any sweep.

An execute retry with its own act's receipt reports `owner_erase`. A retry that
finds only a hard-delete marker retains the ordinary hard-delete result; a
presence-only marker is not proof that the owner erase ran or retired its
checkpoint leaves.

The tombstone reason byte for `owner_erase` is **6**. The tombstone value stays
25 bytes. Reserved and unknown reasons keep their existing hard-delete effect
and retain checkpoint payloads. Actor-facing `SafeDeleteReason` inputs do not
accept the new reason; it is selected by the native owner-erase paths, not by a
caller-supplied string. Short-id hydrate and erase receipts report the actual
reason.
