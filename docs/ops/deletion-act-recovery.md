# Original act receipts after interrupted deletion publication

A shared-vault erase can carry a completed authority act. Its normal claim still
runs in the tombstone publication transaction, and its receipt is added in the
purge transaction. Staging alone never claims or consumes the act.

Before a shared window document changes, the existing local deletion-gate
sidecar now saves the claim's original act id beside its request, target and
reason. The same pre-publication writer revalidates the owner and deletion
checks. A refusal discards the staging as before.

If the live document takes the tombstone but the publication write fails, a
later window persistence can make that tombstone durable without the rolled-back
claim. Open-time recovery or cold-window rematerialization then runs the normal
reason-aware replay. When that replay redeems the exact local sidecar and purges
local state, it claims the original act for the original request and new receipt
in that same transaction, if the original act is still stored. An act already
claimed by the same request can add its receipt. An act claimed by another
request keeps the existing conflict result. If the owner withdrew the original
act after interrupted publication, replay uses its existing receipt binder:
it does not recreate or claim the absent act, nor does absence strand the purge
and topology reservation. The presence check and claim share the purge writer;
decode, storage, incomplete-act and conflicting-execution errors still propagate.
The purge, receipt, gate-ledger append, any act claim and sidecar removal commit
or roll back together. Withdrawal admission is unchanged.

A remote tombstone supplies no act id. Without a redeemed local act binding,
replay keeps its existing receipt-binding behavior for a claim already stored.
No custody owner act, marker, row id or gate-ledger claim id substitutes for the
original completed authority act. Current legal holds, topology protection,
source admission and pre-publication authority checks are unchanged.

The private pending-deletion sidecar and required-marker codec version is 1
(previously 0). The public gate-ledger version and record shape are unchanged.
There is no old-format reader or migration. This change does not add in-process
replay of a failed live publication; the existing persistence/reopen paths still
perform recovery. It is not a general custody, peer-erasure or artifact-rewrite
completion claim.
