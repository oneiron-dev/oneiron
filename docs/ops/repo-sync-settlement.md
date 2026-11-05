# Settle a retained repo document-copy edit

The native owner API reviews a marked source document's retained copy lineage.
It can apply an exact canonical replacement when the current visible diff has
`sealed_file_edited` or `projection_edit_conflict`. It does not settle window
updates or expose a new SDK or HTTP route.

## Review and replace

Use an `EntityDocument` handle for the source and an `AuthenticatedOwner`:

```rust
let Some(review) = doc.repo_copy_edit_review_as(&owner)? else {
    return Ok(());
};
// Show review.submitted() and review.cause() to the owner.
// replacement is the canonical text the owner chooses, not the masked text.
let approval = review.approval_for(replacement);
let frame = doc.settle_repo_copy_edit_as(&owner, &approval, replacement)?;
```

The review reads the current source, its masked copy, and the stored lineage.
It does not refresh the lineage before reading, which would overwrite the
submitted text. No mark, an unread copy, an empty lineage, a NOTE, or a diff
that is no longer held produces no review. The submitted text is the current
retained lineage text, not an inventory of every historical held operation.

`approval_for` binds the reviewed revision and the exact replacement. It is
not authority. The setter revalidates the actual owner and recomputes the
review in the writing transaction. A changed source, incarnation, mask,
lineage, cause, or replacement makes the approval stale and changes nothing.
The caller must review again. There is no persistent approval or retry journal.

The revision hashes both version vectors in sorted peer/counter order. Its
hash domain is `oneiron.repo-sync-settlement.review.v1`. Variable-length fields
are length-framed. There is no new limit, timeout, or default policy.

## What commits

The setter holds the existing document writer lock. It retains the existing
credential, deletion, off-record, citation, NOTE, and canonical write checks.
It attributes the replacement to the revalidated human owner through the
normal canonical text writer, including shared-vault scope, prose admission,
stamps, and indexes. It does not change peer admission or grant checks.

Admission may transform the replacement. The same transaction reads the
actual persisted text, carries the reviewed blob's secret marks onto those
bytes, refreshes the copy lineage, and writes the normal durable UPDATE
journal. It does not unseal the source or clear taint. The ordinary document
notice and prose receipts follow only after a successful commit.

The returned frame describes the committed local edit. It is not a remote
ACK or a delivery guarantee. A successful edit makes the prior review stale.

## Remaining work

The `x:` hash record remains historical evidence; this API neither requires
nor deletes it. It is not pending-work inventory or authority.

Window settlement remains open. The home does not retain a held window
update's bytes for this operation; the device may still hold its live window
operations. Recovery of that work needs its own export and admission path.
Broader held-lineage convergence and historical operation scrubbing also
remain open. This API settles only the current reviewed document-copy state.
