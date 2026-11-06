# Completed typed-sheet answer retry

`vault.artifacts.ask` and `vault.artifacts.admit` preserve a completed sheet-row
or folder-item answer bundle before the native workbook writer stages it.
The stored row includes the original question, principal, reversibility,
evidence and selected units, every decision and receipt, the workbook version
and content hash, the read rows, and the abstentions and refusals.

If staging fails, repeat the ask with the same artifact, run reference and
request. The engine restages the stored bundle without calling the unit decider
again. The retry uses the new caller deadline and resolves the current write
batch policy. It does not change the original decisions, source pins or base.
A moved workbook still fails the existing current-source check; the engine does
not silently apply old answers to a new source. Use a new run reference for a
new question or selection. A mismatched request leaves the original row intact.

The facade rechecks the original read rows through the current credential
before restaging and before returning or retaining results. Folder files are
still filtered through that credential. Answers based on stored secret spans
cannot be resumed by a caller now seeing only masked spans. A stored visibility
flag is not a grant or read receipt. Direct Vault callers remain responsible
for the read authority they supply, including `SecretSight::Granted`.

A successful proposal retention atomically deletes the completed-answer row.
The existing held proposal and its Keep, Discard, current-source, withdrawal,
made-by and consume-once checks remain. An existing held proposal or settlement
is detected before deciding again. Direct native settlement also deletes the
same-key completed-answer row in its ledger transaction.

Completed runs with no proposal remain reusable, including their abstentions
and refusals. A stale or unwanted completed-answer row can be released with
`vault.artifacts.release_answers`: use `ProposalSettleRequest`, put the original
run reference in `proposal_ref`, and supply the same consent as Discard. The
response is `released: true` only if a completed-answer row was deleted. This
does not discard a held proposal, fabricate an edit or settlement receipt, or
consume the run reference. The caller may deliberately ask again after release.
There is no automatic expiry or new count cap. Artifact deletion purges these
rows; checkpoints restore them as content. They are not part of the archive's
consume-once settlement-ledger export.

## Remaining FIX 9815 work

This covers a complete decision loop followed by a staging or retention error.
An error before the loop completes can still lose unfinished run state. A
failure to commit the completed-answer row itself is not durable recovery.
Concurrent first requests are not single-flight: they can both call the decider;
the first completed row committed under the ref wins and is never overwritten.
A staging clone while the durable original remains is not full-heap admission.
No runtime, hard-time or full FIX 9815 completion claim is made here.

Normal engine rebuild only. This adds one content side table and one additive
release verb. There is no migration, compatibility reader, new operational
numeric constant, default cap, timer or configuration key.
