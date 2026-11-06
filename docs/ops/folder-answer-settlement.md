# Folder-answer settlement

Keeping a typed sheet proposal splits its answers against current workbook cells,
folder files and live-body frontiers. Changed units withdraw; untouched answers
are staged on a copy. The withdrawal keeps the judged revision and the revision
where the change was found. The existing proposer wake evaluates only those
withdrawn units. It does not accept their replacement answers.

The source snapshot in `edit_settle/carry/sheet_keep.rs` is captured before the
split or native byte staging. It reads each source's head version, content hash
and live frontier in one read transaction. The settlement write transaction
checks that snapshot again before any durable settlement row or artifact append.
A mismatch returns the existing retryable `ConcurrentWrite` error before any
settlement row is written. The pending proposal remains intact. A later Keep
repeats the native split and staging outside the writer, using the original held
proposal rather than a previously reduced copy. It reuses existing answers and
does not call the decider again. Keep does not spin internally while another
writer continues editing an unrelated workbook cell.

Only sources of retained, valued answers participate in the final source check.
A withdrawn file cannot keep invalidating the untouched answers. When no answers
remain to land, the existing all-withdrawn transaction consumes the proposal and
records its withdrawals without appending a version. A partial Keep appends the
carried manifest and records its withdrawals in the same transaction.

Source revisions are not substituted for judged revisions. A live-body export
that the existing carry logic proves equivalent remains eligible. Workbook
before/after byte verification, actual standing-grant lookup, consume-once
ledger, receipt generation and deferred proposer wakes remain the native paths.
`keep_pending_proposal` drops the waiting row only after settlement succeeds.
Direct typed-sheet settlement uses the same source-bound split.

This is an optimistic transaction conflict, not a policy refusal or a timed
hold. It does not add a retry count, timeout, quiet interval, policy cap, schema,
provider replay or automatic acceptance. The existing policy controls the wake.
Byte staging can still report its existing workbook-change or resource errors;
this path does not replace those errors or claim bounded native execution time.
