# Reader jobs in a room that goes on record

Reader jobs, parent counters, wait sets, summary memos and their indexes use the
run's captured storage route. Off-record transactions keep those rows in the room
and discard them when the room closes. Canonical runs use the base vault.

A reader worker rebinds a session on each tick. After the room goes on record,
its new route writes base while still reading the composed room view. Rows
created before the flip remain available to the worker. A committed update must
also stop the old overlay row from hiding the new job state or deleted index.

The session reader transaction takes the overlay's publication permit inside the
base writer, in the same order as an off-record segment. Installing that segment
closes the writer group after this transaction. The next reader writer waits for
publication before opening its composed view. The permit is released before the
write door's postcommit work can acquire another writer.

After a successful base commit, only the transaction's changed full VaultMeta
keys retire from the sealed overlay. Both stored rows and tombstones retire
outright; no new tombstone hides later base writes. Retirement checks the captured
row and the sealed mode generation under the overlay lifecycle lock. A flip back
off record leaves the new mode untouched, including a new row with identical
bytes. Failed base transactions retain every overlay row.

Participant, saver, route, spend, child-generation and lease checks are unchanged.
Session wait replies still deliver after the reader transaction commits. This is
reader-ledger maintenance, not promotion of room content or a new save policy.
