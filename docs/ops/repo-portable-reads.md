# Portable repo selectors for run reads

The run verbs `self.code.snapshots.get`, `self.code.snapshots.read`, and
`self.code.symbols.definitions` accept an optional `portable_repo` field
beside the required `repo` CODE id.
`portable_repo` is the repo manifest's portable id: exactly 64 lowercase
hexadecimal digits. It is a selector, not authority.

The engine resolves this selector before checking the run's repo Grant, in
the same read transaction. A known id selects its current live CODE anchor.
An absent or unknown id uses `repo`, with the existing admission behavior.
Malformed ids are invalid inputs. No new repo identity is minted by a read.

The selected anchor remains the target for the run's Grant, ref and path
checks, pinned snapshot, read lane, returned `repo`, and source row ids.
A snapshot file read with `why` uses the existing per-file reveal flow.
On a portable hit, its reveal names that exact selected anchor rather than
substituting another served anchor. After a reveal commits, the engine
checks the same selector and hit state, run lease, snapshot pin and read
lane again before returning bytes. Reads without a portable hit keep the
existing served-anchor-or-fallback reveal behavior.

Symbol definitions use the same selected repo and pinned snapshot. The
symbol manifest must still match that snapshot's repo ref and commit, and
each returned definition must pass the Grant's readable-path bounds.

These selectors do not change native Git, snapshot ingestion, symbol
writes, work, or view doors. Native repo admission checks the same typed
selector against the existing EntityId Grant bounds; it grants no new
rights. Served-anchor lookup still has no portable selector. Reads add no
grants and do not change masking, owner approval, or repo admission rules.
A manifest alone never grants access.
