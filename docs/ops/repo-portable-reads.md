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

`self.code.snapshots.ingest` accepts the same optional selector. The
selected CODE supplies the stored folder and project key, the run's read
lane, and the returned `repo`. The existing import writer still limits the
snapshot, blobs, and symbol graph to paths the run's Grant reads. Before
any write, it resolves the same selector again and checks the selected
CODE, hit state, current Grant bounds, and run lease. A changed selection
returns a retryable error without writing rows. An absent or unknown id
keeps the existing fallback behavior.

`self.code.work.open` also accepts the selector. Its queue, green snapshot,
read lane, returned rows, and fresh work receipt use the selected CODE.
The receipt writer re-resolves the same selector and keeps all current
Grant, path, and lease checks. Later view reads, symbol declarations,
proposals, and queue entries use that work's stored repo and current native
admission. A later portable mapping never retargets an existing work.

The run host's existing write gate for imports and work opens admits and
records the selected CODE, not the fallback repo. After the gate returns,
the native door admits the selector again and compares its repo and hit
state with the gate's selection before reading or preparing bytes. Its
writer checks the same selection again. Direct native and live-run facade
calls keep their existing native admission without adding a host gate.

These run selectors do not change native Git. Native repo admission checks
the same typed selector against the existing EntityId Grant bounds; it
grants no new rights. Served-anchor lookup still has no portable selector.
Reads, imports, and work opens add no grants and do not change masking,
owner approval, or repo admission rules. A manifest alone never grants access.
