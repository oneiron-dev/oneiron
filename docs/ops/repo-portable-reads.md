# Portable repo selectors for run snapshot reads

The run verbs `self.code.snapshots.get` and `self.code.snapshots.read` accept
an optional `portable_repo` field beside the required `repo` CODE id.
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

These selectors apply to the two run snapshot read verbs only. They do not
change native Git, snapshot ingestion, symbol, work, or view doors. They
add no grants and do not change masking, owner approval, or repo admission
rules. A manifest alone never grants access.
