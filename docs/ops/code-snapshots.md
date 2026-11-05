# Code snapshots: committed import and current folder capture

Both doors act as the authenticated vault owner. A folder names an absolute path
on the host serving the vault, not on the calling client.

- `vault.code.snapshots.ingest` takes `project_id` and
  `pointer: {local_folder, commit}`. The full 40-hex commit selects a Git tree.
  This door never reads dirty working files.
- `vault.code.snapshots.capture` takes `project_id` and `local_folder`. It reads
  current ordinary files and symlink target text. It includes untracked and
  ignored files. It skips `.git` metadata, indexed gitlinks and linked or nested
  repository directories; it never follows a symlink into another tree. An
  ordinary folder does not need a Git repository.

A capture records `capture:<canonical-host-folder>` and `commit: null`. Its fork
hash is the codebase manifest's content hash, not a Git commit and not the
repo-mutation recovery snapshot hash. Capturing does not create a Git commit.

Both paths apply the current vault custody rules in the final grouped writer.
Withheld files do not become empty ASSETs. Retained files produce ASSET bytes, a
CODE_ARTIFACT, its filtered snapshot and the native masked symbol manifest in that
same writer. Capture revalidates the original owner before any derived write.

The result's artifact id and fork hash pin subsequent `snapshots.get`,
`snapshots.read` and `symbols.definitions` calls. Those readers use stored bytes
and the caller's existing read checks, never a newer folder or implicit HEAD.
A snapshot, project key, scope key or path grants no repository membership,
editable whitelist, push permission or delegated run access. Committed-only
checkout and mutation calls still require their actual commit witness.

Capture file buffers use the process memory admission line and keep their lease
through the snapshot writer. The door adds no fixed file-count, file-byte or total
byte limit and no new wait timeout. This is not a claim that all pre-existing
indexing, parser or response allocations are covered by that lease. The separate
repo-mutation recovery capture retains its existing bounds and encoding.
