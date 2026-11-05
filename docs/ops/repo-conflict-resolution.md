# Repository conflict resolution

A recorded repository conflict may name several files. Resolving one file writes
its own `repo.conflict_resolved` claim with that file in `resolved_paths`. It does
not close the `repo.conflict_open` claim while another recorded path is unresolved.

## Completion and recovery

The completion writer reads all active resolution claims attached to the same
branch subject. Only claims naming this exact open-conflict id, repository and
branch contribute to coverage. The open claim becomes `Superseded` only when
these per-file receipts cover every original `conflicted_paths` entry.

Coverage and the lifecycle transition share one write transaction. Two final
resolutions cannot both miss the other's already-written receipt and leave a
fully resolved conflict open. On closure, each contributing resolution gets its
`Supersedes` edge to the original open claim in that same transaction. Recovery
of an earlier partial resolution can therefore recognize its completed work even
after another file closed the conflict.

The original open value and each per-file receipt remain unchanged. A single-file
conflict still closes after its one resolution. The mutation queue's prepared
Git commit, branch/path checks, recovery intent and resolution ids are unchanged.
A partial resolution is successful; it leaves the conflict active for the other
files. The active-claim listing retains the original path set, and the resolution
claim listing records which of those files have been resolved.

No new setting, threshold, schema, migration or rollout step is required.
