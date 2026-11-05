# Erased-source runner cancellation

An accepted hard erase or authenticated checkpoint restore clears the existing
copies of a selected source's BYOA input before cancelling its owned runner
attempts. The queue's existing native force-cancel operation remains the only
terminal transition. Terminal rows keep their native no-op behavior.
A full accepted hard purge carries its actual purge context even when that
transaction writes the hard marker later. Marker-bound scrub-only callers keep
their existing marker requirement. The other actor-scrub guards are unchanged.

The payload cursor records the exact original source set for each owned attempt.
A direct task reference or typed development reference selects it. The original
one-hop `CliAttempt` relation also carries that source set to the request row.
Sharing a staged job does not make another attempt an owned cancellation target.
The pass does not follow a growing source map or assign every source to every
attempt.

Payload rows, archive marks, run snapshots, manifest-revision witnesses and the
existing staged-input cleanup finish before the native cancellation loop. The
shared payload flush does not cancel anything. An ordinary Store-only payload
scrub keeps its prior behavior and discards the source association.

Cancellation results leave a writer as private attempt-id/generation pairs.
Observers and stop signals run only after the owning durable commit. A nested
savepoint or speculative recovery preflight does not publish them. Checkpoint
restore publishes them after its image commit, before fallible reopening or
rebuilding. A Cancelled ledger row does not prove that an external process has
stopped.

This does not finish the separate canonical-exhaust artifact erasure work.
Historical artifact versions, shared ASSET retention, statutory holds, custody
retirement and durable owed completion still use their existing rules. An absent
hard marker at a scrub-only seam is not upgraded into erase authority.

No configuration or migration is needed. Deploy matching engine/server binaries
through the normal authorized rollout.
