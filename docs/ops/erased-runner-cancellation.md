# Erased-source runner cancellation

An accepted hard erase or authenticated checkpoint restore clears the existing
copies of a selected source's BYOA input before cancelling its owned runner
attempts. The queue's existing native force-cancel operation remains the only
terminal transition. Terminal rows keep their native no-op behavior.
A full accepted hard purge carries its actual purge context even when that
transaction writes the hard marker later. Marker-bound scrub-only callers keep
their existing marker requirement. The other actor-scrub guards are unchanged.

The accepted full purge also clears the target's spawn asks from live code-run
replay rows and kept step starts before the other actor fields go, even when the
marker is written later. The selective rewrite preserves unrelated calls and
receipt metadata. Planned-pack revision cleanup keeps its original marker guard
and post-marker caller; restore keeps its existing authenticated target sweep.

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

## Canonical exhausts and completion

A first native terminal capture records its actual artifact, version, claim and
content hash in the same transaction as successful settlement. Generic result
attachments and caller-supplied artifact metadata do not create this fact. The
byte-free erased-input settlement creates no capture fact.

After the one payload flush, the accepted actor or restore writer joins the exact
owned source subsets to that capture. Before releasing references, it inventories
all native chain and replicated-claim hashes, the actual ASSET descriptors, and
current and remembered governed body instances. It stages source-attributed body
erase notes, then marks a newly selected artifact hard-erased before one native
full purge. If that artifact's original native purge is already running in the
same writer, its before-release inventory is retained and the family joins its
actual completion instead of purging it twice. The original caller's marker
order stays unchanged. Transaction-local context is cleared on success and error.
Historical artifact versions, signed claims, shared ASSET retention, statutory
holds and custody retirement retain their existing rules. A hold on an artifact,
its ASSET or a retained version claim keeps the family whole and owed.

The private continuation keeps original sources, independent instance coverage,
actual retirement names and the native teardown state. The ordinary due pass
settles it. Existing final receipts remain pending until both complete coverage
and the native custody obligations prove retirement. A missing capture or
malformed/missing descriptor is unknown, not destruction. An empty later binder
cannot replace known names or establish coverage. Attempts without a positively
recorded capture remain unknown; no never-captured proof is inferred from absence.
An ordinary Store-only scrub does not gain artifact erase authority.

Capture identities restore as CONTENT structural metadata. Accepted continuations
restore as LIVE structural history, without a dependency that would prune them
when their source or artifact has gone. An authenticated restore re-purges
restored artifact metadata while retaining independent inventory and custody
names. The custody finisher stays outside the writer. This is not a claim of
end-to-end destruction proof or external process termination. An absent hard
marker at a scrub-only seam is not upgraded into erase authority.

No configuration or migration is needed. Deploy matching engine/server binaries
through the normal authorized rollout.
