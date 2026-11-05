# Blob artifact versions after producer retirement

Checkpoint capture keeps each blob artifact head and version in the artifact's
compartment. The producer actor is a separate actor part. The `blob.version`
claim is kept in its own claim compartment.

If the actor's compartment retired after capture, an authenticated restore can
still preserve a version when its original claim remains readable. Restore
checks the native claim in the same write transaction. The claim must name the
exact artifact and match the complete stored version binding, including the
whole MadeBy envelope with only its actor restored. The recovered actor must
belong to both the unopened compartment set and the restore's erased set.

Only version and head rows missing their actor part wait for this check. Normal
version, head, hosting and other payload rows keep their original landing
order. The deferred check runs after payload rows, custody handling, type
indexes and stored agent pins have landed.

The recovered original is an intermediate row inside that write transaction.
The existing authenticated actor scrub then rewrites the version and its bound
claim to genuine erased attribution before commit. Existing claim holds preserve
the complete record/claim pair under the existing hold behavior. No reader sees
a new committed restored-only intermediate state. This does not close deferred
hold-release work or every actor-erasure path.

A missing, unreadable, malformed or mismatched claim supplies no original actor;
the row remains omitted, as before. Claim proof or binding failures do not add a
new restore prerequisite. Storage and I/O faults still fail the restore, and
malformed version records keep their existing failure behavior. Missing live
compartment custody still fails before a destination is made. No new actor
identity, attribution state, compatibility reader or checkpoint format is added.
