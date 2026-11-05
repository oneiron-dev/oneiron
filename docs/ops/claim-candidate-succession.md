# Claim candidate edits and returned ids

The native code-run `vault.claims.put` result names the actual stored claim in
`output.id`. Callers must use that result, not assume that it equals the input id.
The canonical path and an on-record session use the same native writer.

For an active, non-MACHINE evidence claim, a change to its predicate, subject,
value, confidence, world, relationship, scope or salience writes a fresh successor
and closes the original through the existing supersession machinery. The new row,
its native admission, the original's closure, the `Supersedes` edge and the diff
commit together. A failure commits neither side. The successor retains the scope
stamps the same candidate would have resolved at the original id; those stamps
are data and grant no authority. All native source-trust, consent, criticality,
read and write rules still apply. The close uses the supplied `learned_at` time
and the existing lifecycle envelope clamp.

Hook bindings and connector subscriptions share `agent.connector_subscription`.
They and `affect.vad` annotations retain their stable ids because their readers
and cursors use those ids. Identical semantic retries and lifecycle-only updates
also retain their ids. Value comparison uses MessagePack bytes and confidence
uses its exact float bits; approval and envelope provenance are not value edits.

## Scope of this change

FIX 9589 and FIX 11032 remain PART. This is the native put terminal and its actual
code-run consumers, not a global change to `BatchBuilder::claim_candidate`.
The generic batch and ingest paths, the write-fixture path, off-record overlay
staging, already-closed targets and MACHINE succession keep their existing
behavior and remain separate work. The after-apply candidate terminal used by
VAD annotations and repository review writes is unchanged.

The public JSON and SDK result shapes do not change. A matching rebuilt engine
contains the behavior; no migration, configuration, guest or worker update is
needed. Source comparison and stdin rustfmt are not a compile or runtime result.
No tests are part of this change.
