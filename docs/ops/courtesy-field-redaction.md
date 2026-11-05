# Local selected-field courtesy redaction

`vault.courtesy_delete.answer` accepts `redact` selections when `choice` is
`redact`. Each selection names `record` (32 hex) and `value_fields` (literal
keys of that CLAIM's `val` map). Repeated records/keys are combined. Empty
`redact` records the menu choice without a field action, as before.

The answer writer revalidates the owner and selects only this ask's actual,
still-present pact/world/epoch copies. Non-copies and missing copies are
reported in `excluded`. Real legal holds and independently selected storage-only
restrictions still apply. A failed edit rolls back all edits and the answer.
No hold or restriction is lifted just by choosing Redact.

For supported ordinary CLAIMs, the local executor removes only the selected
map entries. It preserves the header and every unselected field/entry's wire
bytes. The existing ordinary body/family/source-trust admission still runs.
It does not change subject, source, evidence, world, relationship, facet,
project, authorship or ClaimOf. Reserved/family-owned claims and record-headed
entities need their existing typed document/family doors; this slice does not
bypass them. Keys are not JSON paths, free-text reasons, or inferred names.

Every historical `record.raw` insertion is rewritten in a fresh full Loro
snapshot. Operation ids, dependencies, timestamps, messages, operation order
and frontiers remain; the exported artifact's typed history is verified.
Unselected history is not deleted or restarted. The writer installs the
snapshot and exact retained/reverse bindings together. It discards old staged
text/phonetic/vector inputs, publishes the current redacted lexical/phonetic
view, and queues a fresh embedding without retaining the old vector.

`local_redactions` reports only the local action: actor/time, record, selected
keys, changed historical-row count and exact old/new revision bindings. Receipts
are retained on the filed ask across later menu choices. Frontier-derived
references retain causal identity. Raw-derived references rekey to the actual
rewritten raw hash. Old full-body/content pins are never re-signed or silently
retargeted. A changed short-reference hash byte makes its old pin stale; the
8-bit hash alone is not proof of content equality.

## What this does not claim

This is the first **local field/history** slice, not complete A9 or peer erasure.
It does not rewrite old snapshots, checkpoints, previously exported copies or
replicated window history. Persistent selector/replay normalization, export
scrubbing, ingest settlement and recovery canonicalization remain open. The
existing B2 clamp still excludes non-delete answers' covered copies from
ordinary shared retrieval. No numeric retention period, expiry nudge, automatic
name detector, new global refusal, migration or compatibility reader is added.
