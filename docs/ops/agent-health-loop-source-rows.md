# Agent-health Loop source rows

The agent-health review can record a host-local model-input read-row union for
an actor-only `loop` card. It records the actual native call-receipt keys for
the whole stream, including the calls that delimit a repeated run, and the
witnessed review, loop-threshold, window and card-floor settings. Catalog
settings contribute a known empty set. Owner settings, unwitnessed fits and
reviewer-seeded settings leave this union unknown.

The blocked-state read keeps the TASK and MESSAGE reads in one snapshot.
Every MESSAGE header read contributes its actual row, including headers too
old for the report window. A missing typed TASK, dangling MESSAGE edge or
failed read leaves the union unknown. The old blocked flag and error handling
remain in use. The boolean TASK reader delegates to the same native typed-body
reader that returns its actual row id.

Only the actor-only call-stream Loop producer supplies a known set. Streams
with an attempt witness, attempt-backed findings, unread receipts, other
signals and attribution causes leave it unknown. Card merges union all known
contributors; one unknown contributor makes the merged set unknown. A late
attribution fold also clears the local union. Erasing an actual entity member
clears the whole union, not a remaining subset. This does not remove the
card's evidence, numbers or existing draft.

Saved Weave cards carry the same numeric witness. Each known member joins the
saved period's existing erase index, even when the card has no Coach draft or
its draft was already scrubbed. Deleting a numeric member clears the whole
saved union, rebuilds the period's index and drops its saved render without
changing draft text, evidence or the draft-erased flag. If that member is also a draft source,
the existing draft scrub still runs. The served copy checks every numeric
member's deletion or stale state in the same read snapshot before checking the
draft. This also covers saved periods whose index lacks numeric membership;
there is no backfill or new index family. The period and card still serve.

The Coach brief combines the stored card union with loaded-skill, current-TASK,
observed-brief and actual logged-pad-read rows. All five contributors must be
known. Other pad outcomes remain unknown; they keep their existing model
inputs and access behavior. `AgentHealthCoachAnswer.source_rows_complete`
records whether this brief union was known at draft time. The answer's
`source_rows` remains the separate known-source erase witness. Existing draft
membership, subject/TASK/pad checks and sticky erase behavior are unchanged.

These are host-local model-input rows, not an assertion that a primary-entity,
world, secret, erase or authority resolver recognized every key. Call receipts
are native side-table rows, not primary entities. `RunAdmission::sourced`
carries the rows without resolving them. Routing, recipients and owner-copy
policy are outside this model-input union.

The stored card's new `source_rows` field is required and nullable. Missing
fields are not default-filled; there is no migration or old-format reader.
Generated SDK mirrors come from `python3 scripts/sdk/generate.py`.

This implements only the Loop slice of FIX 7147 / FIX 6997. Other detectors,
complete attempt-attribution witnesses and full guard-aware provenance remain
open. No numeric defaults, thresholds, caps, timers or access policy change.
