# Coach code-fix candidate provenance

`Vault::code_fix_work(limit)` returns each failure's local code-fix work. Each
settled `CandidateRun` has a required `coach_own` boolean:

- `true`: the Coach drafted this candidate for this run.
- `false`: the host supplied it as a pinned publisher candidate, including a
  catch-up run for a candidate pinned after the failure settled.

The engine carries that origin beside the candidate object. A candidate id, even
one beginning with `coach.`, does not establish its origin. If a publisher uses the
same id as the Coach's draft, both candidates keep their own instruction and origin.
Publisher catch-up and retry matching do not mistake the Coach's result for a
publisher run.

This field changes neither export consent nor the replay's model judgment.
`FixOutcome::Fixed` still means the decision ladder judged the replay fixed. It is
not independent evidence of success. These records do not feed Coach reliability
learning without the separate native anchored-outcome join.

The record format requires the field. There is no old-format reader or backfill.
Deploy a matching engine/server when consuming the new result shape. No setting,
new timer, model prompt, or model worker change is required.

## Publisher input matching

The work view's `CandidateRun.publisher_ref` is required and nullable. Only
an actual Coach-drafted candidate carries `null`. A publisher reference records
the input kind, the instruction's BLAKE3 content digest or the actual engine
build/patch pin, and an occurrence number among equal ids and inputs in the
host's complete candidate slice. It is a local input association, not proof of
the publisher's identity, authority or provenance. The caller's id stays a
label; an instruction digest is only a content comparison.

Catch-up, selection and kept-result replacement compare both the label and
this reference. Two objects sharing a label no longer suppress or replace each
other when their instructions, engine pins or occurrence numbers differ. A
changed input gets its own run instead of inheriting an older input's verdict.
Reordering other inputs preserves the references. Identical inputs are numbered
in collection order; removing one can change their local addresses. Neither
old nor new result rows are discarded, and a retry still replaces only its own
not-run row when the native Grant/protocol conditions allow it.

References are computed from the full borrowed host slice before catch-up
enters the writer. Missing candidates keep those references through replay,
including not-run results; they are never renumbered from the missing subset.
Only selected replay inputs clone instruction bodies. The hosted catch-up
caller passes its actual candidate objects rather than dropping their kinds
into a list of labels.

The `CodeFixHost` trait, native engine target's label and content pin, replay
Grant/authority checks, export records and shadow protocol are unchanged. An
export's `result_id` still identifies its record, not a self-describing join to
a publisher input slot. Export occurrence carriage and independently anchored
outcome learning remain open; this matching fix closes neither. Current-format
work rows carry the new field directly: there is no compatibility reader,
legacy wildcard, work-key change or migration. No live replay or runtime proof
is asserted by this source change.
