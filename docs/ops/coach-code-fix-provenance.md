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

## Native embedding: associate an exported result with local input

Native hosts can use the public
`dreamer_runner::maintenance::code_fix::publisher_candidates_with_refs`
helper to reconstruct references from their complete `PublisherCandidate` slice.
It uses the same implementation as initial replay and catch-up. Do not construct
references from a filtered missing-candidate list or compare a label alone.

For each retained `CodeFixWork.settled`, call
`CodeFixSettled::publisher_candidates_for_result(result_id, full_candidates)`.
It returns borrowed pairs of the local `CandidateRun` and its matching publisher
input for a `CodeFixExport::FixResult` id. Invented-example ids do not select a
candidate run. It requires both the run's queued public record id and the exact local
label/reference match. It returns all matches, never an assumed unique input.
A Coach draft or withheld run cannot match. A current slice without that input
returns no association; historical association requires the corresponding kept
input slice. Removing identical occurrences can change their local addresses.

The result id alone does not prove origin. The local work row binds that id to
its candidate reference in the same write that queues the export. A delivery
acknowledgement removes the queue row, not this work binding. The owner's erase
or cleanup can still remove local work. This view does not prove a record is
still eligible to send, that it was delivered, or that a replay succeeded by an
independent measure. Use the existing export doors for sending.

This API reads only the local objects the caller supplies. It changes no export
bytes, consent, record version, queue state or publisher identity. A remote
receiver without the retained work and input slice still has no self-describing
input association. Independently anchored outcome learning remains open. No SDK
verb or generated wire shape is added, and no setting or numeric default changes.
