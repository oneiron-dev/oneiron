# Proposal birth attribution

`ProposalTextArtifact::open` and `open_generated` capture the attempt in the
current run-write token when the artifact opens. They do not read the later
finalizer's or keeper's run. No token means an honest unknown birth attempt;
opening a proposal does not require a run.

The optional `birth_attempt` uses the existing proposal document's `meta` map.
It survives `export_snapshot` / `from_snapshot`, then enters the finalized
record. Imported endpoint-only proposals have no captured birth attempt.

When the edit-distance evidence door has no usable explicit attempt executor,
it checks the generated proposal's birth model first, then the captured birth
attempt's terminal pack receipt, then the host's executor. A missing receipt or
executor leaves the existing unknown result. Task type and project selection
are unchanged. `MadeByTrigger::Run` is a replay-record id, not an attempt id.

This supports the public proposal API. It does not add a server interview-birth
route or capture the birth of an inbox claim. Inbox/FieldDiff attribution remains
separate; callers that know the drafting attempt can still pass the existing
`attempt_receipt` evidence field. No served-ingress coverage is implied.

## Storage and erase

The persisted proposal-artifact record uses schema 4 and requires the
`birth_attempt` member: MessagePack binary containing an attempt id, or Nil.
Only schema 4 is read; there is no older-format reader or migration.
The existing proposal tables and checkpoint classifications are unchanged.

Proposal erasure still drops its document and texts and anonymizes affected
spans while retaining record identifiers. The captured attempt is one such
identifier. Attempt payload erasure and attempt-record pruning retain the
terminal pack receipt. This change adds no new erase policy or global erase
completion claim. A normal engine/server update is sufficient; no configuration
or deployment action is performed here.
