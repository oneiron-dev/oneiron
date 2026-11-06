# Team source capture

`self.team.start` and `self.team.record` accept an optional `captureScope` in
`ClaimScope` form. It chooses the native position of an optional canonical claim.
An absent or null position captures nothing. A failed capture does not reject the
ordinary start or receipt.

## A new team start

Only the final successful start can capture its newly authored membership. The
claim contains the team's stamp, leader, start time, member attempts and widening
proposals. It does not contain the leader's private TASK binding or attempt
payload. Partial/refused starts still keep the members they queued, without
capturing a source. A planned start and an existing native binding mint no new
witness.

The host uses the actual write envelope and host-turn read key. The fresh claim
must pass that original reader's policy in the same savepoint. Its source
identifier grants no read authority.

The native binding keeps the claim id and exact claim-body hash, its physical
native key, and a canonical hash of every `TeamRunBinding` field. Source metadata
is outside that hash. An unchanged replay keeps the witness. A changed native
binding clears it. Deleting and recreating a row cannot revive its old witness.

## New member dispatches

`self.team.start` also accepts a separate optional `memberCaptureScope`. It
chooses the position for publications of newly enqueued direct members only.
An absent position changes nothing. An existing/deduped attempt, planned spawn
or workflow wrapper mints no witness. A later member's failure keeps earlier
successful enqueues and their publications, as it keeps those members today.

Each publication contains the new attempt's identity and creation time, its
actor, placed type and project, and team stamp. It contains no briefing,
private payload, model, manifest or TASK value. The original actual host-turn
key must admit the fresh claim in the enqueue's savepoint. A capture failure
discards only that publication and preserves the ordinary enqueue.

The native payload retains the source pointer. Its binding hashes the physical
attempt id, kind, creation time and complete original payload, excluding the
source metadata itself. A normal typed payload rewrite drops the pointer; a
retry's different id cannot reuse it. Neither case grants access to old native
rows. A receipt keeps available descriptors from the status rows it actually
consumed. Coach first admits each exact publication with its own scoped reader,
then verifies the current native pointer, birth hash and projection in the same
snapshot. Missing, changed, retired, withheld or malformed sources stay unknown.
Lease state, later model/manifest measurements and all other receipt cohorts
remain separate. A partial witness never completes the receipt's fact-source set.

## Receipt and Coach reads

A receipt retains the start descriptor from the same native-row read used to
compute its facts. Later Coach qualification uses Coach's own scoped reader,
not the start caller's key. In one snapshot it admits the exact captured claim,
then checks the native source pointer, physical key, complete run-body hash and
captured projection. A missing, changed, retired, withheld or unqualified source
stays unknown. Ordinary receipt getters expose no captured claim value.

The original-input witness on `self.team.record` remains separate. Neither
witness supplies unknown attempt, launch, observation, model, market or pattern
facts. An incomplete receipt fact-source set stays `None`; an individual witness
does not turn it into a complete source set.
