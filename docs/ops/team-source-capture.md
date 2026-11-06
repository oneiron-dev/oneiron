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
