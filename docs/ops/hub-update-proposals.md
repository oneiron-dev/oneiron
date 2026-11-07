# Settle a hub skill update proposal

A hub sync can return `proposed` and a proposal id. The working skill and its
admitted capabilities stay unchanged until the owner accepts that proposal.
Initial-import permission asks remain a separate operation.

The owner answers through HTTP `POST /v1/core/facade/vault.skills.proposal.settle`,
the matching MCP verb, or the generated SDK verb. The input is:

```json
{"entity":"<skill entity id>","proposal":"<proposal claim id>","accept":true}
```

The response names the same entity and proposal, and its actual `approval`:
`approved` after the exact package commits, or `rejected` after a rejection.
An agent cannot borrow the owner's proof for this door.

Acceptance refetches the proposal's configured hub source and queries dependency
advisories before opening the effect's writer. The ref, content hash, version,
capabilities and body-change review context must still match. A moved ref or a
changed proposal returns an error and leaves the proposal open. The writer
rechecks the owner, current imported skill, source alias, ref policy and the
owner's content-hash block rule.

The first imported record write carries a native exact-record `OwnerConsent`
admission proof. Its constructor spends the one-use authorization in the same
writer; there is no second spend and no fabricated held-out result. Native origin,
hash-block and callable sandbox admission checks remain in force.

One transaction commits the consent receipt and its spent one-use authorization,
the actual package, capabilities, provenance and scan receipts, the skill's
`Approved` stamp and matching package sidecar, and the proposal's
`Approved/Retracted` close. The skill's local lifecycle and governance are kept.
The owner's acceptance answers the scan ask; it does not require a new held-out
improvement result and does not leave a working Active skill at Proposed.
After commit, the existing ref-tracking door marks that fetch revision trusted.
Automatic sync keeps its existing policy and savepoint behavior.

With `accept:false`, only the pending proposal closes `Rejected/Retracted`.
Rejection does not fetch a package, query scanners, mint or spend an approval,
change the working skill or capabilities, or mark a revision trusted. A proposal
that has already closed cannot be accepted or rejected again.
