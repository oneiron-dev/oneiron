# Review and settle one claim under a native Grant

`vault.claims.review` and `vault.claims.settle` accept an optional `grant_ref`.
Without it, both keep the existing owner-proof path. With it, both act as the
credential's actual holder under the explicitly named native consent Grant.
A Grant reference is not itself a credential.

## Delegate the action

The authenticated root owner can use the engine API
`Memory::delegate_memory_authoring` with
`MemoryAuthoringAction::ReviewClaim`, the delegate's actual `WriteActor`, and the
exact proposed CLAIM id. The normalized action is `memory.claim.review`.
The existing consent registry returns its Grant and receipt. The holder passes
that Grant's bound digest as `grant_ref` (64 hex). Existing consent revocation
revokes it. This change does not add a host mint door for memory-authoring Grants.

The bound covers this claim's review and either approval or rejection. It does
not cover a claim's subject, another claim, a whole vault, or generated-claim
vetting. The owner can create another explicit bound for another claim.

## Review and answer

1. The holder calls `vault.claims.review` with `claim_ref` and `grant_ref`.
2. The holder reads the proposal and its content-bound `review_id`.
3. The holder calls `vault.claims.settle` with the same `claim_ref`, `grant_ref`,
   `review_id`, and `decision: "approve"` or `"reject"`.

The action Grant adds no read rights. The holder must already be able to read the
proposal through its ordinary Recorded read lane. Its effective credential scope
continues to apply. A transported holder must present its own verified credential;
an in-process host keeps the existing trusted native invocation boundary.

The writer rechecks the holder, live credential, live ordinary Grant, current
root-owner issuer, exact claim/action bound, native readability, reviewed body,
pending row, policy frontier, and opener lineage. A proposal's opener cannot
settle it. Existing MACHINE history and pending-consent rules still apply.

A holder answer is `answered_by: {"kind":"grant","grant_ref":"..."}`.
The durable settlement row names that Grant and the actual actor. Holder reason
codes are `gate.claim.settle.holder_approved` and
`gate.claim.settle.holder_declined`; owner reason codes stay unchanged.

A Grant does not manufacture an owner answer to a critical owner obligation.
Approval reaches the ordinary native Gate as the actual authorized holder,
including its actor and agent-definition approval ceilings. The holder's Gate
envelope is separate from the stored claim's original author, source, lineage,
and provenance; approval does not replace those authorship fields. A held or
refused action does not land. Owner approvals and generated-claim vetting keep
their existing path. The typed `vault.claims.retract` revert and VAD post-commit
warning behavior remain. `vault.claims.vet` and `.vetting` remain owner-only.

Policy-row `Rule {row_id, version}` settlement authority is not implemented by
this slice. No migration, compatibility reader, configuration change or new
lifetime/default is introduced. Deployment needs the updated engine/server and
regenerated SDK surfaces.
