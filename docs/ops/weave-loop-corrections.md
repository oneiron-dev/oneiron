# Weave loop-decision corrections

A human can mark a shown loop decision wrong from a Person or Owner Weave lens.
The control calls the existing `vault.weave.item.wrong` or
`vault.weave.owner.item.wrong` verb with:

```json
{"item":"loop_decision","item_ref":"<decision_ref from the shown row>"}
```

`item_ref` names the actual `GateDecisionId`. It is not the decision's claim,
actor, or evidence reference. A loop decision takes no `project_ref`.

The label is immutable negative feedback. It does not change the canonical
decision, its outcome, its reasons, a claim, or any read permission. Filing uses
the existing authenticated reader binding and checks the live Admissions report
again in the same writer as the label. Existing clocks, grants, Owner proof,
Admin proof, and advisory correction-count rules stay in force. Agent lenses
still have no wrong control. Admin lens controls remain unbound; the native
Admin label method keeps its existing proof checks.

Both saved-period and live-lens correction evidence count these labels under the
same reader namespace and time rules as other wrong-item labels. Decision refs
remain plain cells, not entity backing handles or read grants.

Redacting a decision to its retained skeleton keeps feedback about that decision.
Physically deleting a decision removes its labels in the same transaction,
including retention deletion and authenticated restore/activation drops. Existing
actor and Admin-grant erasure still removes labels filed by that actor or grant.
A missing claim alone is not a signal to erase feedback about a retained decision.

## Current storage format

The existing `weave:wrong-item:v1:` family uses one family byte (`0` for an entity
or audit key, `1` for a gate decision), the native 16-byte id, then the 16-byte
label receipt id. The two id families cannot alias. Private kept-live-lens item
keys use the same 17-byte tagged key, encoded as 34 hex characters.

This is the current format, with no migration or old-format reader. The table,
CONTENT restore classification, and label value fields are unchanged. A matching
engine/server rebuild is needed after merge; there is no new configuration,
worker, VM, or deployment setting.
