# Code-consent settlement policy supplier

`code_consent_settlement` is an optional typed field in a trusted
`POLICY_MANIFEST`. It names who may settle a held code effect. It is not an
execution grant. The shipped row is version `1` with
`eligible: {mode: "all_power_holders"}`. This is an authenticated holder of the
power, not a new Owner-only default (DEC-0006).

The other eligibility shape is `{mode: "named", holders: [PERSON_REF, ...]}`.
References are canonical lowercase PERSON ids. The empty named set is empty;
it never means all holders. Listing a person does not grant them power.

The existing policy-manifest Owner and policy-holder write doors carry this
field. Their current proof, same-writer policy power, exact-body comparison,
trust, quarantine and receipts still apply. A typed manifest put replaces the
whole field, as it does the other declared write axes; omitting it removes it
from that contribution. Unrelated policy tables are preserved.

## Resolution and evidence

An authenticated authored row replaces a seeded fallback. Other trusted rows
can only narrow the eligible set. A narrowing row alone cannot create a
settlement baseline. Versions are citations, not a highest-version-wins
permission rule. Distinct authored rows remain an explicit conflict even if a
narrowing row would give them the same intersection. That conflict does not
change an existing Owner answer path or globally fail another Gate axis.

The resolved witness retains every contributing manifest id, exact body hash,
row version and seeded/authored/narrowing origin. The policy frontier hashes
that witness, the resolved eligibility and the authored-conflict status. The
row is cited as `code_consent_settlement@version` with its source manifest.

The hold-time freezer accepts the connector/browser producer's actual
`ExternalEffectGateInput`. It derives the native action bound and serializes
that bound with the existing consent codec. It does not reconstruct missing
connector facts from a caller label, a digest or an unrelated principal. The
opener's original subject remains part of the frozen bound.

Addressable holder candidates come from the existing native grant inventory.
Each must be a live PERSON, pass the row's filter and hold a current active
Action grant bound to that same PERSON as a human, covering the frozen action
class and target envelope. A granting Owner's identity is not a substitute for
a subject match. Non-addressable principal-label grants are not guessed into
PERSON identities by this supplier.

On the answering snapshot, the policy/power evidence reader revalidates the
real person's native authentication, frozen eligibility, exact current policy
witness and current action-grant cover. It returns actual actor, principal,
authentication receipt, grant and policy evidence. It is not an approve-once
capability and does not mint a marker or a receipt.

## Integration state

This supplier is not the complete non-Owner answer route. The actual immutable
code-wait binding must carry and hash the exact frozen value. Connector minting
must freeze at the native HOLD-TIME producer; browser minting must use its
closed native facts. The question, word and answer hooks must use that binding.
The final typed holder act must keep target, opener lineage, original authority,
first-answer, admission, once consumption and settlement in the same existing
writer and ledger. A holder denial must not impersonate the Owner-denial signal
that self-heal consumes. Stop-asking still requires its separate setting power.
Do not expose an Owner/System shim or treat this evidence reader as that act.

No new runtime timeout, count cap or default duration is introduced. The one
new numeric constant is the shipped row's citation version `1`. No migration
or old-format reader is provided. No compile, runtime or full-row completion
claim follows from this source.
