# Code-consent settlement policy

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

Browser sends also retain their actual hold-time project and audience. Both
candidate discovery and the answering writer use `BrowserSendScope::covered_by`
on each person's current human-bound grant. This is the same native selector,
target and budget treatment as a browser send, including its existing unknown
project/audience behavior. A project-scoped grant is not compared with a
made-up generic `browser` target, and its granting Owner is not substituted
for the person who holds it. The frozen browser scope is covered by the same
binding digest as the rest of the settlement value.

On the answering snapshot, the policy/power evidence reader revalidates the
real person's native authentication, frozen eligibility, exact current policy
witness and current action-grant cover. It returns actual actor, principal,
authentication receipt, grant and policy evidence. It is not an approve-once
capability and does not mint a marker or a receipt.

## Integration state

The immutable code-wait binding carries `holder_settlement`, including the
exact policy witness, action bound and candidates. Its canonical typed MessagePack bytes
are length-bound into the binding digest before the effect's own digest is
composed. Encoding errors propagate; no missing or placeholder policy bytes
stand in for the value. Connector minting freezes inside the pending call's
writer while it still holds the native HOLD-TIME input. Browser minting uses
its engine-stamped facts and the same private pinned-input builder as the
send's approval digest.

The question addresses the frozen Owners union the frozen eligible holders.
The original Owner set stays unchanged in the binding. A wait with neither
Owners nor holders is not minted. Human word admission accepts an asked live
Owner or a live frozen holder; a word is evidence, not settlement authority.
The answering writer requires native Owner authority or the current typed
holder policy and action power before inspecting first-answer state. The
public status read applies the same current admission in its read snapshot.
The server preserves the full Owner-proof fast path and binds fallback slips
with the native person-credential binder, not only the request-liveness binder.
An Owner's narrowed person credential does not acquire Owner authority from
the person's identity: it needs the holder policy and power like any other
person credential. The original opener-lineage exclusion still applies to
answers, not to an Owner's status read.

The native holder receipt projector now writes the real human actor to the
existing Gate ledger without an Owner stamp. It retains actual grant, policy
citations and frontier. Its holder-denied reason differs from the Owner-denial
signal that self-heal consumes. Historical settlement attribution does not
revalidate or gate an already completed effect. Attribution is data, not a
credential and not authority to claim an approve-once marker.

The typed `act_on_code_consent_wait_as_holder_in_txn` entry accepts the
native answer target and authenticated person, not a supplied approval digest
or policy proof. It loads the persisted wait, verifies its binding digest and
schema, parked checkpoint, exact target, first-answer state, the person's
actual word, opener lineage and original authority. Only then does it resolve
the current policy and action power in that writer. An approve-once act claims
the existing marker and writes the human Gate receipt in the same transaction;
a denial writes its distinct holder receipt without a marker. Both acts
queue the existing transaction-owned consent-answer wake flag after the
receipt. The wake fires only after committed group durability, never before
commit; rollback drops it. An already-answered or refused-target result does
not queue a new answer wake. This event is not permission to run the effect.

The answer hook calls this closed act before recording its first-answer stamp,
in the same writer. A result with no act does not create an answer stamp.
The stamp records the returned decision and actual person, authentication and
policy frontier. Its optional typed `holder_basis` retains only the actual
grant reference and resolved policy; it does not duplicate the identity fields.
An Owner answer has no holder basis. Admission, once consumption and settlement
retain their existing proof requirements.

A later holder settlement reconstructs the historical holder attribution from
that stamp and basis, then appends its actual settlement receipt through the
holder projector. It does not reauthenticate the historical actor, manufacture
an Owner stamp or write a System receipt in place of the holder. The original
Owner and unanswered-settlement paths retain their existing receipt door.
Stop-asking still requires its separate setting power; effect-settlement power
alone cannot change a connector setting. The existing Owner three-choice
route remains unchanged. The consumer adds no second consent-answer wake.
The policy evidence reader and receipt projector are not approval doors.

The served facade uses the existing request-bound native person proof. Its
pre-hook check authenticates that person, not their settlement authority.
The Memory door still requires the same human actor and vault-bound proof,
refuses generated-code answers and reads the ask and word through the caller's
credential. The engine's current policy and power checks remain the authority.
Record-scope flags and managed-person and invitee allowlists stay unchanged.
The embedded verb calls retain their constructor-owner and writer-lease proof;
merely binding another human actor does not authenticate that person.

No new runtime timeout, count cap or default duration is introduced. The
shipped row's citation version is `1`. The binding schema is `6` (was `5`)
and its hash domain is `oneiron:code-consent-binding:v3` (was `v2`) to cover
the new frozen field. These are format/identity revisions, not runtime
policy defaults. No migration or old-format reader is provided. No compile,
runtime or full-row completion claim follows from this source.
