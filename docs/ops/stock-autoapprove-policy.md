# Stock-model automatic approval policy

ARCH-0053 R13 gives the owner one switch. It is OFF in an untouched vault.
The switch permits automatic stock-model changes only when the candidate is
not worse and not pricier, including equal price. An unknown comparison stays
an ordinary offer. Training never deploys a model automatically. A new download
still needs its actual download card once, even when this switch is ON.

## Save the owner's setting

The owner can read `GET /v1/owner/settings/stock-autoapprove` and write
`POST /v1/owner/settings/stock-autoapprove` with `{"enabled": true}` or
`{"enabled": false}`. These routes use the existing owner credential and holder
proof. Embedded hosts use `Vault::stock_autoapprove_policy` and
`Vault::set_stock_autoapprove_policy` with an actual `AuthenticatedOwner`.
There is no environment or configuration-file override.

The answer has `enabled` and `revision`. Absence reads as
`{"enabled": false, "revision": null}`. Only a changed value writes a new local
revision. A no-op still revalidates the caller, but records no new policy act.
An OFF -> ON change cannot revive an old ON revision. The owner-setting act
and optional signed operation follow the native policy-setting record path.
The setting is LIVE restore state, like the other owner policy settings.

## Native trial recommendations

`ModelTrialPolicy` no longer accepts a caller's `auto_approve` flag. On a new
trial completion, the native writer reads this owner setting after the original
question/backend/quality checks, and passes it to the existing action predicate.
The same not-worse/not-pricier rule, download flag and tradeoff choices apply.
The receipt keeps the exact `stock_autoapprove_policy` value that writer read.
An immutable completion replay returns its original receipt before reading a
new policy value. It never relabels a historical recommendation.

`ModelTrialAction::AutoApprove` remains a recommendation for the activation
owner. It does not bind a model or approve a training offer. An activation must
re-read the live policy and verify current serving/quality/price/download
facts. This change does not claim that automatic application or the actual
download-card-once path is complete. Existing manual approval and undo remain.

## Authority is not authentication

A policy revision identifies saved standing permission. It is not a current
owner credential, an `AuthenticatedOwner`, or an authentication decision id.
Reading ON does not prove quality, price, availability or download consent,
and never reports that a model has already applied. A later automatic answer
must re-read the policy in its committing writer and record policy provenance
separately from the owner's direct answer. `OfferAnswerRecord.authority` is
`{"kind":"owner","owner":...,"authentication":...}` for the person's present
answer, or `{"kind":"stock_policy","revision":...}` for standing permission.
A policy answer carries no synthetic owner or authentication id. The owner's
existing manual offer, training and undo doors still require their own live proof.
