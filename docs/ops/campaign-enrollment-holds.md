# Held campaign enrollment calls

A campaign enrollment can reach the ordinary outbound Gate and return a hold.
The engine retains that observed hold beside the original enrollment request.
It asks the owner once for that hold and keeps the question's sequence with it.
Answering a generic question does not approve an outbound effect.

## Review and press

The owner-facing facade verbs use the same native owner proof as the consent
lifecycle doors. An agent credential does not become an owner proof.

- `vault.campaign.held`, with `{}`, lists retained hold observations. Each entry
  includes the call ref, current recorded approval digest, frozen event ref,
  original attempt ref, owner-question sequence, and any approved redrive ref.
- `vault.campaign.approve_once` takes `call_ref` and `approval_digest` from the
  reviewed hold. In one writer, it revalidates the owner, recomposes the same
  original request against its frozen event and current program, checks the
  reviewed digest and erase fences, approves that exact effect once, and queues
  the original typed enrollment payload. It creates no standing grant.

A moved request or digest is not approved under an earlier review. The owner
reviews the new hold instead. The receipt records the exact approval, and the
hold status lists the queued redrive ref. Repeating an old, terminal attempt's
dedupe key is not used to restart it.

The ordinary campaign pump owns the redrive. It still checks home and membership,
Gate policy and consent, budget, the intent ledger, and the real transport. The
approve-once door itself sends nothing.

## What the status means

The list is the last observed hold, not proof of current send authority. An
`approved_redrive` is evidence of queued work, not a successful or sent call.
A call that is no longer held retires its auxiliary question while retaining the
original request and ledger history. Erasing the original call removes the
retained request; erasing an auxiliary attempt or frozen reference clears its
held metadata without deleting an unrelated original request.

Erase-time question withdrawals are announced only after their owning transaction
commits. Raw deletes and replay chunks carry the actual changed question sequences
to that commit. A successful nested replay passes its sequences to the existing
parent transaction drain. A failed child or root transaction announces none.
Grouped restore and legal-hold writers keep that same drain, including when a
later post-commit operation reports an error.
