# Code consent reply lineage

A canonical code-mode run that resumes from a bound connector consent wait
keeps `source=Generated` for later writes. Its dispatcher also adds
`ToolOutput` to the write's source lineage when both facts below hold:

1. The settlement's **actual delivered reply**, after the side-row wall,
   decodes as a connector reply with `Delivered { result: Some(..) }` or
   `AwaitingInput`. A delivery without a result, refusal, unknown delivery,
   malformed reply, hold, or pending reply does not establish this fact.
2. The replay commit consumed that settlement into the resumed result.
   The stored settlement receipt and reply digest, parked-step seal and wait
   generation, and resumed result's path, handle and digest must match the
   committed consumption. The bridge call must name that exact wait at the
   binding's call sequence.

The settlement stores a required `external_reply` boolean beside its actual
reply digest. It does not derive the boolean from approval, a verb name,
`source_rows`, or the broad settlement outcome `Delivered`. The settlement
facts digest includes the boolean under `oneiron:code-consent-settled:v2`.
The native consent binding schema version is **5**. The required settlement
field introduced in schema 3, frozen owner set introduced in schema 4, and
original caller-class byte introduced in schema 5 have no defaults, migrations,
or old-format readers. The caller class comes from the admitted Memory surface
and is included in the binding digest; it is not inferred from an actor record.

Before each subsequent guest step dispatches, the canonical dispatcher
joins the committed proof into its existing monotone lineage state. Reopening
uses the native control row and replay metadata, not a copy of the foreign
reply body. An inherited continuation may keep the original run's consumed
step and result; this lookup does not require the continuation's run id to
be the original binding's run id. Existing sealing and consumption checks
remain in place, and nothing answers or sends a call again.

## Scope

This path covers canonical REPL runs and their native bound connector consent
waits. Session replay storage does not commit the canonical consumption fact,
so this lookup explicitly skips session storage and never looks through it
into the base vault. It does not change browser lineage, hook retry rules,
held-call delivery, grants, masking, output erasure, or pending bridge outcomes.
Direct recorded SDK connector answers are a separate lineage supplier. These
slices do not by themselves close every connector or session provenance path.

A consent-only `connector.call` made through `self.use` uses the same bound
code-consent wait as a direct connector call. Its call site keeps the actual
`self.use` request identity, while the pending effect remains `connector.call`.
Other `self.use` operations and holds for reasons other than consent keep their
existing answers and waits.

A hard-stopped REPL entry still commits the real wait it reached beside its
failed-step checkpoint, but returns its original runtime or provider error,
not a successful Waiting outcome. Reclaim and redirect can then resume the
same run under a new valid lease. Force-cancel and terminal lease expiry do
not revive the attempt. The retained seal can still make the already-admitted
owner question answerable, just as when the run parked before force-cancel;
the owner's real answer and the effect's existing gates remain required.

## Shared-vault owner questions

A held call freezes every live vault owner's identity in its minting writer,
not just the lowest-ID owner. The frozen, sorted set is part of the binding
digest under `oneiron:code-consent-binding:v2`. One native `People` TASK ask
creates a member consult for each owner and registers the existing human
followup path. Missing contact routes leave questions on the asks list; this
does not claim delivery to a client without a route.

Only an asked owner's own Human word is admitted, and the same word writer
checks that the speaker is still a live vault owner before recording it or
settling the TASK ask. A newly added owner is not silently added to the frozen
question. The TASK ask's first-word receipt does not approve the held call.
Later words remain evidence: if one speaker loses ownership before answering
the consent wait, another still-live asked owner can give their own word and
answer it. The consent operation reads the admitted word, not just the TASK
ask's first-word selection.

The first authenticated consent answer still wins in one writer. Existing
sealed-target, same-speaker, current owner authentication, opener-slip lineage,
original-caller authority, and effect-gate checks stay in place. This adds no
quorum, extra approval step, new wait, public answer fields, or membership
refresh on an already-open question.

## Terminal held-call settlement

A terminal held connector call commits its held-call state, code-consent
settlement, receipt and parked-run reply in one native transaction. This includes
a tool reply, a refusal, unresolved delivery that will not be retried, and a
connector question. The live reply is cleared before that transaction. Existing
side-row masking, erased-actor handling and first-settlement rules still apply.
Connector questions bind their live host handle in memory before that commit
can publish the reply. Durable resume persistence follows the commit. If the
commit fails, the host abandons the live handle and drops its pending resume
state. No registry mutex is held across the row or resume writer.

The outbound intent ledger remains receipt-only. Recovery without retained live
reply bytes still reports `result_not_retained`. Expiry commits an existing held
row with its wait and keeps the existing receipt-only fallback for a row that
disappeared before the writer. This does not promise reply recovery across a
process exit before the terminal transaction.

## Retrying an unopened typed question

The existing connector settler pass retries an unopened typed consent question
for record-keeping connector calls. It uses the original actor and actor class
captured by the admitted caller, not an actor-type guess, a current live-run
lookup, or the owner or system actor. The native reserved-ask and actor-write
checks still run. A failed retry leaves the generic held-call question in place
and can retry on a later pass. Opening the question does not answer it or
authorize a send. The original credential, grant, scope and frozen-input checks
are unchanged.

A sealed NoRecord call (FIX 4520) captures its caller's live session binding
before its first typed question can fail. If that question does not open, the
binding stays in the RAM of the exact session instance, keyed by the wait,
beside the held call's ref. It is never serialized beside the sealed arguments,
and it is never rebuilt from a session name after a restart.

The same settler pass then retries through that binding. It runs the same
native question and ask as the first attempt, as the original caller, on the
caller's own surface in the original session. Hooks and receipts are kept as the
first attempt kept them, so an Anonymous route gets no ordinary durable receipt.
The pass never uses a bare record-keeping Memory surface for a sealed call.
Before each attempt, and in each commit that attaches the ask, the binding
checks the exact session instance, the captured route generation, the caller's
own proof and the caller's place in the session. The ask's own writers check the
author's write authority. The binding is correlation, not authority. It adds no
grant, consent, refusal, wait, retry clock or new error.

The pass drops a kept binding when the ask is attached, when the call or its
wait is terminal, or when the caller's binding is refused. Session close drops
the rest. An actor erase does not touch the binding inside its transaction; the
next pass finds the row gone and drops it. A sealed call with no kept binding
(the capture failed, the process restarted, or the session closed) keeps its
existing initial-question, generic fallback, release and expiry paths. The
connector hold expiry and settler interval are unchanged.
