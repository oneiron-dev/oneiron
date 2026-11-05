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
The native consent binding schema version is **4**. The required settlement
field introduced in schema 3 and the required frozen owner set introduced in
schema 4 have no defaults, migrations, or old-format readers.

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
