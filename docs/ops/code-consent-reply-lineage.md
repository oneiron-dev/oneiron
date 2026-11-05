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
The native consent binding schema version is **3** (previously 2); the new
settlement field has no default, migration, or old-format reader.

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
