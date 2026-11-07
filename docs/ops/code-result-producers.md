# Stored-result producer metadata

A value stored by the live executor host carries `producing_step_start` in its
`CodeRunRawOutput` manifest. The value is the host's existing `step_start`: the
bridge sequence at which the producing executor step began. It is not a step
ordinal, a timestamp, or a new permission.

The canonical and room routes set the value before publishing the occurrence.
Replay encoding keeps the nullable value beside the occurrence's existing path,
body facts and source rows. Result cards include it when it is known. A replayed
store that reuses an earlier occurrence retains that occurrence's original value,
including an unknown value; it is not relabelled with the resumed step.

The coordinate does not change a body digest, occurrence id, read check, source
row, secret or taint mark. Non-executor publishers, context-only references,
diagnostics and attachment projections that have no executor coordinate keep
`None` and do not add the key to their cards. This slice covers the live host's
stored-value path, not every executor output family.

MIME, character encoding, effect, grant and fence metadata are not inferred from
this coordinate. Those parts of FIX 4429 remain separate work. No new setting or
worker configuration is required.
