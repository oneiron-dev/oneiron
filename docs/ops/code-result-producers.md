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

## Large JSON reply effects

A large JSON reply spilled by `dispatch_call` or its callable-skill path also
carries `producing_effect`. This is the actual bridge `SelfCall.effect().as_str()`
label, such as `self.verbs.call`, not the inner verb, action digest or grant. The
canonical and room publishers set it before publishing the occurrence. Encoding
requires a nullable field; result cards include only known values. A replayed
reply keeps its earlier occurrence's exact value, including `None`.

Typed large inference-default, settled-ask, world-privacy and native team-start
replies also carry the same actual bridge effect. They keep their existing guest
JSON shape, sweeping sink, source rows, result card and stored-value occurrence
allocation. Canonical and room routes set the effect before publication; replay
keeps the earlier occurrence's exact value, including `None`. Storageless and
inline replies keep their existing behavior.

Generic stored values and direct arbitrary reply publishers do not guess a
label for a new occurrence. Other executor output families remain outside this
effect slice. Copying supplied effect metadata before byte validation preserves
all existing byte comparisons; it does not prove the metadata's producer.

MIME, character encoding, grant and fence metadata are not inferred from either
producer field. Those parts of FIX 4429, and effect coverage outside these large
bridge replies, remain separate work. No new setting or worker configuration is
required.
