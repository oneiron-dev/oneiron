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

## Measured text encoding

A newly measured body's manifest carries `text_encoding: "utf-8"` only when
`BodyFacts.text` confirms that its whole final byte stream is valid UTF-8. The
meter checks across frame boundaries; an unfinished final code point is not
classified as text. Measurement follows custody sweeps and their final tail, so this is a
fact about the stored bytes, not the producer's original value. It records the
engine's validated UTF-8 reading; it does not recover a producer-declared
charset. A binary body, a context-only reference, or a projection with no
measured body keeps `None`.

Encoding publishes with the existing manifest and is a required nullable replay
field. Cards include it only when known. It is not a grant, producer-origin proof,
MIME type, JSON-syntax claim, or a ranged chunk's `utf8`/`base64` transport choice.
A fresh byte measurement can establish the encoding when bytes are republished;
producer step/effect metadata still keeps its original replay values. Raw-put
byte validation accepts an explicit unknown encoding. A supplied known encoding
must match the actual byte measurement in the existing full comparison; it does
not replace that measured fact or certify a producer's identity.

MIME type remains unknown here. A JSON encoder's output can pass through a raw
custody sweep before publication, so the encoder alone does not prove that the
final body is still JSON. No new parser, read, setting or refusal is added.

## Caller-declared media type

`store(value, name, {declared_media_type: "text/plain"})` can attach the
caller's explicit media-type declaration to that stored occurrence. The host
carries the string verbatim through the canonical or room route, before the
occurrence is written. Its card includes `declared_media_type` only when known.
A replay retains the original occurrence's exact declaration, including an
unknown value; changing a replayed request cannot relabel that occurrence.
The shadow arm carries the same declaration without publishing a vault row.

This is a caller declaration, not a validated MIME type of the final bytes.
It does not select a parser, prove JSON syntax or a charset, affect body
identity, or grant a read. Custody transforms may change the stored bytes.
Omitting the option leaves the declaration unknown; other producers and
context-only projections do not infer it from serialization, path, kind,
effect or measured `text_encoding`. Byte-validation paths carry only this
supplied declaration into the comparison and retain every measured-byte check.
The current codec requires its nullable field; there is no old-format reader.

The QuickJS bootstrap change is source-only until its controlled component
build replaces the artifacts and manifest together. Do not claim the shipped
component accepts this new option before that rebuild.

## Streamed REPL step outputs

A successful REPL step's observation, separate console evidence and output
files carry the same `producing_step_start` bridge sequence supplied to its
`RecordingJsHost` at entry. This is not the step ordinal or a clock value.
The coordinate joins the existing source rows on the canonical or room
publisher before the occurrence is written. The same guest filename in a
later step already receives a distinct per-step output path.

This carry does not change stored-value replay: those occurrences retain
their original producer metadata. Generic evidence, scripts, resumed wait
replies and pinned-entry observations still have no step coordinate here.
No effect, media type, grant or fence is inferred for the streamed family.
