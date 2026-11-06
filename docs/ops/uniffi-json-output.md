# UniFFI opaque JSON output

`WireJson` carries compact JSON text inside a typed foreign record. Its owned
`Lift<serde_json::Value>` conversion consumes arrays and objects with explicit
iterator frames. Keys and scalar values use the active `serde_json` serializer;
array order, object insertion order, escaping and number formatting stay native.
The conversion drains its owned frames before returning an encoding error.

Pending proposal results use a direct typed lift for `vault.artifacts.proposals`,
`vault.artifacts.propose_output` and the proposed result of
`vault.artifacts.append`. The shared client call still completes before this
conversion. The public generated records and their `summary: WireJson` field
are unchanged. Made-by metadata keeps the existing record codec.

This removes the extra JSON-tree record round trip for those proposal results
and recursive rendering and ordinary destruction of their summary at this
boundary. It does not remove recursive JSON values from native proposal getters,
the shared client, verb hooks or the general generated-record codec.

Five nested proposal results (`vault.artifacts.propose_deck`,
`vault.artifacts.body.deck.export`, `vault.artifacts.admit`,
`vault.artifacts.review_slides`, `vault.artifacts.ask`) use the same direct
typed lift. Each consumes its nested `proposed` first. Ask-unit JSON and
non-null narrowed `requested_schema` values move owned into their `WireJson`
leaves. A null schema still reads as absent; false `on_device` and empty
`reasons` still read as omitted. Finite siblings keep the existing record
codec. Outside these selected paths the general codec is unchanged.

Seven other top-level `ActAnswer` outputs (`connector.call`,
`vault.fanout.resume`, `vault.fanout.resume_as`, `vault.fanout.ack`,
`ai.voice.tool`, `vault.records.erase_confirm`, `vault.shared.execute`) match
native `QuestionsNarrowed` into the same generated `QuestionsNarrowed`
via the existing `NarrowedQuestions` lift. `ai.voice.tool` also uses that lift
for a nested `LiveVoiceToolCallReply::QuestionsNarrowed` inside `Done`, keeping
its finite `processed` fields.

`connector.call`'s `Done` reply, the whole connector reply nested inside
`ai.voice.tool`'s `Done`, and bare `connector.answer` results use a shared owned
`ConnectorCallReply` lift. Delivered content and non-null optional JSON leaves
move into `WireJson`; whole connector questions keep their required message
and schema, including a present null schema. Optional null JSON still reads
as absent. Delivered and awaiting-input empty optional vectors still read
as absent; held, refused and pending-delivery reasons remain required vectors.
The top-level and nested narrowed-question arms stay first and distinct.

`connector.call_status` uses that same owned reply lift for its settled and
awaiting-input replies. Pending metadata stays intact; empty pending reasons
and false `uncertain` still read as absent. The native `asked` count uses the
existing checked width conversion to the generated `u64` field.
`connector.schema` consumes a non-null optional input schema into `WireJson`;
null still reads as absent, `destructive: Some(false)` remains present, and
empty reasons still read as absent.

`vault.claims.review` and `vault.claims.vetting` use an owned claim-review
lift with the same generated `WireClaimView`, not the hand-written claim DTO.
Both the required value and optional scope move into `WireJson` before any
encoding error returns. A null scope still reads as absent. The finite claim
scope, provenance and record reference keep the existing record codec, as do
confidence and salience so their float widths and non-finite behavior stay
unchanged. All fields, including unsigned validity times, remain present in
their existing public types.

The bare JSON result of `self.skills.call` also moves directly into the
existing owned `WireJson` lift after the same typed client call. Its run/host
input, sandbox, hooks, return contract, carrier and generator census stay
unchanged. Other opaque output types keep the existing encoding fallback;
this change does not add record or container conversions.

`vault.kv.get`, `vault.kv.search` and `vault.kv.put` use owned keyed-memory
result lifts. Each item's required value moves into `WireJson`; a null value
stays present as JSON `null`. Namespace segments, keys, revisions, unsigned
second timestamps and put-receipt metadata retain their existing types and
values. Optional lookup absence and search order remain unchanged.

`self.skills.callables` uses an owned callable-card lift. Both required
`arguments` and `returns` JSON leaves are consumed before an encoding error
returns; null stays present. Skill identity, version, description, reference,
card order and the native catalog's read checks stay unchanged.

`ai.options` consumes every model-option JSON value before propagating an
encoding error. The same public `AiOptions` record retains required option
order, present empty lists and the optional media-unit count, including zero.
Its typed client call and native host-door checks remain unchanged.

`vault.conversations.create` and `vault.conversations.turns.create` use an
owned native write-receipt lift. Its required body moves into `WireJson`,
including a present JSON null; id, entity type and learned-at keep their
existing types. Native writers, announcement projection and client hooks
still complete before the conversion; request bodies are not substituted.

`vault.runs.checkpoint` uses an owned checkpoint-page lift. Every resumed
reply is consumed before a conversion error returns or finite step metadata
crosses the existing record codec. Optional reply null still reads as absent,
just like a missing reply. Run identity, completed steps, checkpoint order,
wait identity, effect, output handle and next-step cursor retain their existing
fields and widths. The native inline-size and taint checks remain unchanged.

`vault.diagnostics.list`, `vault.diagnostics.get` and `vault.coach.inspect`
use owned diagnostic and Coach-result lifts. All required diagnostic JSON
leaves, the proposal claim's JSON and its optional repair are consumed before
an encoding error returns. Required null values remain present; optional null
repairs still read as absent. List order, optional lookup absence, every
inspection field and each scoped-read receipt remain intact. Finite report,
working-set and receipt fields keep the existing record codec. Native scoped
reads, diagnostic filtering and fenced untrusted text are unchanged.

`vault.settings.wake_policy.set`, `vault.settings.inference_defaults` and
`vault.settings.inference_defaults.replace` consume the policy action's
required outcome directly into `WireJson`. Null stays present. JSON text held
inside outcome strings stays opaque text; it is not parsed or validated again.
The same native action, owner/ceiling checks and typed client calls still
complete before conversion.

`vault.lenses.result_set.action` consumes its required outcome into `WireJson`
before converting the finite scoped-read receipt. The same `readReceipt`
record, entity-kind spelling, float conversion and count widths remain intact.
Required null stays present, and JSON held inside strings remains opaque. The
same native selection, action dispatch, input and client call are unchanged.

The handwritten `lens_frame_event` binding consumes optional local refinement
and required tool outcome JSON before converting finite state or receipt
metadata. Optional refinement null still reads as absent; required tool null
stays present. Local state and tool read receipts keep the existing record
codec, including state tags, field renames and receipt widths. The finite
callback arm and the same native client call remain unchanged.

Every remaining variant and row, including `DetailsOnDevice`, keeps the
original whole-record `lift_record` fallback. Native getters, the shared
client and verb hooks are unchanged, and outside these selected conversions
the general generated-record codec is unchanged. No outer-Vec, depth, heap,
speed or runtime claim follows.

Input parsing, input canonicalization, hook masking, admission and receipts
are unchanged. No end-to-end depth, memory, speed or runtime claim follows from
this output conversion alone.


The `self.browser.batch` output also uses its complete owned answer conversion.
It consumes every `decisions` value and the optional session manifest's
`image_release` before the shared finite record conversion. Empty decisions
remain absent. A missing or null image release remains absent; null decision
array elements remain JSON null. The wrapper, manifest and all other batch
fields keep their existing serde shape. The browser records, client, hooks and
input conversion do not change.
