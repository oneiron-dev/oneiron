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

The remaining browser-answer aliases also consume the optional manifest image
release through the owned conversion. Their finite payloads keep the shared
record codec, including all field names, flattened fields, optional values,
empty-vector omission, booleans, widths and native checks. The library proposal
answer also consumes decisions in its optional replay batch; the library-run
answer consumes decisions in its required batch. All decisions and manifest
JSON are consumed before a finite error can return. A missing replay stays
missing, while a present replay with no decisions stays present. Desktop-answer
outputs and unselected input conversions are unchanged.


`self.identity.settle` consumes a `NeedsPerson` card directly into `WireJson`.
Its required null card stays present. The same settled entity, unknown state,
deciding ask and person-choice ask remain intact, with the same public record,
input, native settlement and typed client call. JSON held inside card strings
stays opaque text. No identity or action-admission rule changes.


`feedback.preview` consumes its required bundle directly into `WireJson`, while
keeping every finite preview field and disclosure state in the shared record
codec. `self.off_record.results.read` also consumes a page's required JSON or a
result card's optional shape before the finite facet or card metadata. Required
page null stays present; a missing or null optional shape stays absent. The
same native readers, release checks, preview approval and typed client calls
remain unchanged.

`vault.shape.plan.card` consumes its required generated UI and every manifest
JSON value in the plan's seed, before/after items and undeclared rows before
any finite conversion can fail. The shared record codec retains all other
shape fields and custom serde behavior, including present empty body strings,
default booleans, decimal vault identifiers and reach metadata. Missing or null
optional manifest JSON stays absent. Hex-encoded manifest bodies remain opaque
strings. The native plan, input, authority and typed client call do not change.


The shared result-card shape also crosses by ownership in
`self.off_record.results.list` and `vault.results.read`. A list consumes every
card shape before returning a conversion error. The same finite card,
occurrence manifest, refusal, count and cursor fields retain their existing
record codec. Optional null shapes still read as absent.

All other shape-manifest output paths use the same owned leaf conversion:
`vault.shape.read`, `vault.shape.plan`, `vault.shape.apply`,
`vault.shape.items.receipt`, `vault.shape.groups`,
`vault.shape.groups.resolve`, `vault.inbox.groups` and
`vault.inbox.groups.resolve`. Stored and live seed rows, every apply item,
every group member, plan items and undeclared rows keep their original order
and cardinality. Every manifest JSON value is consumed before a finite error
can return, including across all groups in a page. An absent item receipt
stays absent. Unified Dreamer groups and resolutions keep the original finite
record codec, including omitted empty collections and checked count widths.
Native reads, applies, owner proof, release checks, public records, typed client
calls and input conversions remain unchanged. This completes these selected
output families only, not the general input, depth, heap or runtime work.


`self.inbox.list`, `self.inbox.mark` and `self.inbox.get` consume every
notification action argument into the existing required `WireJson` field.
A null argument remains present; action order, empty-action omission, seen and
acknowledged state, counts and page cursors retain the original record codec.
The opened inbox item also consumes every component property in its optional
lens, using a child-stack walk before either subtree can return an error.
Optional null properties remain absent. The original lens version pair is
captured before consuming its root; it is not restamped or validated again.
All other node and atom fields keep the original finite record codec, including
text framing, bindings, present empty children and scalar widths. Native
notification readers, action selection, meeting cards, owner/scope checks,
client calls and inputs are unchanged. The finite lens tree still has arbitrary
child depth; this does not claim end-to-end depth, heap or runtime closure.


`vault.weave.lens` and `vault.lenses.default` consume component properties
from both the flat render and the authored lens tree before converting finite
card metadata. The default-lens result keeps its exact narrowing receipt.
`vault.weave.digest` first consumes every claim value and optional scope across
all sections, then both representations of its optional lens card, before any
finite conversion can fail. Required claim null remains present; optional null
scope and component properties remain absent. All sections, finite item
variants, refusals and card metadata keep the shared record codec.

`vault.lenses.list` drains every optional compiled lens across the entire page
before converting finite row metadata. Missing compiled lenses stay missing;
row order, cursor and all proposal fields stay intact. These paths reuse the
opened-inbox tree walk and preserve the original lens version pair without
restamping or revalidating. Empty native children and binding vectors still
read as present empty vectors in the generated records. Native reads, owner
and scope checks, input conversion, clients and hooks remain unchanged. This
is selected output conversion only, not end-to-end depth, heap or runtime
closure.


`vault.weave.report` shares the saved digest's owned claim conversion. Every
required claim value and optional scope across all report sections and items
is consumed before a finite conversion can fail. The exact narrowing receipt,
section order, scores and all non-claim item variants retain the whole record
codec. Required null remains present; optional null scope remains absent.
Correction replies stay on their existing finite codec. Native reads, policy,
input conversion, typed client calls and hooks are unchanged.


`vault.inspection.resolve` and `vault.lenses.resolve` consume the optional
resolved entity body before converting finite inspection or selection metadata.
A missing item stays missing. Missing or null body JSON still reads as absent;
a present item with no body stays present. Provenance, state, handle, narrowing
receipt, selection reach and cursor bytes retain the existing record codec.
Native read checks, exact-frame resolution, inputs and typed client calls do
not change. Exported `pack_json` remains opaque text; this conversion never
parses or rewrites JSON carried inside a string.


`ai.image`, `ai.speech`, `ai.transcribe` and `ai.embed` consume the provider
usage JSON by ownership before converting finite answer fields. Provider
receipts and nested usage metadata stay intact; null provider JSON remains
absent. The same finite record codec keeps part order, base64 strings, optional
video fields, count defaults and embedding-number conversion. It also keeps
each verb's original finite conversion diagnostics. This does not change
native calls, inputs, public records, clients, hooks or media admission, and
does not claim depth, heap or runtime closure.

`ai.video.poll` reuses the owned answer conversion for its completed video
answer. Queued, running and failed jobs keep the original whole-record codec,
including progress omission and every native error variant's custom serde
fields. The existing job state, provider receipts, finite conversion errors,
client call and native admission remain unchanged.


`self.saved_query.create`, `self.saved_query.update`,
`self.saved_query.archive` and `self.saved_query.read` consume the definition's
filter and matcher JSON before converting finite record metadata. An explicit
stack walks every filter term, including nested conjunctions, disjunctions,
negations and claim values. Shallow native-node serde keeps the active JSON
map order and finite fields; required claim null stays present. Hard matchers
use the same walk, while a null judge rubric still reads as absent. The same
finite codec keeps all scope axes, versions, lifecycle, clocks and optional
read records without changing `found`.

`self.saved_query.evaluate` consumes every generation's provider JSON across
all outcomes before a conversion error can return. Provider null stays a
present required `WireJson` value, unlike optional media-usage JSON. Outcome
and generation order, optional judges and memos, counts, provider pins, costs,
cursors and all finite usage counters retain the original record codec.
`self.saved_query.members` has no opaque JSON or recursive output type and
keeps its existing conversion. Native query reads, filters, evaluators,
authority, public records, inputs, client calls and hooks are unchanged. These
are selected output conversions, not end-to-end depth, heap or runtime proof.


`ai.ask_image` consumes the provider JSON in its optional spend receipt before
converting finite image-answer and decision metadata. Missing usage stays
missing. Present usage keeps a required provider JSON value, including null;
it does not use the optional media-usage omission rule. Image answers,
confidence, presence, evidence, provider pins, finish reasons and all finite
receipt fields retain the original whole-record codec.

`vault.models.trials.nominate`, `get`, `approve`, `run`, `resend_arm` and
`complete` consume both usage-bound JSON values in the echoed trial request.
`vault.models.bindings.propose`, `get`, `accept` and `deny` do the same inside
their trial view. Both bound values are consumed before either conversion
error can return. These are owner-supplied cost bounds, not provider spend
receipts. Required null values stay present. The original whole-record codec
keeps all policy fields, backend pins, held-out and unknown-arm order,
optional evidence and receipts, costs, counts, binding routes and settlement
state. `vault.models.bindings.read` has no opaque usage JSON and is unchanged.
Native calls, admission, inputs, public records, clients and hooks are
unchanged. This is selected output conversion, not end-to-end depth, heap
or runtime closure.


`ai.streams.abort` and `ai.streams.terminal` consume every tool-call input,
tool-result output, required provider JSON and optional token-score JSON in
the terminal response before a conversion error can return. Required null
values remain present. Missing or null token scores still read as absent;
a missing response stays missing. The original whole-terminal record codec
keeps every finite content variant, content order, finish reason, failure,
empty-assertion omission, counter width and per-verb conversion diagnostic.
Native streams, public records, inputs, typed clients, hooks and authority
are unchanged. This is selected output conversion, not end-to-end depth,
heap or runtime proof.


`vault.runs.step` and `vault.runs.program_step` reuse the owned response
conversion for a readable settled model step. Missing outer rows and missing
nested model steps stay missing. Availability, issue variants, result refs,
base64 bodies, recorded run identity, clocks and all other finite fields keep
the original whole-record codec. This changes no native reads, admission,
public records, inputs, typed clients or hooks and makes no depth, heap or
runtime claim.


`vault.models.roles.invoke` uses the same owned response conversion for its
generated result. Embedded and tagged results retain the original finite
codec, including numeric widths and optional execution metadata.
`ai.steps.submit` and `ai.steps.receipt` also consume a finished step's
optional parsed JSON or a failed step's required provider JSON inside its
optional spent usage. Response leaves and parsed JSON are both consumed
before either error can return. Missing or null parsed JSON remains absent;
required provider null remains present. Retry, progression, failure and
validation fields, memoization, fallback and claim refs stay on the original
whole-receipt codec.

`ai.streams.events` consumes every tool-call-end input, tool-result-end output
and done-event message and usage leaf across the whole event list before
returning a conversion error. Delta fragments stay strings, event order and
all finite variants stay on the original whole-event-record codec, and done
events gain no token-score field. These conversions do not change native
execution, public records, inputs, typed clients, hooks or authority and are
not end-to-end depth, heap or runtime proof.
