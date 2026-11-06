# Phone-line arrival metadata

Metadata intake does not answer a call, accept audio, recognize a speaker, provision a
number, or connect a telephony provider. A separate receiving-agent HTTP session path
is described below. FIX 3894 / OF-605 remains partial; no running-call or provider proof
is claimed. Ordinary outbound `voice.call` and the existing owner/device voice loop are
unchanged.

## What the engine records

A self-held `voice` ChannelIdentity binds an agent and a separately registered channel
MACHINE actor. Registration uses the existing host-root credential door; a phone number,
actor-class label or caller field does not authenticate that machine.

An authenticated owner can store a reversible `enabled` setting and an explicit
six-axis `share_scope` for that exact identity. No row means off. Enabling does not mint a
read grant. The scope is consent data, recorded with an arrival for review; a future live
answering path still has to enforce the actual line ceiling on every read. This slice
performs no agent-context reads during metadata intake. Turning the setting off is not identity release or
retirement, and an owner can disable an existing setting even if its old bridge is gone.

The phone-specific transport accepts call-arrival metadata in a JSON body: a provider
call id and optional opaque caller label. Neither value appears in the request URL. The
authenticated request must carry the existing holder-bound verified slip, not a legacy shared secret, and the native scoped
reader must name the same live MACHINE as the line's actual and owner-pinned channel
actor. Configuration and admission resolve the current channel, address and receiver
from the identity's live claim heads, as the ordinary inbound router does; the body
supplies custody only. Reconfiguring after a supported claim correction pins the current
receiver, not the original seeded body binding. The native writer rechecks the enabled
setting, current assignment, live receiving agent, read policy and exact channel actor
before admitting the event. A caller
label is never a PERSON, owner, provider identity or voiceprint.

The metadata row and the existing SurfaceEvent attempt commit in one transaction. The
SurfaceEvent is a foreign, claims-not-instructions `voice` Message. Its correlation,
source/counterparty and payload reference contain only a domain-separated digest, not the
raw caller label or provider call id. The existing inbox lens projects that event; no
second review queue is created. The native metadata row passes the existing authored-row
secret wall. This replay-bound bare-store writer refuses secret-shaped hits rather than
minting new custody handles; the transaction then keeps neither metadata nor queue item.
Reads return the bytes actually kept. Retiring identities retain their existing inbound
delivery behavior; this path neither enables outbound calls nor answers calls.

The core acknowledgement contains only payload, correlation and attempt references,
plus whether the call replayed. It never echoes caller text. This route sits outside
the general HTTP reply cache: every retry reaches native admission and rechecks the
current enabled setting, identity and credential. A retry of the same line/call id with
the same original metadata returns the first receipt. Changed metadata cannot overwrite
it. Explicit metadata erase replaces the row with a content-free marker; a retry cannot put the caller label back. The existing queue
keeps only its opaque receipt/reference and the receiving identity, so a metadata lookup
then reports not found. Line deletion and the agent/channel-actor scrub remove the
associated private rows in the same writer. No raw audio or host quarantine file exists
in this slice.

Phone-line settings are LIVE restore state, like other current identity-authority
settings. A checkpoint's stored setting is not a newly authenticated owner act. Arrival
metadata is CONTENT, never a grant or a credential. There is no migration or old reader.

## Native call-bound reads

`Vault::phone_line_answer_read_key` consumes the receiving agent's actual verified
credential and the opaque arrival reference. It issues no credential or grant and
returns no private caller metadata. The returned key keeps the credential's existing
bounds and is off-device, because its answer is for an external caller. Its frozen
ceiling meets both the arrival's recorded scope and the line's current scope.

Each entity-row admission rechecks the current line, agent, bridge, owner and live
arrival in the same snapshot, then checks the current scope and native facet placement.
This also applies to point reads, derived sources and the session view. Erase, disable
or a binding mismatch admits no row through the call key. Ordinary keys with no phone
ceiling keep their existing behavior. `ScopedRead::phone_line_scope` reports the live
consent ceiling for prepared-context invalidation. `phone_line_output_scope` checks that
ceiling, every supplied source row and the native disclosure rules in one snapshot.
That includes Tier-A marks, withdrawal and the existing turn-message and summary-source
closure; these disclosure checks may read source bodies. The actual anonymous
interlocutor set travels with the prepared generation. A caller must compare the result
with the scope captured before assembling context; re-stamping an old response with the
new scope does not make that response safe.

The server has an optional call-bound reader and a weak PCM dequeue fence. Ordinary
voice sessions set that reader to `None` and keep their owner-only behavior. The separate
phone HTTP start constructs it from the receiving agent's actual credential and arrival.
The phone-bound brain
captures consent before context assembly and registers that generation's sources before
model admission. A changed scope replaces its history Arc, so an old asynchronous turn
cannot append into the new scope's history. Old-generation notices and queued PCM are
checked against the original prepared scope, not re-stamped with current consent.

The speculative Memory carrier retains the original phone key and verified credential.
Each reconstructed identity key must still carry that same proof, then conjoins every
frozen call ceiling, the original definition's native world bound and the off-device
bound. Changing the Memory proof or adding a host
action cannot replace the captured phone credential. Clones and the room/thread
rebinders retain it. Agent-class verification and the normal recall world defaults
still use the existing Memory path; no actor label or new all-world default replaces it.

The phone-only memories path keeps the caller anonymous and uses the native phone
reader's live line consent for disclosure, not a fabricated contact clearance or owner
presence. It accepts only an anonymous first-claim audience, with no contact, room entry,
voiceprint evidence or owner claim. B's credential and line ceiling still apply to every
read, and the existing non-owner Tier-A and live-source rules still apply. Generic
Unknown and room disclosure behavior is unchanged. The assembly and narrowing receipts
still describe the actual anonymous audience.

Before a phone-bound safeguard notice enters history or the control stream, its
original prepared generation, consent scope and anonymous audience are checked with
both the turn's sources and the additional row named by the notice. Ordinary sessions
still deliver their notices as before. This is the immediate notice-body send check,
not a claim that every control event or saved journal page is phone-bound.

The private phone-mode journal page now rechecks saved PCM, safeguard, notice and
memories bodies before copying them into a reply. It uses the original journal epoch,
that epoch's prepared scope, sources and audience, plus the actual event's source rows.
The native phone reader checks their union against current line consent and disclosure
in one snapshot. A missing original preparation admits no such body. Skipping a body
still advances the existing cursor; ACK boundaries and source-free control events stay
unchanged. Ordinary pages keep the original implementation through the `None` path.
Tool source labels are not treated as source-free control: this anonymous mode admits
no tool context through the existing owner-only tool door, and a saved label without
its source admission is not released. These saved-page checks do not activate a phone
session or prove the remaining live ASR, text-send and controller credential paths.

`ScopedRead::phone_line_agent_read` admits the actual receiving agent's live AGENT_DEF
body and returns a reader conjoined with that definition's native world scope. The
current credential, line consent, row scope and facets share one read transaction.
`All` keeps the key's existing bounds; `Base` restricts it to base reality; `World(w)`
keeps that world plus base reality, meeting any world bound already held. The same
admitted body supplies instructions and models after the native lifecycle, approval
and enabled checks. There is no default-agent or empty-list substitute. This getter
does not activate an answering session.

The call freezes instructions and the native model list from one admitted definition
body. The phone-bound chat brain and host-call backend attach B as the actual caller on
their existing funded runs, and filter the native ladder through that same frozen list.
Credential authority, source provenance and payer identity remain separate. Ordinary
sessions keep their original callers, routes, policy admission and funding.

The phone text run carries one owned check bound to the actual prepared generation,
not a later generation label or scope. Run clones and fresh fallback permits retain
that same check. After the native text gate proves and starts its actual permit, it
conjoins the check onto the same lease before handing it to the provider. These
runtime-only checks do not change lease identity, signatures, accounting or request
hashes. They cannot replace an earlier condition, and their cell is unlocked before
a check reads current credential, line and source state. This is a transport carrier,
not yet a claim that every text provider, queued send or retry invokes it; those
physical consumers must be connected before phone activation.

The phone preparation factory consumes this original call-bound reader and
requires the same authenticated instrument and projected agent on the same vault before
allocating its configured call budget. It constructs one anonymous first-claim party
labeled only by the new opaque call ref: no owner session, PERSON, roster, room or
voiceprint. Instructions and model restrictions come from the same admitted definition;
its native world scope stays on both direct and speculative readers. The budget actor
and model caller are the actual agent; caller attribution does not change the run's
payer. Existing configured budget, reserve, suspension and render settings are reused.
No-room funding retains the native `None` payer; it is not a new agent billing account. Media uses the phone-specific door,
not the ordinary owner/device door. The phone HTTP start connects this constructor to
the shared public-session lifecycle; a running call has not been proved. Native
action/model-ceiling qualification remains partial; caller attribution is not credential
authority.

The shared public-session implementation has a private optional phone mode. It reuses
the same session hold, command queue, media worker, journal, stop and task ownership.
A phone lookup first matches the original authority, then checks current line consent.
Its credential/line watcher uses the existing liveness interval; changing the scope's
value alone does not end the call. Ordinary start still supplies `None` and keeps its
original owner/device checks. The separate receiving-agent HTTP doors select only
phone sessions under their original credential; they do not loosen the owner doors.
This source path is not runtime proof of an answered call.

Live Soniox segments reuse that same media door for continuing-stream admission.
Before socket readiness, frame send, flush, and read-driven flushing, the phone mode
rechecks its original receiving-agent credential and current line on the same vault.
This applies to queued audio, opening configuration, cuts, keepalives and replayed
frames. Refusal ends the hearing through its existing error path; it is not a socket
drop that reconnects. Ordinary doors admit these checks without changing their stream,
lease, queue or reconnect behavior. No speech generation is invented for incoming
caller audio. Buffered transcription and complete text-request release remain separate;
these live-send checks still do not activate an answering route or prove a running call.

The call-local media entry points attach the actual receiving agent to the same
admitted run and filter its ladder through the frozen native model list, including
owner-selected fallback rungs. Voice routing filters eligible backend bindings before
selecting the route, rather than stopping at an unlisted primary when a listed route
can serve it. Existing media callers pass no agent context and keep their prior routing
and billing. The optional phone media door rechecks the original credential and
current line before native inference admission. Its worker binds release to the exact
queued speech generation, not the latest generation. OpenAI-compatible direct and
brokered speech, Cartesia, ElevenLabs and VoxCPM2 render uploads forward that callback
to physical sends and retries. VoxCPM2 also retains its current-reference upload check;
its readiness probe is not counted as an inference attempt. Old media callers keep
`None` release and their existing paths.

A credential, model list or generation label does not supply a whole source set. These
media calls still assert no whole set unless their actual producer supplies it. The
prepared phone output check uses its original captured consent, sources and audience;
complete instruction, history, tool and saved-control accounting, live ASR withdrawal
and the actual answering lifecycle remain open. These ports are not phone activation or
provider/runtime proof.

A phone-bound host refuses speaker matching and roster departures before accessing
any roster. Ordinary voice hosts keep their existing matching and departure behavior.
This guard does not create an anonymous session or activate an enrollment path; the
prepared factory's public call lifecycle and no-enrollment execution remain open.

Complete tool/control and saved-notice replay source accounting, explicit no-recognition
execution and the actual answering lifecycle remain open. These native read and output-check ports are not a
claim that a phone call can be answered.

Native sessions with a live dispatch check also carry the committed reply's original
checkpoint authority into next-turn preparation, even when no parkable snapshot basis
was made. Before each physical preparation-frame write, the coordinator renders the
same tail producer again, then rechecks that original authority off the runtime. It
sends only if the new wire rows equal the captured tail. The live call check runs
before and after this work and keeps its original typed error.

A canonical authority rejection uses the existing session-drop path. A changed or
unavailable speculative tail stops only that preparation; it is not a claim that the
canonical base remains valid. Stopped preparation keeps computed work unknown. The
next-state board filters unreadable loaded-skill handles only in its cloned read set;
served rows, the live baseline and acknowledgments are not changed. Ordinary sessions
without a live dispatch check retain their original send path. These checks do not
qualify all historical or derived sources, erase a worker's already received descriptor,
or activate the phone call lifecycle.

The same live native sessions now check their original canonical authority before every
physical write of the suffix-commit and checkpoint-publication control frames. These
plain frames carry no input descriptor. Their separate checked writer leaves the existing
FD writers unchanged and does not count a model attempt. The original call check runs
before and after each off-runtime authority read, so a live release keeps its original
error even when authority changed during that read. A canonical rejection uses the
existing session-drop path. A partly sent control frame or staged worker state remains
unknown; this source path is not a worker-disposal or runtime certificate. Sessions with
no live dispatch callback still use the original plain control send.

## HTTP doors

- `GET /v1/owner/phone-lines/{identity_ref}` reads the owner's stored setting.
- `POST /v1/owner/phone-lines/{identity_ref}` stores the native JSON config:
  `enabled` and the explicit federation `share_scope`.
- `POST /v1/core/phone-lines/{identity_ref}/arrivals` accepts a JSON object with
  `call_id` and optional `caller` (string or null). Unknown fields are invalid.
  It requires a holder-bound verified slip with core read/write, bound to the actual
  configured channel MACHINE; it returns 202 with opaque refs and `replayed`.
- `GET /v1/owner/phone-lines/{identity_ref}/arrivals/{arrival_ref}` reads the private
  metadata. Use the exact opaque `payload_ref` returned by admission or kept in the
  inbox. No raw call id is put in the path. Unknown or erased references return 404.
- `DELETE /v1/owner/phone-lines/{identity_ref}/arrivals/{arrival_ref}` erases that
  metadata and keeps a retry marker. An absent arrival returns 404.

All successful responses carry `Cache-Control: no-store`. Owner doors use the vault's current
owner proof and revalidate it in the native read or writer. Request JSON uses the existing
deferred body reader after authentication; larger bodies use its existing spool path.
The metadata doors add no SDK verb, shared secret, number/provider provisioning or
audio endpoint. The separate phone-session transport below adds no credential or grant.

## Authenticated phone-session HTTP transport

`POST /v1/core/phone-lines/{identity_ref}/arrivals/{arrival_ref}/voice` takes the existing
`LiveVoiceStartRequest`: `sample_rate`, `channels`, and the existing optional room/roster
fields. The current anonymous phone factory does not admit a room or roster. The arrival
reference is the opaque `payload_ref` from metadata intake, not a provider call id or
caller label. The request must present the receiving agent's own holder-bound verified
slip with core read/write. It is not the channel MACHINE's credential.

The existing native answer-key constructor checks that credential against the actual live
line and arrival, proves its principal is the receiving agent, and freezes that agent's
admitted definition, models and world bounds. No body field, bridge credential, owner
fallback, actor label or supplied scope replaces these checks. The response is the same
opaque `LiveVoiceSession` and audio format as the ordinary voice transport.

The same credential then uses these POST routes with the existing typed voice requests:

| Path under `/v1/core` | Request | Reply |
| --- | --- | --- |
| `/phone-voice/audio` | `LiveVoiceAudioRequest` | `LiveVoiceProcessed` |
| `/phone-voice/events` | `LiveVoiceEventsRequest` | `LiveVoiceEvents` |
| `/phone-voice/ack` | `LiveVoiceAckRequest` | `LiveVoiceProcessed` |
| `/phone-voice/usage` | `LiveVoiceUsageRequest` | `LiveVoiceUsage` |
| `/phone-voice/tool` | `LiveVoiceToolRequest` | `ActAnswer<LiveVoiceToolReply>` |
| `/phone-voice/end` | `LiveVoiceSessionRequest` | `LiveVoiceProcessed` |
| `/phone-voice/close` | `LiveVoiceSessionRequest` | `LiveVoiceProcessed` |

Each request reuses the session store's exact authority binding, live phone consent check
and existing write-hold admission. These routes select only phone sessions, not ordinary
owner sessions. Events use the existing phone journal page and its saved-body checks.
End preserves the final events; close performs the existing end, shutdown and map removal.
All successful replies carry `Cache-Control: no-store`. The routes sit outside the generic
HTTP reply cache, so a cached response cannot substitute for current credential or line
checks. Deferred request-body reading and the shared voice queue remain unchanged.

The existing owner `ai.voice.*` preflights and doors remain owner-only. Ordinary start
still passes `None`, including its working room/roster behavior. The separate phone tool
route requires an idle phone session and uses its native receiving agent as the connector
caller. It conjoins the original phone key onto the same credential memory that carries
the read collector, invocation, locality and host origin. It neither substitutes an owner
nor creates a connector grant. The connector's existing grant checks and destination
narrowing remain unchanged. Delivered results and their actual listed rows enter the
shared voice brain before its next utterance; unknown picked rows remain unknown.
Phone event pages still withhold tool-context labels and check prepared output sources.
This is not proof of complete historical, derived or connector source accounting.

The eight phone-session operations are registered in the HTTP OpenAPI document with
JSON payloads; the concrete native voice DTOs still parse and serialize them. Typed SDK
publication, external telephony integration and runtime answering proof remain partial.
No number is provisioned, no audio or transcript is persisted by metadata intake, and
these source changes do not prove the complete anonymous-call lifecycle.

## Typed receiving-agent phone verbs

The host SDK also publishes `ai.phone.voice.start`, `audio`, `events`, `ack`, `usage`,
`tool`, `end` and `close`. These are separate from the owner-only `ai.voice.*` verbs.
Every phone verb keeps the raw transport's holder-bound receiving-agent credential and
core read/write requirement. Session operations select the same phone-only session store.
The actual phone key and record bounds stay on reads; these verbs do not substitute an
unrestricted owner handle.

`ai.phone.voice.start` takes `PhoneVoiceStartRequest` with `identity_ref`, the opaque
`arrival_ref`, and a nested `voice` containing the existing `LiveVoiceStartRequest`.
The nested request carries the configured sample rate and channel count; the owner DTO
is unchanged.
The remaining verbs use the same request and reply types as the raw phone routes above.
The tool verb carries its facade invocation onto the original connector memory, while
its actual connector actor still comes from the proved phone session. Its reply uses the
same destination narrowing as the owner tool path. The native phone event page still
withholds tool-context labels. Generated SDK publication is source, not a running phone
call or proof of complete historical and derived source accounting.

## Completion boundaries

The settings/metadata/admission and HTTP doors are not a claim that a provider can ring
a number. The actual number and telephony bridge remain external work. Live anonymous audio, the no-recognition execution path, enforcement of
the line's share ceiling during answering, and the final toggle/inbox UI remain open.
No recording, transcript, delivery, answered-call, current-health or runtime proof is
claimed from an arrival receipt.

Identity deletion calls phone cleanup in the same native writer. Arrival receipts are
not runtime or provider-delivery proof. The engine exposes the intake and review doors;
a host must supply and operate its actual authenticated telephony bridge separately.
