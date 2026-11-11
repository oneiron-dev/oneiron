# Phone-line arrival metadata

This slice does not answer a call, accept audio, recognize a speaker, provision a number,
or connect a telephony provider. FIX 3894 / OF-605 remains partial. Ordinary outbound
`voice.call` and the existing owner/device voice loop are unchanged.

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

The server has an optional call-bound reader and a weak PCM dequeue fence. Existing
voice sessions set that reader to `None` and keep their owner-only behavior. No phone
session factory or audio route activates the new reader yet. The phone-bound brain
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

The uncalled phone preparation factory consumes this original call-bound reader and
requires the same authenticated instrument and projected agent on the same vault before
allocating its configured call budget. It constructs one anonymous first-claim party
labeled only by the new opaque call ref: no owner session, PERSON, roster, room or
voiceprint. Instructions and model restrictions come from the same admitted definition;
its native world scope stays on both direct and speculative readers. The budget actor
and model caller are the actual agent; caller attribution does not change the run's
payer. Existing configured budget, reserve, suspension and render settings are reused.
No-room funding retains the native `None` payer; it is not a new agent billing account. Media uses the phone-specific door,
not the ordinary owner/device door. This constructor is not connected to a public
start door or a running call. Native action/model-ceiling qualification and the actual
answering lifecycle remain open; caller attribution is not credential authority.

The shared public-session implementation has a private optional phone mode. It reuses
the same session hold, command queue, media worker, journal, stop and task ownership.
A phone lookup first matches the original authority, then checks current line consent.
Its credential/line watcher uses the existing liveness interval; changing the scope's
value alone does not end the call. Ordinary start still supplies `None` and keeps its
original owner/device checks. There is no public phone start or HTTP audio door; this
private mode cannot yet start a phone call through an existing production caller.

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
No new SDK verb, shared secret, number/provider provisioning or audio route is added.

## Completion boundaries

The settings/metadata/admission and HTTP doors are not a claim that a provider can ring
a number. The actual number and telephony bridge remain external work. Live anonymous audio, the no-recognition execution path, enforcement of
the line's share ceiling during answering, and the final toggle/inbox UI remain open.
No recording, transcript, delivery, answered-call, current-health or runtime proof is
claimed from an arrival receipt.

Identity deletion calls phone cleanup in the same native writer. Arrival receipts are
not runtime or provider-delivery proof. The engine exposes the intake and review doors;
a host must supply and operate its actual authenticated telephony bridge separately.
