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
performs no agent-context reads. Turning the setting off is not identity release or
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
