# Phone-line arrival metadata (source slice)

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

The proposed phone-specific transport accepts only call-arrival metadata: a provider
call id and optional opaque caller label. The authenticated request must carry the
existing holder-bound verified slip, not a legacy shared secret, and the native scoped
reader must name the same live MACHINE as the line's actual and owner-pinned channel
actor. The native writer rechecks the enabled setting, identity assignment, live receiving
agent, current read policy and exact channel actor before admitting the event. A caller
label is never a PERSON, owner, provider identity or voiceprint.

The metadata row and the existing SurfaceEvent attempt commit in one transaction. The
SurfaceEvent is a foreign, claims-not-instructions `voice` Message. Its correlation,
source/counterparty and payload reference contain only a domain-separated digest, not the
raw caller label or provider call id. The existing inbox lens projects that event; no
second review queue is created. The native metadata row passes the side-row masking wall,
and reads return the bytes actually kept by that wall.

A retry of the same line/call id with the same original metadata returns the first
receipt. Changed metadata cannot overwrite it. Explicit metadata erase replaces the row
with a content-free marker; a retry cannot put the caller label back. The existing queue
keeps only its opaque receipt/reference and the receiving identity, so a metadata lookup
then reports not found. Line deletion and the agent/channel-actor scrub remove the
associated private rows in the same writer. No raw audio or host quarantine file exists
in this slice.

Phone-line settings are LIVE restore state, like other current identity-authority
settings. A checkpoint's stored setting is not a newly authenticated owner act. Arrival
metadata is CONTENT, never a grant or a credential. There is no migration or old reader.

## Completion boundaries

The native settings/metadata/admission source and a candidate HTTP adapter are not a
claim that a provider can ring a number. The actual number and telephony bridge remain
external work. Live anonymous audio, the no-recognition execution path, enforcement of
the line's share ceiling during answering, and the final toggle/inbox UI remain open.
No recording, transcript, delivery, answered-call, current-health or runtime proof is
claimed from an arrival receipt.

Before a READY, the phone-specific owner/core transport and reference reader must be
registered, identity-delete cleanup must be integrated with its owning lane, native
source/restore/erase contracts must be verified, and a passing compiled Engine train is
required. No tests are part of this work. No deployment or provider configuration was
performed.
