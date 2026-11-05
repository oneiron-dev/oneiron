# Host-private legal-clone cipher supplier

The native collector receives only the real host order's hybrid public key.
The host keeps its independent 32-byte order seed in its own device-only
keystore, outside ordinary vault, body, checkpoint, backup and restore paths.
`SlotKind::LegalCloneOrder(order_id)` names the order without misusing the real
host install id. `legal_clone::KEY_LABEL` is the pinned label for
`HybridSecretKey::from_seed`; it is not a new key-generation algorithm.

## Cipher contract

`oneiron_crypto::legal_clone` supplies `CaptureBinding`, `ContentBinding`,
`ContentSource`, the closed seven `SourceComponent` tags, and separate
`seal_`/`open_` functions for content, descriptors and the final summary. Every envelope uses the same host
order public/private key pair, `Purpose::LegalClone` (30), XChaCha20-Poly1305,
X25519 + ML-KEM-1024, the existing epoch 1 and only `HybridCapsule` wraps.
There is no device, client, recovery or offline legal-recipient wrap.

A capture binds its order, actual physical source-vault id, generation,
immutable capture id and the whole actual accepted `CaptureRequest::digest()`.
This required request digest is part of the shared capture scope for all three
AEAD roles and their header-scope/key-id hashes. A clear accepted response or
ACK alone is not this cryptographic binding.

Content also binds the member ordinal, source component, typed source identity,
native source-key digest, raw stored revision, whole-component plaintext
fingerprint and chunk index/count. The source owner computes the source-key
digest from its native family label and length-framed actual raw key.
`ContentSource::GateDecision` uses family byte 1 and its decision id;
`ContentSource::LiveSession` uses family byte 2, the exact registry session-ref
digest and its once-minted instance id. `live_session_ref_digest` uses BLAKE3
with derive-key context `oneiron/host-legal-clone/live-session-ref/v1`, followed
by the UTF-8 byte length as u64 big-endian and those exact bytes. It does not
trim, case-fold or normalize the reference. The encrypted descriptor keeps the
actual reference and instance; their digest is not capture authority.

The gate-ledger family and its named sidecars keep component tags 1 through 5:
whole-family capture is claim-free, while explicit native decision-key selection
can also open claim-bound rows under their actual native custody. Neither path
exports or retains an ordinary claim key. Live-session body and metadata use
tags 6 and 7. The metadata member encrypts the actual raw file row separately
from the body; descriptor metadata alone is not that member. Published live
bodies are only the consumer's stated capture extent, not proof that an active
writer or a partial file has no written bytes.

This is one unpublished format. All gate, live-session and host-reader binding
constructors must change in the same consumer feature pack. There is no default
request digest or old decision-only binding reader.

The full canonical binding is extra associated data, not serialized plaintext.
The envelope header contains only binding/scope digests and fixed role labels,
not the raw source identities or fingerprints. Descriptors and the final
summary are themselves encrypted. A host opens a descriptor with the known
capture and member ordinal, then takes the exact content binding from it.
Counts and the streamed descriptor commitment remain inside the encrypted
summary. The consumer checks them and every whole-component digest/length
before reporting a complete capture. A chunk's AEAD authenticates its declared
whole-component fingerprint; it cannot alone verify the whole component.

The existing 16 MiB envelope plaintext geometry is unchanged. It is a chunk
geometry, not a new source-record or capture-size cap. `Envelope::write_to`
streams the canonical ciphertext without joining another whole envelope Vec.

## What this supplier does not prove

The cipher and slot names do not create capture authority, authenticate an IPC
peer, persist a clone, audit a legal read or prove key deletion. The actual host
consumer owns those steps and all secret lifetimes. The native collector never
receives the private seed or a host keystore handle. No order secret is retained
between mediated host operations or copied into ordinary recovery storage.

A keystore delete error must remain a destroy fault, never a successful
`Destroyed` record. The Unix file backend syncs directory removal, but removal
is not a forensic byte-wipe. Windows deletion has no directory-sync guarantee;
other platform backends inherit their own storage guarantees. The actual host
provider and its complete excluded ordinary-storage paths must be qualified by
the consuming host implementation; backend/API presence alone proves none of
these conditions.

This is source for the same L03/LC consumer feature pack, not a standalone
custody implementation or a claim that any host has been deployed. No tests are
added or run under the current decree.
