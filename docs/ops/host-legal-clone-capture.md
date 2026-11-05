# Host-private legal-clone capture

This capture path is separate from tenant control, owner/member APIs and the
ordinary vault. It is source for the same native/host feature pack, not proof
that any host has deployed a legal-clone store.

## Admission and source lifetime

The manager creates a private Unix listener before dropping the engine to its
tenant identity. The engine consumes that inherited listener once. Native
adoption checks the actual listener descriptor owner, Unix socket type and
listening state. It also requires the pinned host identity to differ from the
engine's tenant identity. Each accepted connection checks the kernel peer
identity against that same pinned host identity. Request fields and the source
hello are not legal-order authority.

The host admits the real order and records its access audit before requesting a
capture. The source hello reports the actual physical vault id on the same
manager-owned process channel. The host binds that id to its running actor and
includes it in the request. Native capture compares it with its own vault id.
The request supplies only the order's hybrid public key; private seed and host
keystore handles never enter the tenant engine.

The first source family is the claim-free gate-decision ledger. It preserves
the exact stored row, original opened policy MessagePack when present, and the
three owned retention-context, bundle-reference and pending-scrub sidecars.
It does not follow contextual entity references or copy derived indexes. A
claim-bearing row is outside this family. Unknown or malformed stored
formats remain errors, not silent gaps or permission to copy another family.

The collector takes the native custody guard before its source writer snapshot.
It keeps both until the same host acknowledges the exact request and ciphertext
transcript after durable publication. The source transaction writes nothing and
aborts after the acknowledgement. Stop and the actual order term are checked
throughout capture. Managed shutdown must close every accepted socket, then
join its blocking worker before closing the vault.

## Encrypted stream and host obligations

The new host-private source hello and capture protocol are version 1. They do
not change ordinary ctl or its contract version. Each component has an
encrypted descriptor and one or more encrypted content chunks. The final
summary is encrypted to the same independently destroyable per-order key.
Only frame kind, lengths and member/part ordinals are clear. Source identities,
whole-component fingerprints and the descriptor commitment remain encrypted.
The existing 16 MiB envelope geometry remains a chunk size, not a record or
capture cap. See [the cipher contract](host-legal-clone-crypto.md).

The host must verify the component's native identity, exact length, complete
chunk sequence and whole-component fingerprint. It must verify the encrypted
summary counts and descriptor commitment against that same stream. It must
persist and sync the complete capture and its publication directory before
sending the request/transcript-bound acknowledgement. A partial stream, file
name or metadata-only hold is not a complete content clone.

The host owns independent order-seed creation, mediated legal-only reads,
per-access audit, stop/release/expiry and durable key/content destruction. A
failed delete remains a fault, not `Destroyed`; unlink is not forensic wipe.
No ordinary restore, backup, search, Dreamer or training path reads the clone.

## Explicit source scope

The request must choose the whole claim-free gate-decision family explicitly,
or name a strictly increasing list of exact 16-byte decision keys. A singleton
uses the same list shape. An empty list captures no decisions; it never means
all. There is no omitted scope or new source-record/capture-size cap.

The new version-1 framing includes that scope before the recipient key and in
the exact request digest. This format has not shipped; there is no old reader
or compatibility branch. Selection is applied before policy decryption or
component emission. A selected missing or claim-bearing decision prevents the
completion summary and acknowledgement. The emitted decision count must equal
the selected unique key count in the same source snapshot. The host must check
that count and each descriptor's decision membership before publication. It
must not infer complete preservation from a partial stream.

The host derives the selection from its durably admitted order. The explicit
whole-family option is suitable only when that order covers this entire native
family. The selector is source scope, not legal-order or reader authority.

## Scope still being integrated

This native bank alone does not replace any existing live-vault hold. The real
host store/client and managed startup consumers must land with it. Normal
customer-requested holds and their owner-confirmed lift remain unchanged.
Off-record encrypted spill remains governed by its own exact-session order
scope; this gate-ledger collector does not cover that source family.
