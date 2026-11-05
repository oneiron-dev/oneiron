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

The first source family is the gate-decision ledger. Whole-family mode is
claim-free only. Exact decision-key selection can also open claim-bound rows
under their actual native custody generations. Capture preserves the exact
stored row, original opened policy or claim MessagePack when present, and the
three owned retention-context, bundle-reference and pending-scrub sidecars.
It does not follow contextual entity references or copy derived indexes.
Unknown or malformed stored formats remain errors, not silent gaps or
permission to copy another family. Ordinary claim keys stay in native custody;
only the opened source bytes are re-encrypted to the independent host key.

The collector takes the native custody guard before its source writer snapshot.
Only after it holds that writer and rechecks stop and the actual order term does
it send `Accepted`. This pins that source snapshot; it is not a complete clone
or independent legal-order authority. The collector keeps both guards until
the same host acknowledges the exact request and ciphertext transcript after
durable publication. The source transaction writes nothing and
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
component emission. A selected missing or unreadable decision prevents the
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
scope. The additional live-session source bank below is a published-body slice,
not whole written-session preservation or a usable deployed floor.

## Live-session source bank

A live target uses the actual physical vault id, the exact registry reference
and the 16-byte overlay shell minted once at entry. It is not a gate decision
or an entry timestamp. A new order registers under the same entry lock that
publishes closing. An admitted exact standing may reconnect to its retained
closing source. The per-vault private registry keeps public recipient and order
metadata, not source bytes or private keys. A disconnected attempt is not an
order release. Explicit release ends only that order generation; its native
receipt does not claim that HOST keys or clone content were destroyed.

`Pending` means registered without a source pin. `Accepted` is emitted only
when the close-side supplier lends its sealed, drained overlay snapshot and
existing spill directory. The borrowed getter uses actual native file rows and
body-key decoding. Only digest and length from an output reference are body
facts; its placeholder path, kind and completion fields are not occurrence
metadata. No body key or wrap leaves the supplier.

The stream binds a typed source family and the exact whole request digest in
all content, descriptor and summary AEAD roles. The encrypted completion
manifest states its actual extent. `PublishedLiveSessionBodies` is not a claim
that an in-progress written temporary file was captured. This bank therefore
keeps the exact covered close pending after a published-only extent ACK. An
empty published-row set is not proof that no written spill exists. Full
writer-aware temporary-spill coverage and definitive no-written-source proof
remain integration work; this bank must not be activated as whole-session
preservation or used to wipe an unqualified extent.

Managed stop wakes queued capture waiters and shuts all registered stream
clones before the existing all-socket shutdown and all-worker join. A capture
already borrowing source must return before its worker can finish. Service
stop is not authority release, a complete clone or permission to wipe.
