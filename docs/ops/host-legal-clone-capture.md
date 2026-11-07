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

## Integration and unchanged behavior

This native source does not remove an existing live-vault hold. Normal
customer-requested holds and their owner-confirmed lift remain unchanged. The
matching HOST store/client, key custody, audit, typed verifier and durable ACK
must be integrated before a deployed preservation claim is valid. Source code
alone is not a compiled or deployed floor.

## Live-session written-spill source

A live target uses the actual physical vault id, exact registry reference and
16-byte overlay shell minted once at entry. It is not a gate decision or an
entry timestamp. A new order registers under the same entry lock that publishes
closing. Registration installs an opaque native retention guard for active,
future and finished spill sources. The private order standing owns that
ORIGINAL guard through disconnect and failed attempts; reconnect never tries
to replace a source guard after its bytes or keys have gone. Ordinary writers
without an order keep their existing weak tracking and disk-spill behavior.

An admitted exact standing may reconnect to its retained closing source. The
per-vault registry keeps order/public-recipient metadata and the opaque native
source-lifetime guard, not HOST private keys or a separate raw-body store.
Explicit release ends only that order generation, interrupts its attempts and
waits for their collectors before acknowledging. Its native receipt is not
proof that HOST keys or clone content were destroyed. Expiry uses the admitted
order term, not a new timeout or default retention interval.

`Pending` means registered without a final source pin. Covered close seals and
drains ordinary overlay writes, then freezes the native per-instance IO gate.
Only short native IO is drained; neither a producer nor HOST network IO runs
under that gate. The final published snapshot, frozen file descriptors and
native keys stay with the borrowed getter through whole-source verification
and durable HOST ACK. Files renamed before a failed publication or an aborted
binding remain actual native candidates, not fabricated committed rows.

The encrypted metadata component is a closed `LiveSpillMetadata` value:
`Published` carries an actual raw key/file row; `NativeFile` carries the actual
filename, native-finish flag and physical size. The latter is not producer
path, kind or completion. Its shared key/family helpers distinguish the two
variants. Metadata tag 7 precedes its body tag 6; both use the exact metadata
encoding's hash as their revision. Body length and fingerprint come ONLY from
the measured native plaintext, never an output reference's placeholder fields.
No native key or file descriptor leaves the supplier.

`WrittenLiveSessionSpill` covers ALL final published bodies and frozen written
files of that exact closing instance. The encrypted summary's `live_bodies`
count equals the number of complete metadata/body pairs; a gate capture has
zero. The HOST must parse the whole metadata component before checking its
variant's key/family commitment and the following body's same source, key and
revision. It checks every body fingerprint/length and the final counts and
transcript before durable publication and ACK. A successful ACK retires only
that exact captured standing. Any other covered order still must capture or
reach release/expiry before normal close can wipe its source.

A zero-body completion is emitted ONLY after the combined final published
snapshot AND frozen native inventory prove no written source. Empty published
rows alone never establish that fact. A failed physical suffix is an honest
source error and retains the covered source; it is not a partial completion or
wipe permission. This extent is written result-body spill, not all session
content, producer completion, future writes, crash recovery or a historical
legal-clone replay guarantee.

Managed stop wakes queued capture waiters and shuts all registered stream
clones before the existing all-socket shutdown and all-worker join. A capture
already borrowing source must return before its worker can finish. Service
stop is not authority release, a complete clone or permission to wipe.
