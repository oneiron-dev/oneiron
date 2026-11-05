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

## On-record message source

The order can name exact stored MESSAGE entities (`CaptureScope::Messages`,
strictly increasing 16-byte ids). Each id must be a stored MESSAGE row; a
missing id, or an id whose row is not a MESSAGE, fails the capture before its
summary, so no acknowledgement can claim it. For each message, in id order, the
stream carries its exact entity row (component 8), then its document head and
every stored row and update of that document slot (component 9), then every
stored outgoing edge row (component 10), all copied as stored. When the
message's result attachment names a body that the message still holds (its own
body occurrence, that exact digest and length, from the producer run,
occurrence and path the attachment names), that body's exact bytes follow as
component 11 (family `code_run:raw_output`, key the stored raw-output key of
its handle, fingerprint its BLAKE3), checked against its length and digest as
it streams. Every component of one message carries the BLAKE3 of its entity row
as its revision. The summary's `messages` count is the selected id count;
`absent_result_bodies` names each selected message whose attachment names a
body it no longer holds, or that no row holds any longer: its rows are
captured, the body is not and is never claimed. `decisions`, `live_sessions`
and `live_bodies` are zero. A world withhold on the producer's served rows is
a read-surface rule and does not apply to the clone, which is sealed to the
order's recipient.

The collector pins every result body, then takes the custody read guard before
its source writer, as a gate capture does, and holds all three until the exact
HOST acknowledgement; the source transaction writes nothing and aborts. Assets
and model-call records are not part of this extent, and messages stored after
the request are never included: only an explicit prospective scope may add
them.

## Prospective message capture

Only an explicit `CaptureScope::ProspectiveMessages` request captures messages
stored after it; every other scope copies what exists at its source snapshot.
The first selector is `MessageSelector::Vault`: every new base on-record
MESSAGE row of the vault. Off-record overlay writes never reach it.

The request's connection stands the order durably under `legal_hold:host:`
(its capture binding, term, public recipient key and next ordinal), so it is
carried with the host-order family and host-sealed in checkpoints, never in an
owner image or export. A released generation is recorded and never stands
again. While the order stands and before its `ends_at`, the shared base put
seam seals each new MESSAGE row, exactly as staged, to the order's public key
inside the same writer, and keeps the ciphertext in the order's outbox. The
message and its sealed copy commit or roll back together. At the end of that
same base batch, still in its writer, each outgoing edge row the batch wrote for
the message (its turn, conversation, author, parent and reply links) is sealed
the same way as its own entry (component 10), under the revision the row
carried. The engine cannot open the outbox. A seal that fails keeps the user's
write and records the message as missed; it is never reported as captured.

The connection drains the outbox in batches of at most
`PROSPECTIVE_BATCH_ENTRIES` entries. Each batch is its own stream: Accepted,
the stored Descriptor and Content frames, then a summary with extent
`prospective_messages`, the batch's first ordinal and entry count, the sealed
message row count and the missed message ids, then Ready and the exact
acknowledgement. Its `descriptors_hash` is BLAKE3 over each component's
descriptor digest in stream order. Only that acknowledgement deletes that
batch's ordinals; one acknowledgement never covers another batch or the order.
The worker takes the LMDB writer briefly as a barrier before each read, so a
wake from a writer that has not yet committed is never read early.

Managed stop does not end a prospective connection at its trigger: every
other legal capture ends and joins at the start of teardown, while prospective
connections keep draining. After every writer of the process has stopped and
before the vault closes, the final drain runs: each attached prospective
connection drains its outbox to empty under the writer barrier and sends one
last batch, possibly empty, whose summary carries `final_next_ordinal`, the
order's next ordinal. No entry at or after it exists and this process writes
none; the batch's range ends there. It is a per-process statement, not the
order's release or end: the standing stays for a later start. A HOST that is
not connected is not waited for, and its order's outbox stays in the vault. A
connected HOST that does not answer holds the drain only to the connection's
existing term deadline or the supervisor's kill; its entries stay unacknowledged
and durable.

The user's own erase, scrub, compaction or prune of a captured message is
never gated: the outbox entry is clone custody, not vault data. Release of the
order generation, or its term end, destroys the standing and its whole outbox
in one write; the maintenance pass ends lapsed orders that have no live
connection. A message has no document rows at birth, so a batch carries none;
edges a later batch adds, and edges a sync landing brings after the message,
are later edits, not prospective captures. The HOST may follow with an exact
`Messages` capture while the message exists.
