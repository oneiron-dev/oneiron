# NOTE document delivery across frame boundaries

NOTE snapshots, update exports and operation receipts are logical document
messages. A logical message is not limited to one transport frame. The ordinary
sync frame bound remains 8 MiB.

## Local messages and network frames

`encode_unsplit_document` makes a trusted local message with the original
`TAG_DOCUMENT | entity:16 | kind:1 | payload` layout. It is for export results
and local delivery queues, not direct network output. Small messages keep their
existing bytes. Non-NOTE exports still use the ordinary bounded encoder.

The server applies its existing subscription, actor, destination, erasure and
current-receipt checks to the whole logical message. Its final release door
splits a message that exceeds one frame into `document_sub_tags::PART` (13).
The same mutable transport sends the complete ordered run. Every part retains
the transport's normal stop and credential-revocation checks.

A PART payload contains:

| Field | Encoding |
| --- | --- |
| Original document kind | 1 byte |
| Complete logical payload length | 8-byte unsigned big-endian |
| Offset into that payload | 8-byte unsigned big-endian |
| BLAKE3 of the complete logical payload | 32 bytes |
| Payload bytes at that offset | Remaining bytes |

Each part includes the original 18-byte document frame header. Its payload
chunk therefore fits within `8 MiB - 18 - 49` bytes. The total and offset name
actual native lengths; they do not impose a new logical document size cap.
The digest is an integrity check, not authority or proof of a read grant.

## Receiving and retrying

The client checks every network frame with the existing bounded decoder. It
joins parts from an ordered run on that connection. Entity, original kind,
total, digest and offset must stay consistent. The buffer grows only with
bytes received, never by reserving a peer's declared total. Its memory lease
observes actual retained buffer capacity and lives through the original
complete-document handler. This observation is not a new memory admission
rule or a certificate for the decoder's internal allocations.

Only a complete payload with the correct digest reaches the existing NOTE
state/update importer or receipt decoder. The original authority session,
head, sequence, seal, citation, erasure and pending-request checks still run.
A prefix does not import data, produce an ACK, accept a receipt or clear a
pending command. The existing connection reset clears partial assembly.
Reconnect and durable command replay retain their ordinary behavior.

The full operation receipt still includes its complete applied view. It is
serialized before persistence as before. The server still rechecks a queued
receipt against current state and erasure. Owner delivery still sends current
state before the receipt and retries that ordered pair together.

## Residence reads

Opened-item residence already transfers large touch values in bounded parts
and checks their complete BLAKE3. A document uses that existing transport,
not the socket's PART frames. The old one-document-frame ceiling no longer
limits its logical total. Blob ceilings, per-reply and per-part bounds remain
unchanged. Entity, document kind, read-only cache, source, citation and erase
checks remain in their original places.

## Scope and limits

The outgoing node batch still carries ordinary bounded document frames. NOTE
export results and full operation receipts do not enter that client queue.
Its limits and selection order are unchanged.

Oversized single `NOTE_OPS` uploads and the separate pending-fork protocol are
not implemented by this change. Their own transport work remains separate.
The implementation still holds whole logical messages and decoded documents;
it does not promise bounded total heap, zero-copy delivery or streaming
admission. There is no old-format reader or compatibility path.
