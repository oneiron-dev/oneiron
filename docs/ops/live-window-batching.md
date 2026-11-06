# Large live window writes in node batches

The live device sender keeps one node BATCH per sync tick. The existing byte
and member limits still apply. Document and window work keep their alternating
tick leader and their own order.

A window update that cannot fit one empty BATCH stays at the head of the live
update buffer. The sender prepares it once for this connection and encodes
ordered window-pad frames with room for the BATCH tag and member length. Each
later tick takes only the frames that fit its ordinary BATCH. Later window
updates cannot pass the unfinished head. The reconnect-only queue is no longer
its normal delivery path.

The BATCH decoder accepts a complete, valid window-pad header with an initial
payload fragment. This does not admit an update. The home assembles the payload,
references and required capsule on the same connection before it runs the
existing window, grant, Write credential, pad, copy-admission and persistence
checks. An incomplete required prefix produces no import or successful receipt.
An optional derived-copy tail never delays that required ready point.

Before each draw, the sender checks the current window withholding verdict
and home grant again. Batch frames keep their receipt registration, but do not
retain the standalone sender's whole-payload continuation copy: the buffered
head already supplies each draw's check. If release or the home grant changes
during a multipart send, the sender forgets only its exact receipt binding and
matching continuation identity, then disconnects. This releases any prefix held
by the home's connection-local assembly. The existing disconnect path retains
the original buffered writes for recovery. It never clears a newer send,
invents an ACK or settles a durable queue row.

The unfinished update stays buffered until all its frames have been selected.
The existing exit path therefore retains it for reconnect recovery if the
connection ends mid-transfer. Opened mode reserves one real queue sequence
when the live transfer starts; partial ticks do not reserve more. Existing
at-least-once exit recovery can record a retry copy after a disconnect. No
exactly-once queue, runtime latency or whole-transfer memory bound is claimed.

## Optional default CLAIM copies

For a non-federated live node batch, the client prepares copies from the actual
carried CLAIM occurrences and the envelope's exact payload. It uses only a
settled default cloud-route vector whose complete source matches that occurrence.
The signed, recipient-sealed bytes remain separate from the raw window's authority.

Non-serializable source tokens stay with the selected members, including a
buffered multipart head. The existing split sink holds a typed native batch,
not its finalized optional-copy bytes. After the underlying socket becomes ready,
its send door rechecks the complete current vector, every original release row,
the machine proved by this socket's upgrade and its current keys, then finishes
the optional suffix synchronously before accepting the write. A miss abandons only the optional copies. It does not disconnect, requeue
or delay the required window bytes.

The original copy-free frames determine raw selection, batch order, multipart
mode and queue sequencing. Copies use only byte and member room left after that
selection, under the existing limits. If there is no room, or the final source
check fails, the sender omits the optional suffix without changing its header,
envelope id or any required part offset. An incomplete optional tail cannot
produce a copy; the receiver still imports and receipts the required prefix
exactly once. Native tokens drop with the selected batch or its buffered head,
never become a durable queued grant, and do not survive the connection.

The live producer covers node batches. Direct UPDATE deltas answering a
VV_REQUEST or VV_RESPONSE also keep their native tokens through the same
socket door, including during the initial handshake, convergence, normal
incoming-message handling and the residence-ACK pump. These direct frames
keep the standalone encoder's existing per-frame limits and order. A final
source miss drops only the optional suffix, not the required window prefix.
Receipt-resend, queued handshake replay, bulk, promotion and server-generated
producers still do not add copies.

`SyncClient::handle_server_message` returns owning `PreparedSyncFrame` values.
The connection keeps each whole native value in its existing split-sink slot
until the underlying socket is ready. It checks the original frame with the
existing withholding predicate before queuing it. Public `as_bytes` and
`into_bytes` expose only required bytes, never optional copies as a future
grant. An optional-only continuation has no required bytes and is omitted by
the native socket when its copies are abandoned. Other replies carry their
original bytes with no optional evidence. There is no parallel raw/with-copies
dispatch or compatibility reader.

The standalone window encoder, protocol tags, header fields, receipt bindings,
limits and retry settings are unchanged. There is no migration or old-format
reader. Rebuild the device client and home server together so both support
partial window payloads inside BATCH members. No configuration or deployment
is performed by this change.
