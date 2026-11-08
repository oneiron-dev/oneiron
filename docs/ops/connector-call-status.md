# Connector-call status and live questions

`connector.call_status` reads a `call_ref` returned by `connector.call`. The
original caller and the vault owner may read it. Other callers receive the same
not-found response as an unknown ref. Polling sends nothing and does not claim an
answer, resume a send, or renew its authority.

## Served reads

HTTP, the held socket, MCP tools and MCP code-mode use the server's status door.
The door builds the caller's credential-backed `Memory` and reads the native call
state. For an unanswered input round it joins questions from that server's live
registry. The join requires the same call ref, handle, generation, question count,
original principal, grant, connector name and tool as the native state snapshot.
The registry keeps the original key binding; polling does not select a new key
or grant or run send/answer admission again.

Questions were cleared of the credential the send presented before entering the
registry. They remain foreign connector data, never instructions or approval.
The door applies the existing per-question device-local projection for the
caller's actual read destination and producer rows. Text naming a row that stays
on this device uses the existing `questions_narrowed` / `on_device` reply. The
outer `state`, `call_ref`, `name`, `tool`, `generation`, `asked` and `uncertain`
fields remain available, as do the question keys and answer handle.

The native `AwaitingInput.reply` is `ActAnswer<ConnectorCallReply>` so that this
projection stays nested inside the status. A `Done` reply keeps the existing JSON
shape. Other status variants are unchanged.

## Missing live text and embedded reads

The durable call row keeps the handle, generation, count and lease, never question
text. If this server has no matching live copy, status returns the row metadata
and `questions_not_retained` as before. The embedded native reader has no server
registry and keeps that same row-only behavior. A live copy is not discarded just
because the row is uncertain or its lease time has passed: the lease is not an
expiry.

A status read does not consume or claim live questions. `connector.answer`
retains its existing principal/grant checks and owns the answer claim. Settled
status reads keep their existing acknowledgement/consumption behavior. No new
storage format, compatibility reader, setting, cap or timeout is introduced.
