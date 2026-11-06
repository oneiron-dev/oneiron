# Retained sync held-edit evidence

The owner can list retained held-edit evidence with the typed SDK verb
`vault.sync.quarantine.held_edits`, also served through MCP and
`POST /v1/core/facade/vault.sync.quarantine.held_edits`. The request is empty.
Use the normal owner credential and holder proof. An embedded handle uses
its actual embedded owner; an ordinary scoped reader cannot list this
whole-vault evidence.

The reply contains the stored sequence and retained quarantine metadata:
window key, container, CRDT-key hash and byte length, reason code, payload
hash, and quarantine time. Both hashes are sixteen-digit lowercase hexadecimal
strings, so JavaScript callers receive all 64 bits unchanged. The native stored
record and its codecs do not change. It includes only entity-map records whose reason
is `sealed_file_edited` or `projection_edit_conflict`, in stored sequence
order. It never returns rejected body bytes or the original CRDT map key.
The owner and any request credential are checked again in the same read
snapshot before scanning the quarantine rows.

These are retained diagnostic records, not a live pending-work inventory
or a settlement status. The existing shared quarantine retention still
applies. An empty list does not prove that no held work exists, and a
record does not prove that work is still pending. Undecodable records are
skipped with the same warning as the existing quarantine reader; storage
errors propagate. Listing does not clear, release, retry, or settle work.
The native `sync_doctor` report and its other fields are unchanged.
