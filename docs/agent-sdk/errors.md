# Memory Wire typed errors

Every SDK failure carries `code`, `message`, and nonempty `suggestions`.
Use the returned suggestions; do not parse message prose. No adapter swallows
or downgrades the engine's refusal. Future remote codes pass through verbatim.

| Code | Response |
|---|---|
| `BAD_REQUEST` | Correct input fields, types and units. Timestamps are Unix seconds. |
| `NOT_FOUND` | Refresh the identifier and current read scope before retrying. |
| `FORBIDDEN` | Respect the gate or identity refusal. Review pending consent; do not widen scope or retry blindly. |
| `INVALID_STATE` | Read the current lifecycle head, then make a new decision. Do not replay a stale target. |
| `INTERNAL_SERVER_ERROR` | Check the server endpoint, network and health. Report reproducible SDK boundary failures. |
| `LEASE_REQUIRED` | Use standard/minimal recall or acquire a lease through the engine's budget door. |
| `OFF_RECORD_SESSION_DOOR` | Use the owning off-record session handle. The canonical witness door is not that handle. |
| `OWNER_BINDING_REQUIRED` | An owner device must bind this human actor in the authority log. Scope changes do not grant ownership. |
| `VAULT_LOCKED_SINGLE_WRITER` | Connect to the process that owns this vault. Do not remove lock files or open a second writer. |

Remote server-specific codes and HTTP schemas are also indexed by
[the engine API reference](../../oneiron.skills.md).
