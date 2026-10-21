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
| `LEASE_REQUIRED` | Use light or medium recall, or present a budget lease. |
| `IDENTITY_UNSETTLED` | The effect named a person through a mention that is not settled yet. Settle it with `self.identity.settle`, then act. |
| `BUDGET_SPENT` | The line a paid call spends on is spent, or the vault's budget policy refuses it. Use light or medium recall, or ask the owner to raise the line. |
| `MODEL_UNAVAILABLE` | The model the request needs did not answer usably; nothing stands in for it. Use light or medium recall, or ask the owner to check the model route. |
| `OFF_RECORD_SESSION_DOOR` | Use the owning off-record session handle. The canonical witness door is not that handle. |
| `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE` | No record holds a room's consent to one caller managing its whole off-record stretch, on any host. Act as a member instead: status and witness, and save or export your own copy through the room's routes. |
| `OWNER_BINDING_REQUIRED` | An owner device must bind this human actor in the authority log. Scope changes do not grant ownership. |
| `VAULT_LOCKED_SINGLE_WRITER` | Connect to the process that owns this vault. Do not remove lock files or open a second writer. |
| `WRONG_ROOT` | The verb was named under the wrong root and nothing ran; the SDK never corrects and runs it. Issue a fresh call to the `replacement` the error carries. |
| `PENDING_ASK` | A verb hook asked before the verb ran: the verb waits on that open ask and was not refused. The error's `hook` names the invocation and the ask; a retry with the same invocation answers the same ask, never a second one. Each handle's `retry(pending, verb, input)` resends the call under it (UniFFI: the failure's `pending` payload); `oneiron mcp` resends an identical repeated tool call under the pending call's invocation. |
| `INVENTED_REFERENCE` | Name only records this writer can read, by the ref the engine issued. The write was refused and receipted. |
| `HOST_ACTION_REQUIRES_SUPPORT_GRANT` | A hosted operator's root acts as nobody inside a customer's vault. Ask the customer for a support grant; the operator's admin commands need none. |
| `WORLD_RECIPIENT_LIMIT` | The owner's read setting for a row's world keeps it from where this answer goes; the message names his choice, never the world. Read it where his choice admits, or ask him to change that setting. The row is there: do not treat this as not found. |
| `WORLD_PLACEMENT_UNVERIFIABLE` | A row's world placement, the rows a result came from or the vault root cannot be verified now, so nothing was released. No change to the request helps; retry once the vault has settled it. |
| `SANDBOX_PROPOSAL_DISK_FLOOR` | A foreign program's proposed file would cross the host disk's free-space floor, so the run failed and proposed nothing. The message names the bytes needed and free. No change to the request helps; run again once the host has room. |

Remote server-specific codes and HTTP schemas are also indexed by
[the engine API reference](../../oneiron.skills.md).
