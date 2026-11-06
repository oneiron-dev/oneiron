# SLIM lifecycle calls on the sync socket

The existing non-waking facade calls are `vault.slim.policy`, `vault.slim.state`, `vault.slim.resume_step`, `vault.slim.drop_heavy` and `vault.slim.resume`. HTTP facade ingress and sync-socket RPC ingress use one classifier for this set.

For a decoded socket RPC naming one of these calls, ingress does not automatically resume SLIM before dispatch. The verb still passes its normal credential, owner and dispatch checks. `vault.slim.resume` performs its own transition and returns that transition's receipt; observation does not preemptively change the state it reports.

Malformed RPCs and every other socket message keep the existing inbound-resume behavior. The socket's privileged-message revocation check still runs before classification. HTTP `GET /api/health` remains non-waking, and the HTTP facade path rules do not change.

## Owner-attested MCP calls

For an owner-attested MCP POST whose body is already held in memory, ingress can identify a registered direct lifecycle verb or a registered `invoke_action` whose `arguments.verb` names one of the same five calls. It then leaves the transition to that verb, rather than resuming SLIM first. In particular, an action invoking `vault.slim.resume` can return the receipt for its own transition.

This is a wake hint, not authorization. The original attestation, request bytes, credential and owner checks, action validation, and dispatch remain unchanged. The action hint reads only the nested verb from the already-held body; it does not copy the action arguments or add a body limit.

Encoded or spooled bodies, escaped names that the borrowed projection cannot read, and connection setup still keep their existing behavior. This is not full MCP or other body-carrier parity.

No wire format, policy, model choice, retry interval or configuration default changes. No migration, deployment change or external service is required.
