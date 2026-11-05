# SLIM lifecycle calls on the sync socket

The existing non-waking facade calls are `vault.slim.policy`, `vault.slim.state`, `vault.slim.resume_step`, `vault.slim.drop_heavy` and `vault.slim.resume`. HTTP facade ingress and sync-socket RPC ingress use one classifier for this set.

For a decoded socket RPC naming one of these calls, ingress does not automatically resume SLIM before dispatch. The verb still passes its normal credential, owner and dispatch checks. `vault.slim.resume` performs its own transition and returns that transition's receipt; observation does not preemptively change the state it reports.

Malformed RPCs and every other socket message keep the existing inbound-resume behavior. The socket's privileged-message revocation check still runs before classification. HTTP `GET /api/health` remains non-waking, and the HTTP facade path rules do not change.

This does not establish non-waking behavior for MCP or other body-carried calls. Their ingress and original-receipt parity remain separate work. No wire format, policy, model choice, retry interval or configuration default changes. No migration, deployment change or external service is required.
