//! A `tools/call`'s lasting receipt on MCP (OF-538), as the gateway's one
//! door writes it.

use serde_json::Value;

use super::McpGatewayError;
use crate::mcp::McpResolvedActor;
use crate::server::SyncServer;

/// OF-538's one MCP door: records a `tools/call` once it has answered, in its
/// own write transaction, and states the receipt on the reply, success or
/// refusal alike: `structuredContent.meta.receipt_ref` on a result,
/// `error.data.receipt_ref` on a refusal. A call inside an anonymous
/// off-record session records nothing and states `receipt_ref: null` with
/// `no_record: true`. `attempt` is what the call's collector held (OF-568
/// L4), never read from its arguments.
#[allow(clippy::too_many_arguments)]
pub(super) fn mcp_call_receipt(
    server: &SyncServer,
    actor: &McpResolvedActor,
    tool: String,
    request_digest: String,
    inputs: Option<oneiron::receipt::ActionInputs>,
    attempt: Option<oneiron::receipt::CallAttemptWitness>,
    anonymous: bool,
    called: Result<Value, McpGatewayError>,
) -> Result<Value, McpGatewayError> {
    let (outcome, result_digest) = match &called {
        // A `reveal.wait` reply is digested with its value masked (OF-560).
        Ok(result) => (
            oneiron::receipt::CallOutcome::Ok,
            Some(oneiron::receipt::call_json_digest(
                oneiron::task_verb::sdk::masked_reveal_reply(&tool, result)
                    .as_ref()
                    .unwrap_or(result),
            )),
        ),
        Err(error) => (
            oneiron::receipt::CallOutcome::Refused {
                code: error.kind.to_owned(),
            },
            Some(oneiron::receipt::call_refusal_digest(
                error.kind,
                &error.message,
            )),
        ),
    };
    let stamp = crate::api::call_receipt::record(
        server,
        anonymous,
        oneiron::receipt::CallReceiptInput {
            transport: oneiron::receipt::CallTransport::Mcp,
            verb: tool,
            actor_ref: actor.actor_ref.to_hex(),
            actor_class: actor.actor_class.gate_actor_class().to_owned(),
            credential_ref: actor
                .auth
                .as_ref()
                .and_then(crate::api::call_receipt::credential_ref),
            carrier_machine: None,
            outcome,
            request_digest,
            result_digest,
            inputs,
            attempt,
            served: Vec::new(),
        },
    );
    match called {
        Ok(mut result) => {
            crate::mcp::mcp_stamp_call_receipt(&mut result, &stamp);
            Ok(result)
        }
        Err(mut error) => {
            error.call_receipt = Some(Box::new(stamp));
            Err(error)
        }
    }
}
