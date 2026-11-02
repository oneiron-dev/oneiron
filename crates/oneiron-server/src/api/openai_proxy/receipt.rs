//! FIX 3389: the lasting receipt a raw `/v1/chat/completions` reply states
//! (OF-538), as the facade, MCP and WS doors state theirs: its ref in
//! `x-oneiron-receipt-ref`, or `none; no-record` for a caller verified in an
//! anonymous off-record session. The body an OpenAI client reads keeps its
//! shape, success and refusal alike.
//!
//! The raw door records its own call, once. A refusal before any caller
//! resolved (a body that is no call, a credential the resolver refused) is
//! its connection's (FIX 811), never a guessed actor's. A resolved call is
//! the caller `/mcp` resolved, attributed as MCP attributes it. The receipt
//! states digests of what was asked and answered, never the bodies.

use axum::Json;
use axum::response::{IntoResponse, Response};
use oneiron::EntityId;
use oneiron::receipt::{
    ActionInputs, CallAttemptWitness, CallOutcome, CallReceiptInput, CallTransport,
};
use oneiron::task_verb::sdk::ChatCompletionResponse;
use serde_json::Value;

use super::wire::Refusal;
use crate::api::McpCallContext;
use crate::api::call_receipt;
use crate::api::llm::RefusalCode;
use crate::server::SyncServer;

/// The verb a raw proxy call's receipt states: the row the typed doors serve
/// the same call under (Engine call, FIX 3389).
pub(in crate::api) const PROXY_CALL_VERB: &str = "ai.chat.completions";

/// What a raw call's receipt states of its request, taken before the body is
/// decoded: the digest of its canonical JSON, or of its bytes when it is no
/// JSON, and that JSON, for the inputs the call reads.
pub(super) struct ProxyRequest {
    digest: String,
    value: Option<Value>,
}

impl ProxyRequest {
    pub(super) fn of(body: &[u8]) -> Self {
        let value = serde_json::from_slice::<Value>(body).ok();
        let digest = match &value {
            Some(value) => oneiron::receipt::call_json_digest(value),
            None => oneiron::receipt::call_bytes_digest(body),
        };
        Self { digest, value }
    }

    /// Records a refusal no resolved caller stands behind for the connection
    /// it arrived on (FIX 811), and states it on the reply. Such a call names
    /// no principal, so it binds no session and is never the anonymous
    /// exception.
    pub(super) fn unattributed(self, server: &SyncServer, mut refused: Response) -> Response {
        let (outcome, result_digest) = refusal(&refused);
        let stamp = call_receipt::record(
            server,
            false,
            call_receipt::connection_call(
                CallTransport::OpenAiProxy,
                PROXY_CALL_VERB.to_owned(),
                outcome,
                self.digest,
                result_digest,
            ),
        );
        stamp.stamp_header(&mut refused);
        refused
    }
}

/// Who a resolved raw call is, taken from its one context before the call
/// consumes it: the actor, its class and the credential it presented, as MCP
/// states them, the session it named and the principal judged in it, and
/// the inputs the call reads.
pub(super) struct ProxyCaller {
    actor_ref: String,
    actor_class: String,
    credential_ref: Option<String>,
    session: Option<String>,
    principal: Option<EntityId>,
    anonymous: bool,
    inputs: Option<ActionInputs>,
}

impl ProxyCaller {
    pub(super) fn of(server: &SyncServer, actor: &McpCallContext, request: &ProxyRequest) -> Self {
        // OF-063: only a caller whose principal is verified in the session
        // keeps no record, judged on arrival and again before the receipt is
        // written. The configured root maps to the actor it acts through
        // (FIX 2271), as on MCP.
        let principal = call_receipt::mcp_session_principal(actor.auth.as_ref(), actor.actor_ref);
        let session = actor.off_record_session.clone();
        let anonymous =
            call_receipt::session_is_anonymous_for(server, session.as_deref(), principal);
        Self {
            actor_ref: actor.actor_ref.to_hex(),
            actor_class: actor.actor_class.gate_actor_class().to_owned(),
            credential_ref: actor.auth.as_ref().and_then(call_receipt::credential_ref),
            session,
            principal,
            anonymous,
            // OF-568: what the call reads, captured before it runs.
            inputs: call_receipt::action_inputs(server, PROXY_CALL_VERB, request.value.as_ref()),
        }
    }

    /// Records the call once it has answered, in its own write transaction,
    /// and states the receipt on the reply. A paid answer whose exchange was
    /// not remembered still answered: the remember refusal rides its body, so
    /// its digest, and the call is `Ok` (Engine call, FIX 3389). `served` is
    /// the rows its recall listed, on an answer. A receipt that cannot be
    /// written leaves the reply as it was, with no header.
    pub(super) fn answer(
        self,
        server: &SyncServer,
        request: ProxyRequest,
        attempt: Option<CallAttemptWitness>,
        listed: &[EntityId],
        answer: Result<ChatCompletionResponse, Response>,
    ) -> Response {
        let (mut reply, outcome, result_digest, served) = match answer {
            Ok(answer) => {
                let digest = serde_json::to_value(&answer)
                    .ok()
                    .map(|answer| oneiron::receipt::call_json_digest(&answer));
                let served = listed.iter().map(EntityId::to_hex).collect();
                (
                    Json(answer).into_response(),
                    CallOutcome::Ok,
                    digest,
                    served,
                )
            }
            Err(refused) => {
                let (outcome, digest) = refusal(&refused);
                (refused, outcome, digest, Vec::new())
            }
        };
        let anonymous = self.anonymous
            || call_receipt::session_is_anonymous_for(
                server,
                self.session.as_deref(),
                self.principal,
            );
        let stamp = call_receipt::record(
            server,
            anonymous,
            CallReceiptInput {
                transport: CallTransport::OpenAiProxy,
                verb: PROXY_CALL_VERB.to_owned(),
                actor_ref: self.actor_ref,
                actor_class: self.actor_class,
                credential_ref: self.credential_ref,
                carrier_machine: None,
                outcome,
                request_digest: request.digest,
                result_digest,
                inputs: self.inputs,
                attempt,
                served,
            },
        );
        stamp.stamp_header(&mut reply);
        reply
    }
}

/// A refusal's outcome and content digest: the code and message the proxy's
/// wire ([`Refusal`]) or the model admission ([`RefusalCode`]) built it
/// with. One neither built states its status and no digest, as the facade
/// records a reply its own refusal did not build.
fn refusal(response: &Response) -> (CallOutcome, Option<String>) {
    let built = match response.extensions().get::<Refusal>() {
        Some(refusal) => Some((&refusal.code, &refusal.message)),
        None => response
            .extensions()
            .get::<RefusalCode>()
            .map(|refusal| (&refusal.code, &refusal.message)),
    };
    match built {
        Some((code, message)) => (
            CallOutcome::Refused { code: code.clone() },
            Some(oneiron::receipt::call_refusal_digest(code, message)),
        ),
        None => (
            CallOutcome::Refused {
                code: format!("HTTP_{}", response.status().as_u16()),
            },
            None,
        ),
    }
}
