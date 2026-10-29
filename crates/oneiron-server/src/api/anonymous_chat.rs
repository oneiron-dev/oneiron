//! A single memory-free turn on the house configuration or a plain model.
//!
//! Mounted outside idempotency and wire telemetry. The engine owns both
//! policy checks; this host owns model bindings and the two notice channels.
//! Nothing here enters agent chat, witnesses a turn, or saves an off-record room.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{CallOutcome, RunCall, RunReceipt, RunReceiptSink};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::off_record::anonymous_chat::{
    AnonymousChatResponder as Responder, AnonymousChatSession, AnonymousChatTarget,
};
use oneiron::store::GateSystemNoticeRecord;
use oneiron::task_verb::sdk::{
    AnonymousChatRequest as ChatRequest, AnonymousChatRequestTarget as Target,
    AnonymousChatResponse as ChatResponse,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, FatalLlmError, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStreamResult, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence, Vault,
};
use rand_core::RngCore;

use crate::ai_host::CHAT_ROLE;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::ServedOffer;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/ai/anonymous-chat", post(chat))
        .merge(super::facade::anonymous_chat_routes())
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    let request_id = format!(
        "{:016x}{:016x}",
        rand_core::OsRng.next_u64(),
        rand_core::OsRng.next_u64(),
    );
    response.headers_mut().insert(
        "x-request-id",
        header::HeaderValue::from_str(&request_id).expect("generated request id is ASCII"),
    );
    response
}

fn refusal(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({"error": {"code": code}}))).into_response()
}

pub(super) async fn chat(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ChatRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = auth.require(CoreScope::Read) {
        return error.into_response();
    }
    let Ok(Json(request)) = payload else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_anonymous_chat_request");
    };
    match super::facade::host_doors::ai_anonymous_chat(&server, &auth, request).await {
        Ok(answer) => Json(answer).into_response(),
        Err(error) => refusal(error.0, error.1),
    }
}

pub(crate) struct ChatRefusal(pub(crate) StatusCode, pub(crate) &'static str);

/// The existing anonymous-chat execution, on the caller's own credential.
/// Only the standalone HTTP routes call it: recorded transports cannot run
/// hooks, claim invocations or retain a result for this memory-free turn.
pub(crate) async fn ai_anonymous_chat(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: ChatRequest,
) -> Result<ChatResponse, ChatRefusal> {
    if request.text.trim().is_empty()
        || matches!(request.target, Target::HouseMind) && request.model.is_some()
        || matches!(request.target, Target::PlainModel) && request.model.is_none()
    {
        return Err(ChatRefusal(
            StatusCode::BAD_REQUEST,
            "invalid_anonymous_chat_request",
        ));
    }

    let target = AnonymousChatTarget::from(request.target);
    let (model_request, offer) = match bind_target(&server, target, request.model.as_ref()) {
        Ok(binding) => binding,
        Err(_) => {
            return Err(ChatRefusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "anonymous_model_unavailable",
            ));
        }
    };
    let backend = if offer.binding.locality == ModelLocality::OnDevice {
        OffRecordBackendClass::Local
    } else {
        OffRecordBackendClass::RemoteProvider
    };
    // Names are host-generated, request-local and never returned or logged.
    let session_ref = format!("anonymous:{:016x}", rand_core::OsRng.next_u64());
    // OF-063 (FIX 2137): the stretch maps to the principal the credential
    // names; a credential naming none opens it bound to nobody.
    let opened = match crate::api::call_receipt::request_principal(&auth) {
        Some(principal) => server
            .vault
            .open_anonymous_chat_for(&session_ref, backend, principal),
        None => server.vault.open_anonymous_chat(&session_ref, backend),
    };
    let session = match opened {
        Ok(session) => session,
        Err(_) => {
            return Err(ChatRefusal(
                StatusCode::CONFLICT,
                "anonymous_session_unavailable",
            ));
        }
    };
    let mut session = ClosingSession(Some(session));
    let responder = AnonymousChatResponder {
        vault: &server.vault,
        auth: &auth,
        target,
        request: model_request,
        offer,
        budget: private_budget(server.ai.chat_settings().turn_budget_units),
    };
    let policy_backend = PolicyBackend {
        server: &server,
        auth: &auth,
    };
    let policy_budget = private_budget(server.ai.chat_settings().turn_budget_units);
    let result = session
        .0
        .as_ref()
        .expect("anonymous session is open")
        .chat(
            &request.text,
            target,
            &responder,
            &policy_backend,
            &policy_budget,
            // The host's owner-plane wording and dial (FIX 5043), its
            // decision ladder's paired question lent (FIX 1201).
            &server
                .decision_host()
                .policy_model_config(&server.policy_doors.owner),
        )
        .await;
    let closed = session.close();
    if !auth.credential_is_live(&server.vault) {
        return Err(ChatRefusal(StatusCode::FORBIDDEN, "credential_revoked"));
    }
    if closed.is_err() {
        return Err(ChatRefusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "anonymous_session_close_failed",
        ));
    }
    match result {
        Ok(turn) => Ok(ChatResponse::from(turn)),
        Err(_) => Err(ChatRefusal(StatusCode::CONFLICT, "anonymous_chat_failed")),
    }
}

/// Close on cancellation as well as the ordinary reply, block and error paths.
struct ClosingSession<'a>(Option<AnonymousChatSession<'a>>);

impl ClosingSession<'_> {
    fn close(&mut self) -> oneiron::Result<()> {
        self.0
            .take()
            .map_or(Ok(()), |session| session.close().map(|_| ()))
    }
}

impl Drop for ClosingSession<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn private_budget(units: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "anonymous-chat",
        units,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
        BudgetExhaustionPolicy::Suspend,
    )
}

/// Only the current text crosses the engine's responder seam. The house's
/// instruction comes from its configured model rung, never an agent record.
struct AnonymousChatResponder<'a> {
    vault: &'a Vault,
    auth: &'a CoreAuth,
    target: AnonymousChatTarget,
    request: LlmRequest,
    offer: ServedOffer,
    budget: BudgetGuard,
}

impl Responder for AnonymousChatResponder<'_> {
    fn respond<'a>(
        &'a self,
        target: AnonymousChatTarget,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = oneiron::Result<String>> + Send + 'a>> {
        self.respond_with_notices(target, text, &[])
    }

    fn respond_with_notices<'a>(
        &'a self,
        target: AnonymousChatTarget,
        text: &'a str,
        notices: &'a [GateSystemNoticeRecord],
    ) -> Pin<Box<dyn Future<Output = oneiron::Result<String>> + Send + 'a>> {
        Box::pin(async move {
            if target != self.target || !self.auth.credential_is_live(self.vault) {
                return Err(oneiron::Error::InvalidConfig(
                    "anonymous binding is no longer live".into(),
                ));
            }
            let mut request = self.request.clone();
            request
                .messages
                .extend(notices.iter().map(|notice| LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: notice.body.clone(),
                    }],
                }));
            request.messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: text.to_owned(),
                }],
            });
            let response = generate_private(request, self.offer.clone(), self.budget.clone())
                .await
                .map_err(|_| oneiron::Error::InvalidConfig("anonymous model call failed".into()))?;
            Ok(response
                .message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect())
        })
    }
}

fn bind_target(
    server: &SyncServer,
    target: AnonymousChatTarget,
    model: Option<&ModelId>,
) -> oneiron::Result<(LlmRequest, ServedOffer)> {
    let unavailable = || oneiron::Error::InvalidConfig("anonymous model is not configured".into());
    let (locality, ladder) = match target {
        AnonymousChatTarget::HouseMind => server
            .ai
            .chat_seat()
            .map(|seat| (seat.locality, Arc::clone(&seat.ladder)))
            .ok_or_else(unavailable)?,
        AnonymousChatTarget::PlainModel => server
            .ai
            .model_runtime()
            .router()
            .and_then(|router| router.served(model?))
            .ok_or_else(unavailable)?,
    };
    let purpose = CallPurpose::AnswerGen;
    let mut request = LlmRequest {
        model: ladder.model().clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("answer".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: false,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let house = target == AnonymousChatTarget::HouseMind;
    let ladder = if house {
        let call = server
            .ai
            .admit_role(&server.vault, CHAT_ROLE, request)
            .map_err(|_| unavailable())?;
        request = call.request;
        call.ladder
    } else {
        let binding = oneiron::llm::HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality: request.envelope.locality,
        };
        request = server
            .vault
            .authorize_raw_inference(
                request,
                &oneiron::llm::HostInferenceContext {
                    binding,
                    extraction_egress: None,
                },
            )?
            .into_request();
        ladder
    };
    ladder
        .anonymous_call(request, house)
        .map_err(|_| unavailable())
}

/// Owner policy uses the host's configured checker. Missing or unavailable
/// checker coverage is reported by the engine as skipped, never clean allow.
struct PolicyBackend<'a> {
    server: &'a SyncServer,
    auth: &'a CoreAuth,
}

impl LlmBackend for PolicyBackend<'_> {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            if !self.auth.credential_is_live(&self.server.vault) {
                return Err(FatalLlmError::Auth.into());
            }
            let call = self
                .server
                .ai
                .admit_role(&self.server.vault, ModelRole::Checker, request)
                .map_err(|_| FatalLlmError::InvalidRequest)?;
            let (request, offer) = call.ladder.anonymous_call(call.request, false)?;
            generate_private(
                request,
                offer,
                private_budget(self.server.ai.chat_settings().turn_budget_units),
            )
            .await
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Calls still take one-use permits and settle their private meters. No
/// server receipt sink, quota store, fallback telemetry or event bus sees them.
struct DiscardReceipts;

impl RunReceiptSink for DiscardReceipts {
    fn record(&self, _: RunReceipt) {}
}

async fn generate_private(
    request: LlmRequest,
    offer: ServedOffer,
    budget: BudgetGuard,
) -> LlmResult<LlmResponse> {
    let run =
        crate::models::undeclared_run("anonymous-chat", budget, None, Arc::new(DiscardReceipts));
    let call = RunCall {
        selector: None,
        request: &request,
        offer: &offer.binding,
    };
    let permit = match offer.backend.request_digest(&request, false)? {
        Some(digest) => run.admit_request(call, &digest)?,
        None => run.admit(call)?,
    };
    let backend = run.gate(offer.backend, &offer.binding);
    let response = backend.generate(request, permit.lease()).await?;
    permit.settle(CallOutcome::Answered(&response.usage))?;
    Ok(response)
}
