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
    AnonymousChatBlockReason, AnonymousChatResponder as Responder, AnonymousChatSession,
    AnonymousChatSkippedCheck, AnonymousChatTarget, AnonymousChatTurn,
};
use oneiron::policy_model::{PolicyModelConfig, PolicySkipReason};
use oneiron::store::GateSystemNoticeRecord;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, FatalLlmError, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStreamResult, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence, Vault,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::ai_host::CHAT_ROLE;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::ServedOffer;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/ai/anonymous-chat", post(chat))
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

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Target {
    #[default]
    HouseMind,
    PlainModel,
}

impl From<Target> for AnonymousChatTarget {
    fn from(target: Target) -> Self {
        match target {
            Target::HouseMind => Self::HouseMind,
            Target::PlainModel => Self::PlainModel,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    text: String,
    #[serde(default)]
    target: Target,
    /// A configured provider model id, required only for plain_model.
    model: Option<ModelId>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ChatResponse {
    Reply {
        content: String,
        notices: Vec<GateSystemNoticeRecord>,
        skipped_checks: Vec<SkippedCheck>,
        /// The same notices, in the same order, for the model's notice
        /// channel. Neither channel is a chat message or a retained turn.
        model_notices: Vec<GateSystemNoticeRecord>,
    },
    Blocked {
        input: bool,
        notice: Box<GateSystemNoticeRecord>,
        preceding_notices: Vec<GateSystemNoticeRecord>,
        reason: BlockReason,
        model_notices: Vec<GateSystemNoticeRecord>,
    },
}

#[derive(Serialize)]
struct SkippedCheck {
    input: bool,
    reason: PolicySkipReason,
}

impl From<AnonymousChatSkippedCheck> for SkippedCheck {
    fn from(check: AnonymousChatSkippedCheck) -> Self {
        Self {
            input: check.input,
            reason: check.reason,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum BlockReason {
    Policy,
    HumanReviewUnavailable,
}

impl From<AnonymousChatTurn> for ChatResponse {
    fn from(turn: AnonymousChatTurn) -> Self {
        match turn {
            AnonymousChatTurn::Reply {
                content,
                notices,
                skipped_checks,
            } => Self::Reply {
                content,
                model_notices: notices.clone(),
                notices,
                skipped_checks: skipped_checks.into_iter().map(SkippedCheck::from).collect(),
            },
            AnonymousChatTurn::Blocked {
                input,
                notice,
                preceding_notices,
                reason,
            } => {
                let mut model_notices = preceding_notices.clone();
                model_notices.push((*notice).clone());
                Self::Blocked {
                    input,
                    notice,
                    preceding_notices,
                    reason: match reason {
                        AnonymousChatBlockReason::Policy => BlockReason::Policy,
                        AnonymousChatBlockReason::HumanReviewUnavailable => {
                            BlockReason::HumanReviewUnavailable
                        }
                    },
                    model_notices,
                }
            }
        }
    }
}

fn refusal(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({"error": {"code": code}}))).into_response()
}

async fn chat(
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
    if request.text.trim().is_empty()
        || matches!(request.target, Target::HouseMind) && request.model.is_some()
        || matches!(request.target, Target::PlainModel) && request.model.is_none()
    {
        return refusal(StatusCode::BAD_REQUEST, "invalid_anonymous_chat_request");
    }

    let target = AnonymousChatTarget::from(request.target);
    let (model_request, offer) = match bind_target(&server, target, request.model.as_ref()) {
        Ok(binding) => binding,
        Err(_) => {
            return refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "anonymous_model_unavailable",
            );
        }
    };
    let backend = if offer.binding.locality == ModelLocality::OnDevice {
        OffRecordBackendClass::Local
    } else {
        OffRecordBackendClass::RemoteProvider
    };
    // Names are host-generated, request-local and never returned or logged.
    let session_ref = format!("anonymous:{:016x}", rand_core::OsRng.next_u64());
    let session = match server.vault.open_anonymous_chat(&session_ref, backend) {
        Ok(session) => session,
        Err(_) => return refusal(StatusCode::CONFLICT, "anonymous_session_unavailable"),
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
            &PolicyModelConfig::default(),
        )
        .await;
    let closed = session.close();
    if !auth.credential_is_live(&server.vault) {
        return refusal(StatusCode::FORBIDDEN, "credential_revoked");
    }
    if closed.is_err() {
        return refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "anonymous_session_close_failed",
        );
    }
    match result {
        Ok(turn) => Json(ChatResponse::from(turn)).into_response(),
        Err(_) => refusal(StatusCode::CONFLICT, "anonymous_chat_failed"),
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
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
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
