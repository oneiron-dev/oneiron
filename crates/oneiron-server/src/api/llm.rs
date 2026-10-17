//! Owner-authenticated raw inference. Host injection is explicit and absent by default.
use crate::models::{OfferLadder, RawInference};

pub(super) mod decision_read;
use crate::{auth::CoreAuth, server::SyncServer};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use oneiron::llm::run_admission::{RunAdmission, RunDenied};
use oneiron::{LlmError, LlmRequest, LlmStreamEvent};
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/generate", post(generate))
        .route("/stream", post(stream))
        // A probe of the house model's decision read; its state is bounded.
        .route(
            "/decision_read",
            post(decision_read::decision_read).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        // Owner-grade credentials can hand an agent a real read/replace tool;
        // scoped core tokens cannot edit vault policy.
        .route(
            "/defaults",
            get(read_defaults)
                .put(replace_defaults)
                .layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
}
fn refusal(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({"error":{"code":code}}))).into_response()
}
/// A param or provider option that would pick the model or the route
/// (`LlmRequest::route_selector_override`), named as `key` or `namespace.key`,
/// with `*` for a namespace no adapter reads.
fn route_selector_refusal(key: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":{"code":"route_selector_forbidden","key":key}})),
    )
        .into_response()
}
fn failure(error: LlmError) -> Response {
    let (status, body) = failure_body(error);
    (status, Json(body)).into_response()
}
/// A failed call's status and typed body, `{"error": {"code", "llm"}}`: the
/// refusal before a stream starts, and a stream's last line once it has.
fn failure_body(error: LlmError) -> (StatusCode, serde_json::Value) {
    use oneiron::{FatalLlmError, RetryableLlmError};
    let (status, code) = match &error {
        LlmError::BudgetDenied(_) => (StatusCode::PAYMENT_REQUIRED, "budget_denied"),
        LlmError::Fatal(FatalLlmError::Auth) => (StatusCode::UNAUTHORIZED, "auth"),
        // The model's answer failed a read check: an upstream fault, never a p = 0.
        LlmError::Fatal(FatalLlmError::LabelRead(_)) => (StatusCode::BAD_GATEWAY, "label_read"),
        LlmError::Fatal(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => {
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        }
        LlmError::Retryable(RetryableLlmError::Timeout) => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        // A spent usage window or spent prepaid credit (OF-305): `llm`
        // carries the window's reset or the credit park, and `quota` points
        // at the owner's durable question.
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => {
            (StatusCode::TOO_MANY_REQUESTS, "quota_spent")
        }
        // A privacy hold, not a rate refusal: no offer the call may use on
        // this device answered.
        LlmError::Retryable(RetryableLlmError::KeptOnDevice { .. }) => {
            (StatusCode::SERVICE_UNAVAILABLE, "kept_on_device")
        }
        LlmError::Retryable(_) => (StatusCode::BAD_GATEWAY, "stream_cut"),
    };
    let mut body = serde_json::json!({"error":{"code":code,"llm":error}});
    if code == "quota_spent" {
        body["error"]["quota"] = serde_json::json!({
            "questions": "GET /v1/ai/status",
            "answer": "POST /v1/ai/quota/{question}",
        });
    }
    (status, body)
}
async fn read_defaults(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> Response {
    if !auth.is_owner_grade() {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    }
    match server.vault.purpose_default_table() {
        Ok(table) => Json(table).into_response(),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

async fn replace_defaults(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(table): Json<oneiron::llm::PurposeDefaultTable>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    }
    // A JSON body is only a DTO. Validate all rows before inspecting any key.
    let table = match oneiron::llm::ValidatedPurposeDefaults::try_from(table) {
        Ok(table) => table,
        Err(_) => return refusal(StatusCode::BAD_REQUEST, "invalid_defaults"),
    };
    if table
        .table()
        .purpose(&oneiron::CallPurpose::Extraction)
        .is_some_and(|row| row.locality != oneiron::ModelLocality::OnDevice)
        && server.extraction_egress.is_none()
    {
        return refusal(StatusCode::BAD_REQUEST, "extraction_egress_unavailable");
    }
    match server.vault.set_purpose_default_table(table.table()) {
        Ok(()) => Json(table.table()).into_response(),
        Err(oneiron::Error::InvalidConfig(_)) => {
            refusal(StatusCode::BAD_REQUEST, "invalid_defaults")
        }
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

/// Admits a raw call: the owner, then the vault's inference policy for the
/// model the request names. The call itself is admitted rung by rung under a
/// run on the raw routes' meter, as it goes out.
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    request: &mut LlmRequest,
) -> Result<(Arc<OfferLadder>, RunAdmission), Box<Response>> {
    if !auth.is_owner_grade() {
        return Err(Box::new(refusal(StatusCode::FORBIDDEN, "owner_required")));
    }
    admit_owner(server, request)
}

/// [`admit_owner`] for a connector's call through the OpenAI-compatible
/// proxy (OF-445): the vault's inference policy for the model, on the raw
/// routes' meter. The proxy has already authenticated its connector and
/// narrowed the model to one `[models]` configures.
pub(super) fn admit_proxied(
    server: &SyncServer,
    request: &mut LlmRequest,
) -> Result<(Arc<OfferLadder>, RunAdmission), Box<Response>> {
    admit_owner(server, request)
}

/// [`admit`] past the owner check: the call is the owner's.
fn admit_owner(
    server: &SyncServer,
    request: &mut LlmRequest,
) -> Result<(Arc<OfferLadder>, RunAdmission), Box<Response>> {
    // The request's model id picks the model and its route; a body field that
    // names another is refused before anything is reserved, with its row.
    if let Some(key) = request.route_selector_override() {
        let reason = RunDenied::RouteOverride { key: key.clone() };
        RawInference::refuse(request, reason, server.run_receipts());
        return Err(Box::new(route_selector_refusal(&key)));
    }
    let Some(raw) = &server.llm else {
        return Err(Box::new(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "llm_unavailable",
        )));
    };
    let original_purpose = request.envelope.purpose.clone();
    // A model `[models]` configured is attested by this host; any other id
    // must have a registered catalog row.
    let binding = match server.ai.model_locality(&request.model) {
        Some(locality) => oneiron::llm::HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality,
        },
        None => oneiron::llm::HostInferenceBinding::Registered,
    };
    let context = oneiron::llm::HostInferenceContext {
        binding,
        extraction_egress: server.extraction_egress.as_deref(),
    };
    let authorized = server
        .vault
        .authorize_raw_inference(request.clone(), &context)
        .map_err(|_| {
            Box::new(if original_purpose == oneiron::CallPurpose::Extraction {
                refusal(StatusCode::FORBIDDEN, "extraction_egress_denied")
            } else {
                refusal(StatusCode::BAD_REQUEST, "invalid_request")
            })
        })?;
    *request = authorized.into_request();
    // The world a caller names does not vouch for the text it sends (Astra
    // R4): a fallback judges the call as naming none, so the vault-wide
    // floor holds it while any world stays on the device.
    request.envelope.scope.world = None;
    raw.call(request, server.run_receipts())
        .ok_or_else(|| Box::new(refusal(StatusCode::BAD_REQUEST, "invalid_request")))
}
async fn generate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (ladder, run) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    match ladder.generate(&run, request, None).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => failure(e),
    }
}
/// A stream's last line when it fails once started: the same typed body a
/// refusal before the stream gets, so credit spent mid-stream closes it
/// with `quota_spent` and its question's pointer, not a bare cut.
async fn send_error(
    send: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    error: LlmError,
) {
    let (_, body) = failure_body(error);
    let mut bytes = serde_json::to_vec(&body).expect("LLM error serializes");
    bytes.push(b'\n');
    let _ = send.send(Ok(bytes)).await;
}
async fn stream(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (ladder, run) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    // The first rung is admitted here, so a refused call answers before the
    // stream starts. Each rung settles itself; a stream the client leaves
    // ends its call, and a started rung keeps its reservation as spend.
    let mut source = match ladder.stream(&run, request, None) {
        Ok(source) => source,
        Err(e) => return failure(e),
    };
    let (send, receive) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
    tokio::spawn(async move {
        loop {
            let item = tokio::select! { _ = send.closed() => return, item = source.next() => item };
            let Some(item) = item else {
                return;
            };
            let event = match item {
                Ok(event) => event,
                Err(error) => {
                    send_error(&send, error).await;
                    return;
                }
            };
            let done = matches!(event, LlmStreamEvent::Done { .. });
            match serde_json::to_vec(&event) {
                Ok(mut bytes) => {
                    bytes.push(b'\n');
                    if send.send(Ok(bytes)).await.is_err() {
                        return;
                    }
                }
                Err(_) => {
                    send_error(&send, oneiron::FatalLlmError::InvalidRequest.into()).await;
                    return;
                }
            }
            if done {
                return;
            }
        }
    });
    let body = futures_util::stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|item| (item, receive))
    });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests;

/// Model calls from the owner's other machines over the mesh (OF-575 MESH:
/// "a phone uses the MacBook's model"). The mesh admitted the peer as a
/// paired machine of this vault, so its calls take the owner's admission,
/// the same rungs as `/v1/llm/generate` and `/v1/llm/stream`.
#[cfg(feature = "mesh")]
pub(crate) struct MeshLlm(pub(crate) Arc<SyncServer>);

#[cfg(feature = "mesh")]
impl oneiron_llm_own_server::LlmMeshHandler for MeshLlm {
    fn serves(&self, model: &oneiron::ModelId) -> bool {
        self.0.llm.is_some() && self.0.ai.model_locality(model).is_some()
    }

    fn generate(
        &self,
        _peer: oneiron::EntityId,
        mut request: LlmRequest,
    ) -> oneiron::LlmGenerateFuture<'static> {
        let server = Arc::clone(&self.0);
        Box::pin(async move {
            let (ladder, run) =
                admit_owner(&server, &mut request).map_err(|refused| refused_error(&refused))?;
            ladder.generate(&run, request, None).await
        })
    }

    fn stream(
        &self,
        _peer: oneiron::EntityId,
        mut request: LlmRequest,
    ) -> oneiron::LlmResult<oneiron::LlmStream<'static>> {
        let (ladder, run) =
            admit_owner(&self.0, &mut request).map_err(|refused| refused_error(&refused))?;
        ladder.stream(&run, request, None)
    }

    /// The configured chat models that run on this node or the owner's own
    /// server; a third-party model is not offered (FIX 1295).
    fn catalog(&self) -> Vec<oneiron::LlmCatalogEntry> {
        if self.0.llm.is_none() {
            return Vec::new();
        }
        self.0
            .ai
            .chat_catalog()
            .into_iter()
            .filter(|entry| oneiron_llm_own_server::advertises(entry.locality))
            .collect()
    }
}

/// An admission refusal as the error the asking node's transport returns.
#[cfg(feature = "mesh")]
fn refused_error(refused: &Response) -> LlmError {
    use oneiron::{FatalLlmError, RetryableLlmError};
    match refused.status() {
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => FatalLlmError::Auth.into(),
        StatusCode::SERVICE_UNAVAILABLE => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}
