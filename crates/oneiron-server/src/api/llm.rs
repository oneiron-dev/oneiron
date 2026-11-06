//! Owner-authenticated raw inference. Host injection is explicit and absent by default.
use crate::models::{CallDeadline, ModelCallBinding, OfferLadder, RawInference};

pub(super) mod decision_read;
mod defaults_submit;
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
use oneiron::code_run::ReadWorldUnknown;
use oneiron::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallInputPart, ModelCallKind, ModelCallReasoningPart, ModelCallRecord,
    model_call_digests, record_model_call_in_txn,
};
use oneiron::llm::run_admission::{RunAdmission, RunDenied};
use oneiron::{LlmError, LlmRequest, LlmResponse, LlmStreamEvent};
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
        // FIX 8211: the kept proposals, and a holder's answer to one.
        .route("/defaults/proposals", get(defaults_submit::list_proposals))
        .route(
            "/defaults/proposals/{proposal}",
            post(defaults_submit::rule_proposal),
        )
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
}
/// A refusal's wire code and its other wire field (empty for a code-only
/// body), kept on the response for the OpenAI proxy's call receipt
/// (FIX 3389) and never written to the wire.
#[derive(Clone, Debug)]
pub(super) struct RefusalCode {
    pub(super) code: String,
    pub(super) message: String,
}
fn coded(mut response: Response, code: &str, message: &str) -> Response {
    response.extensions_mut().insert(RefusalCode {
        code: code.to_owned(),
        message: message.to_owned(),
    });
    response
}
fn refusal(status: StatusCode, code: &str) -> Response {
    let response = (status, Json(serde_json::json!({"error":{"code":code}}))).into_response();
    coded(response, code, "")
}
/// A param or provider option that would pick the model or the route
/// (`LlmRequest::route_selector_override`), named as `key` or `namespace.key`,
/// with `*` for a namespace no adapter reads.
fn route_selector_refusal(key: &str) -> Response {
    let response = (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":{"code":"route_selector_forbidden","key":key}})),
    )
        .into_response();
    coded(response, "route_selector_forbidden", key)
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
        LlmError::Retryable(RetryableLlmError::WorldRouteNotAdmitted) => {
            (StatusCode::SERVICE_UNAVAILABLE, "world_route_not_admitted")
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
    // FIX 2222: an owner act; a hosted operator's root is refused, typed.
    if let Err(error) = crate::api::host_action::require_host_owner_act(&server, &auth) {
        return error.into_response();
    }
    // A managed vault's attested owner reads while he is its live owner.
    if let Err(error) = crate::api::scoped_auth::require_live_managed_owner(&server, &auth) {
        return error.into_response();
    }
    match server.vault.purpose_default_table() {
        Ok(table) => Json(table).into_response(),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

async fn replace_defaults(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: axum::http::HeaderMap,
    extensions: axum::http::Extensions,
    Json(table): Json<oneiron::llm::PurposeDefaultTable>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    }
    // FIX 2222: an owner act; a hosted operator's root is refused, typed.
    if let Err(error) = crate::api::host_action::require_host_owner_act(&server, &auth) {
        return error.into_response();
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
    // FIX 8211: a live policy-power holder's table lands; anyone else's is
    // kept as an inert proposal.
    defaults_submit::submit(&server, &auth, &headers, &extensions, table.table())
}

/// Admits a raw call: the owner, or an agent whose live Grant the owner
/// minted names `ai.text` (FIX 3208), whose call is then his; then the
/// vault's inference policy for the model the request names. The call itself
/// is admitted rung by rung under a run on the raw routes' meter, as it goes
/// out.
pub(super) fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    request: &mut LlmRequest,
) -> Result<(Arc<OfferLadder>, RunAdmission), Box<Response>> {
    if !auth.is_owner_grade() {
        if !crate::api::ai::granted_operations(server, auth)
            .contains(&oneiron::llm::media::AiOperation::Text)
        {
            return Err(Box::new(refusal(StatusCode::FORBIDDEN, "owner_required")));
        }
    } else if let Err(error) = crate::api::host_action::require_host_owner_act(server, auth) {
        // FIX 2222: an owner act; a hosted operator's root is refused, typed.
        return Err(Box::new(error.into_response()));
    }
    admit_owner(server, request)
}

/// [`admit_owner`] for a connector's call through the OpenAI-compatible
/// proxy (OF-445): the vault's inference policy for the model, on the raw
/// routes' meter. The proxy has already authenticated its connector;
/// [`admit_owner`] binds the selected model as configured here or registered
/// in the catalog.
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
            keyless: false,
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
            let admitted = oneiron::llm::admitted_as(&original_purpose);
            Box::new(if *admitted == oneiron::CallPurpose::Extraction {
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
/// Best-effort record of one completed model call, off the reply path. Missing
/// provider fields stay unknown; no receipt, route or read-world is invented.
pub(crate) fn record_raw_response(
    vault: &oneiron::Vault,
    ladder: &OfferLadder,
    run: &RunAdmission,
    request: &LlmRequest,
    response: &LlmResponse,
    binding: Option<&ModelCallBinding>,
    no_record: bool,
) {
    if no_record {
        tracing::debug!("model-call record skipped: off-record session or room");
        return;
    }
    let digests = match model_call_digests(request) {
        Ok(digests) => digests,
        Err(error) => {
            tracing::warn!(%error, "model-call request digests failed");
            return;
        }
    };
    // A recorded call's exact answering binding travels with its answer
    // (FIX 12743) and bypasses the requested-ladder lookup; a call that
    // names none leaves the route explicitly unknown, never a false pin.
    let (rung, route) = match binding {
        Some(binding) => (binding.rung.clone(), binding.route.clone()),
        None => ladder.model_call_binding(None),
    };
    let mut source_rows = run.source_rows().unwrap_or_default();
    source_rows.extend(
        response
            .reply_assertions
            .cited
            .iter()
            .map(|record| record.id),
    );
    source_rows.sort_unstable();
    source_rows.dedup();
    let input_parts = if source_rows.is_empty() {
        vec![ModelCallInputPart::Unknown {
            reason: "model-call request sources were not captured".to_owned(),
        }]
    } else {
        Vec::new()
    };
    let call_metadata = response.usage.call_metadata.as_ref();
    let record = ModelCallRecord {
        schema: MODEL_CALL_SCHEMA,
        attempt: run.instance(),
        lease_generation: u64::from(run.revision()),
        call_index: run.next_model_call_index(),
        kind: ModelCallKind::Generate {
            digests,
            usage: response.usage.clone(),
            finish_reason: response.finish_reason.clone(),
        },
        route,
        rung,
        issuing_login: None,
        organization: None,
        project: None,
        credential_id: None,
        response_id: call_metadata.and_then(|metadata| metadata.response_id.clone()),
        thread_id: None,
        previous_response_id: call_metadata
            .and_then(|metadata| metadata.previous_response_id.clone()),
        store: call_metadata.and_then(|metadata| metadata.store),
        endpoint: call_metadata.map(|metadata| metadata.endpoint),
        captured_at: vault.now_recorded_at(),
        receipt_ref: None,
        actor: run.principal(),
        produced_pending: false,
        tool_rounds: false,
        rounds_truncated: false,
        replay_of: None,
        source_rows,
        produced_rows: response
            .reply_assertions
            .created
            .iter()
            .map(|record| record.id)
            .collect(),
        input_parts,
        reasoning: response
            .message
            .content
            .iter()
            .filter_map(|part| ModelCallReasoningPart::from_terminal(part, None, None))
            .collect(),
        read_world_epoch: None,
        read_worlds: None,
        read_world_unknown: vec![ReadWorldUnknown::Uncaptured],
        tools_present: !request.tools.is_empty(),
        summary_requested: false,
        erased: false,
    };
    if let Err(error) =
        vault.with_write_txn_grouped(|txn| record_model_call_in_txn(vault, txn, &record))
    {
        tracing::warn!(%error, "model-call record failed");
    }
}

async fn generate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: axum::http::HeaderMap,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (ladder, run) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let session = super::call_receipt::request_session_ref(&headers).map(str::to_owned);
    let principal = super::call_receipt::request_principal(&auth);
    let no_record_at_arrival = server
        .vault()
        .model_call_keeps_no_record_for(session.as_deref(), principal);
    // The authenticated caller acted to start this call: the run names it
    // as initiator (attribution only), so its evidence row carries an
    // actor its erase can find. Owner-grade callers bind none, as before.
    let run = run.initiated_by(principal);
    // The caller's own connection is the raw call's deadline (FIX 8213).
    // generate_recorded_by takes the request by value; the record keeps its own copy.
    let record_request = request.clone();
    match ladder
        .generate_recorded_by(&run, request, None, &|| true, CallDeadline::Open)
        .await
    {
        Ok((response, binding)) => {
            let no_record = no_record_at_arrival
                || server
                    .vault()
                    .model_call_keeps_no_record_for(session.as_deref(), principal);
            record_raw_response(
                server.vault(),
                &ladder,
                &run,
                &record_request,
                &response,
                Some(&binding),
                no_record,
            );
            Json(response).into_response()
        }
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
    headers: axum::http::HeaderMap,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (ladder, run) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let session = super::call_receipt::request_session_ref(&headers).map(str::to_owned);
    let principal = super::call_receipt::request_principal(&auth);
    let no_record_at_arrival = server
        .vault()
        .model_call_keeps_no_record_for(session.as_deref(), principal);
    // Same initiator binding as the raw generate path above.
    let run = run.initiated_by(principal);
    // The first rung is admitted here, so a refused call answers before the
    // stream starts. Each rung settles itself; a stream the client leaves
    // ends its call, and a started rung keeps its reservation as spend.
    // stream_recorded_by takes the request by value; the record keeps its own copy.
    let record_request = request.clone();
    let (mut source, mut binding) =
        match ladder.stream_recorded_by(&run, request, None, CallDeadline::Open) {
            Ok(opened) => opened,
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
            // A completed call's evidence lands before its terminal line
            // goes out: a client gone at delivery still leaves its record.
            if done
                && let LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                    reply_assertions,
                    ..
                } = &event
            {
                let response = LlmResponse {
                    message: message.clone(),
                    usage: usage.clone(),
                    finish_reason: finish_reason.clone(),
                    reply_assertions: reply_assertions.clone(),
                    token_scores: None,
                };
                let no_record = no_record_at_arrival
                    || server
                        .vault()
                        .model_call_keeps_no_record_for(session.as_deref(), principal);
                // A recorded stream's exact answering binding travels beside
                // its answer (FIX 12743); a stream that ended any other way
                // leaves the route explicitly unknown, never a false pin.
                let binding = binding.try_recv().ok();
                record_raw_response(
                    server.vault(),
                    &ladder,
                    &run,
                    &record_request,
                    &response,
                    binding.as_ref(),
                    no_record,
                );
            }
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
        peer: oneiron::EntityId,
        mut request: LlmRequest,
    ) -> oneiron::LlmGenerateFuture<'static> {
        let server = Arc::clone(&self.0);
        Box::pin(async move {
            let (ladder, run) =
                admit_owner(&server, &mut request).map_err(|refused| refused_error(&refused))?;
            // The mesh peer is this call's authenticated principal, named
            // as the run's initiator for attribution. A mesh call binds no
            // session, so the vault's session no-record rule can never fire
            // for it and would silently leak off-record peer work into the
            // record: mesh calls record nothing until a verified no-record
            // context crosses the mesh with the call.
            let run = run.initiated_by(Some(peer));
            ladder
                .generate_by(&run, request, None, &|| true, CallDeadline::Open)
                .await
        })
    }

    fn stream(
        &self,
        _peer: oneiron::EntityId,
        mut request: LlmRequest,
    ) -> oneiron::LlmResult<oneiron::LlmStream<'static>> {
        let (ladder, run) =
            admit_owner(&self.0, &mut request).map_err(|refused| refused_error(&refused))?;
        ladder.stream_by(&run, request, None, CallDeadline::Open)
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
