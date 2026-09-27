//! Owner-authenticated raw inference. Host injection is explicit and absent by default.
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
use oneiron::{BudgetGuard, BudgetLease, LlmError, LlmRequest, LlmStreamEvent};
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/generate", post(generate))
        .route("/stream", post(stream))
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
fn failure(error: LlmError) -> Response {
    use oneiron::{FatalLlmError, RetryableLlmError};
    let (status, code) = match &error {
        LlmError::BudgetDenied(_) => (StatusCode::PAYMENT_REQUIRED, "budget_denied"),
        LlmError::Fatal(FatalLlmError::Auth) => (StatusCode::UNAUTHORIZED, "auth"),
        LlmError::Fatal(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => {
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        }
        LlmError::Retryable(RetryableLlmError::Timeout) => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        LlmError::Retryable(_) => (StatusCode::BAD_GATEWAY, "stream_cut"),
    };
    (
        status,
        Json(serde_json::json!({"error":{"code":code,"llm":error}})),
    )
        .into_response()
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
    if table.purposes[&oneiron::CallPurpose::Extraction].locality
        != oneiron::ModelLocality::OnDevice
        && server.extraction_egress.is_none()
    {
        return refusal(StatusCode::BAD_REQUEST, "extraction_egress_unavailable");
    }
    match server.vault.set_purpose_default_table(&table) {
        Ok(()) => Json(table).into_response(),
        Err(oneiron::Error::InvalidConfig(_)) => {
            refusal(StatusCode::BAD_REQUEST, "invalid_defaults")
        }
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

struct Reservation {
    guard: BudgetGuard,
    lease: BudgetLease,
    started: bool,
}
impl Reservation {
    fn settle_terminal(&self, usage: &oneiron::LlmUsage) -> Result<(), oneiron::llm::BudgetDenied> {
        // Providers can omit usage even after producing content. Zero totals are
        // not proof of a free call; retain the same conservative charge as drop.
        if usage.input.total == 0 && usage.output.total == 0 {
            self.guard.settle_reserved(&self.lease).map(|_| ())
        } else {
            self.guard.settle_per_call(&self.lease, usage).map(|_| ())
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.started {
            let _ = self.guard.settle_reserved(&self.lease);
        } else {
            let _ = self.guard.abort(&self.lease);
        }
    }
}
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    request: &mut LlmRequest,
) -> Result<(Arc<dyn oneiron::LlmBackend>, Reservation), Box<Response>> {
    if !auth.is_owner_grade() {
        return Err(Box::new(refusal(StatusCode::FORBIDDEN, "owner_required")));
    }
    let Some((backend, guard)) = &server.llm else {
        return Err(Box::new(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "llm_unavailable",
        )));
    };
    let row = server
        .vault
        .model_registry_row(&request.model)
        .map_err(|_| {
            Box::new(refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "catalog_unavailable",
            ))
        })?
        .ok_or_else(|| Box::new(refusal(StatusCode::BAD_REQUEST, "unknown_model")))?;
    request.envelope.locality = row.catalog.locality;
    if request.envelope.purpose == oneiron::CallPurpose::Extraction
        && request.envelope.locality != oneiron::ModelLocality::OnDevice
    {
        let policy = server.vault.purpose_default_table().map_err(|_| {
            Box::new(refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "defaults_unavailable",
            ))
        })?;
        let allowed = oneiron::llm::locality_within_extraction_bound(
            request.envelope.locality,
            policy.extraction_max_locality,
        );
        if !allowed
            || !server
                .extraction_egress
                .as_ref()
                .is_some_and(|predicate| predicate.permits(request))
        {
            return Err(Box::new(refusal(
                StatusCode::FORBIDDEN,
                "extraction_egress_denied",
            )));
        }
    }
    let admission = guard
        .admit_for_request(request)
        .map_err(|e| Box::new(failure(e.into())))?;
    Ok((
        backend.clone(),
        Reservation {
            guard: guard.clone(),
            lease: admission.lease,
            started: false,
        },
    ))
}
async fn generate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (backend, mut reservation) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    reservation.started = true;
    match backend.generate(request, &reservation.lease).await {
        Ok(response) => {
            if let Err(e) = reservation.settle_terminal(&response.usage) {
                return failure(e.into());
            }
            Json(response).into_response()
        }
        Err(e) => failure(e),
    }
}
async fn send_error(
    send: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    error: LlmError,
) {
    let mut bytes = serde_json::to_vec(&serde_json::json!({"error":{"llm":error}}))
        .expect("LLM error serializes");
    bytes.push(b'\n');
    let _ = send.send(Ok(bytes)).await;
}
async fn stream(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(mut request): Json<LlmRequest>,
) -> Response {
    let (backend, mut reservation) = match admit(&server, &auth, &mut request) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (send, receive) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
    tokio::spawn(async move {
        let mut source = match backend.stream(request, &reservation.lease) {
            Ok(source) => source,
            Err(error) => {
                send_error(&send, error).await;
                return;
            }
        };
        reservation.started = true;
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
            let done = if let LlmStreamEvent::Done { usage, .. } = &event {
                if let Err(error) = reservation.settle_terminal(usage) {
                    send_error(&send, error.into()).await;
                    return;
                }
                true
            } else {
                false
            };
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
