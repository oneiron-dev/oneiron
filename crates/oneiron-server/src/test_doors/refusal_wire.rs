//! Door for tests/check_in_pending_block_wire.rs and
//! tests/task_assignment_conflict_wire.rs: a MemoryError as the facade and
//! the MCP gateway answer it, and an engine error as a facade route's direct
//! engine-to-ApiError mapping answers it.

use axum::response::IntoResponse;

/// The status and the JSON body the facade route answers for this refusal:
/// the real `From<MemoryError>` conversion with its status match, through
/// the real `into_response`, whose body bytes are parsed as JSON. Async
/// because reading an axum body is; no facade visibility was widened for it.
pub async fn facade_refusal(error: oneiron::MemoryError) -> (u16, serde_json::Value) {
    status_and_body(crate::api::FacadeApiError::from(error).into_response()).await
}

/// The status and the JSON body a facade route answers for this engine
/// error through the direct engine-to-ApiError mapping, as the action route
/// answers it: the real `core_engine_error`, the real `From<ApiError>`
/// conversion and the real `into_response`.
pub async fn engine_refusal(error: oneiron::Error) -> (u16, serde_json::Value) {
    let refusal = crate::api::core_engine_error_for_test("engine refusal", error);
    status_and_body(crate::api::FacadeApiError::from(refusal).into_response()).await
}

async fn status_and_body(response: axum::response::Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a facade refusal body reads");
    let json = serde_json::from_slice(&body).expect("a facade refusal body is JSON");
    (status, json)
}

/// The JSON-RPC error reply the MCP gateway answers for this refusal.
#[must_use]
pub fn mcp_refusal(error: oneiron::MemoryError) -> serde_json::Value {
    crate::api::mcp_error_response(serde_json::json!(1), crate::api::mcp_facade_error(error))
}
