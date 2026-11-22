//! Door for tests/check_in_pending_block_wire.rs: a MemoryError as the facade
//! and the MCP gateway answer it.

use axum::response::IntoResponse;

/// The status and the JSON body the facade route answers for this refusal:
/// the real `From<MemoryError>` conversion with its status match, through
/// the real `into_response`, whose body bytes are parsed as JSON. Async
/// because reading an axum body is; no facade visibility was widened for it.
pub async fn facade_refusal(error: oneiron::MemoryError) -> (u16, serde_json::Value) {
    let response = crate::api::FacadeApiError::from(error).into_response();
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
