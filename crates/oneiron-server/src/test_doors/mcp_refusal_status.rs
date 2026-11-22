//! Door for `tests/mcp_facade_refusal_registry.rs` (UC-11): the JSON-RPC
//! number and stable kind the MCP gateway answers an engine refusal code
//! with, through `mcp_facade_error`, so one test pins every row of the
//! gateway's refusal vocabulary without a fixture per code. A second door
//! gives the answer a raw engine error gets, through `mcp_engine_error`.

/// The JSON-RPC number and stable kind a gateway tool call answers a facade
/// refusal whose code is `code` with.
#[must_use]
pub fn mcp_refusal(code: &str) -> (i64, &'static str) {
    crate::api::mcp_refusal_for_test(code)
}

/// The JSON-RPC number, stable kind and reason codes a gateway tool call
/// answers a raw engine error with.
#[must_use]
pub fn mcp_engine_refusal(error: oneiron::Error) -> (i64, &'static str, Vec<String>) {
    crate::api::mcp_engine_refusal_for_test(error)
}
