//! Door for `tests/mcp_facade_refusal_registry.rs` (UC-11): the JSON-RPC
//! number and stable kind the MCP gateway answers an engine refusal code
//! with, through `mcp_facade_error`, so one test pins every row of the
//! gateway's refusal vocabulary without a fixture per code.

/// The JSON-RPC number and stable kind a gateway tool call answers a facade
/// refusal whose code is `code` with.
#[must_use]
pub fn mcp_refusal(code: &str) -> (i64, &'static str) {
    crate::api::mcp_refusal_for_test(code)
}
