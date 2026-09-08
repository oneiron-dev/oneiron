mod actor_dispatch;
mod admission;
mod board_setup;
mod envelope;
mod exec_board_verbs;
mod facade_verbs;
mod tasks_response;

pub(crate) use self::actor_dispatch::{
    ensure_mcp_actor_matches, execute_mcp_tool, mcp_params, mcp_tool_validation_error,
    resolve_mcp_gateway_actor,
};
pub(crate) use self::admission::mcp_admit_scoped_call;
use self::admission::{mcp_scope_covers_entity, mcp_validated_call_args};
pub(crate) use self::board_setup::{McpBoardOmissions, execute_mcp_setup};
use self::board_setup::{
    McpBoardState, McpCarrierPolicy, mcp_board_frame_error, mcp_board_verb_error,
    mcp_current_board, mcp_endpoint_result, mcp_page_cursor_error, mcp_preflight_page,
    mcp_resolve_page, mcp_scoped_tasks_section,
};
use self::envelope::mcp_request_id;
pub(crate) use self::envelope::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, McpToolCallParams, mcp_gateway,
    mcp_tool_first_gateway,
};
pub(crate) use self::exec_board_verbs::execute_mcp_execute_code;
use self::exec_board_verbs::{execute_mcp_board_verb, mcp_verb_family_error};
// Test-only surface: `api/tests.rs` names these bare through the `api` glob,
// but no production path does, so a plain `pub(crate)` re-export would warn as
// unused in non-test builds.
#[cfg(test)]
pub(crate) use self::envelope::MCP_PROTOCOL_VERSION;
#[cfg(test)]
pub(crate) use self::exec_board_verbs::mcp_board_verb_page_source;
// Forwards for the `super::booking` / `super::hex_bytes` paths the moved bodies
// already used: one level down, `super` is this module, so it re-exports them.
pub(crate) use self::facade_verbs::{
    execute_mcp_calendar, execute_mcp_edit, execute_mcp_nav, execute_mcp_read, mcp_ask_result,
    mcp_facade_error, mcp_routed_ask_result,
};
pub(crate) use self::tasks_response::{
    execute_mcp_generated_verb, mcp_actor_class_wire, mcp_actor_result, mcp_api_error,
    mcp_engine_error, mcp_error_response, mcp_scoped_read, mcp_text_content,
};
use super::{booking, hex_bytes};
