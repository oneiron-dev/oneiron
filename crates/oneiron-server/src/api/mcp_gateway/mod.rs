//! The MCP gateway: its module registrations and the names its children share.
//! `mcp_gateway`, `execute_mcp_tool` and `execute_mcp_setup` are its re-exported call surface.
//! Each child module defines its own records; `crate::mcp` owns the MCP wire types.
mod actions;
mod actor_dispatch;
mod admission;
mod board_observations;
mod board_setup;
mod booking_call;
mod call_meta;
mod claimed_release;
mod code_mode_verbs;
mod device_release;
mod envelope;
mod exec_board_verbs;
mod facade_refusals;
mod memory_response;
mod owner_call;
mod question_answers_result;
mod served_rows;
pub(crate) mod skill_execution;
mod stream_reads;
mod tasks_response;
mod tool_receipt;
mod type_feedback_release;
mod verb_hooks;
mod wakes;
mod wire;

pub(crate) use self::actor_dispatch::{
    ensure_mcp_actor_matches, execute_mcp_tool, mcp_params, mcp_tool_validation_error,
    resolve_mcp_actor_for_auth, resolve_mcp_gateway_actor,
};
pub(crate) use self::admission::mcp_admit_scoped_call;
use self::admission::{
    mcp_credential_reads, mcp_scope_covers_entity, mcp_scoped_tasks_section,
    mcp_validated_call_args,
};
pub(crate) use self::board_observations::run_session_reads;
pub(crate) use self::board_setup::{McpBoardOmissions, execute_mcp_setup, ride_run_carrier};
use self::board_setup::{
    McpBoardState, McpCarrierPolicy, mcp_board_frame_error, mcp_board_verb_error,
    mcp_current_board, mcp_endpoint_result, mcp_page_cursor_error, mcp_preflight_page,
    mcp_resolve_page,
};
pub(crate) use self::code_mode_verbs::{
    ReaderChildDoor, RunGuests, VerdictAsker, count_hook_decisions,
};
// L09's resident_pump `run_bound` calls the strict preflight (CUA E4).
pub(crate) use self::code_mode_verbs::{WorkflowPreflight, preflight_task_workflow};
#[cfg(test)]
pub(crate) use self::device_release::release_hook;
use self::device_release::{mcp_release_listed, mcp_release_result};
use self::envelope::mcp_request_id;
pub(crate) use self::envelope::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, McpToolCallParams, mcp_gateway,
    mcp_tool_first_gateway,
};
pub(crate) use self::exec_board_verbs::{
    deliver_run_board_hooks, drop_run_board, execute_mcp_execute_code, execute_mcp_read_result,
    execute_run_board_verb,
};
use self::exec_board_verbs::{execute_mcp_board_verb, mcp_verb_family_error};
pub(crate) use self::owner_call::resolve_mcp_caller;
use self::served_rows::McpServed;
pub(crate) use self::stream_reads::{mcp_stream_reads_task, mcp_stream_task_row};
// Test-only surface: `api/tests.rs` names these bare through the `api` glob,
// but no production path does, so a plain `pub(crate)` re-export would warn as
// unused in non-test builds.
#[cfg(test)]
pub(crate) use self::envelope::MCP_PROTOCOL_VERSION;
pub(crate) use self::facade_refusals::mcp_facade_error;
pub(crate) use self::tasks_response::{
    execute_mcp_generated_verb, mcp_actor_class_wire, mcp_actor_result, mcp_api_error,
    mcp_engine_error, mcp_error_response, mcp_scoped_read, mcp_text_content,
};
use super::hex_bytes;
