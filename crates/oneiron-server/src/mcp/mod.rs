//! MCP connector actor registry.
//!
//! The registry is deliberately not an authority carrier. It resolves an
//! external connector credential to the actor identity and scope that the MCP
//! gateway should attach to the existing vault write path. Approval authority
//! remains in Gate `actor_ceilings` policy rows.

mod actors;
mod args;
mod codec;
mod endpoint_args;
mod endpoint_schema;
mod exec_host;
mod paging;
mod registry;
mod results;
mod schema_parts;
mod schema_tools;
mod surface;
mod tool_catalog;
mod validate;
mod validators;

pub use self::actors::{
    McpBoardSnapshot, McpConnectorActorRecord, McpConnectorActorRegistrationError,
    McpConnectorActorResolutionError, McpConnectorActorRevokeStatus, McpConnectorScope,
    McpCredentialHashKey, McpResolvedActor, mcp_board_state_hash,
};
pub use self::args::{
    McpActorClass, McpActorMetadata, McpAskEffort, McpAskRoute, McpAskToolArgs, McpBookOperation,
    McpBookToolArgs, McpCalendarOperation, McpCalendarRange, McpCalendarSelector,
    McpCalendarToolArgs, McpCitationMode, McpConsentMetadata, McpEditEdgeSubject, McpEditSubject,
    McpEditToolArgs, McpEditVerb, McpNavMode, McpNavToolArgs, McpOccurredRange, McpReadTarget,
    McpReadToolArgs, McpRoutedAskToolArgs, McpToolScope,
};
pub use self::codec::McpToolArguments;
pub(crate) use self::codec::mcp_raw_call_arguments;
pub use self::endpoint_args::{
    MCP_CODE_TASK_MAX_CHARS, MCP_TASK_LABEL_MAX_BYTES, McpCacheHint, McpExecuteCodeToolArgs,
    McpPageRequest, McpSetupToolArgs, McpSubscriptionScope, McpVerbArguments, McpVerbToolArgs,
    McpVerbToolPayload, validate_mcp_endpoint_tool_args,
};
pub use self::endpoint_schema::{
    MCP_BOARD_BUDGET_TOK_MAX, MCP_CACHE_TTL_MS_MAX, MCP_FRAME_EPOCH_MAX, MCP_PAGE_LIMIT_MAX,
    MCP_PAGE_LIMIT_MIN,
};
pub use self::exec_host::{
    McpCodeExecutionError, McpCodeExecutionHost, McpCodeExecutionRequest, McpCodeModeProvider,
    McpEngineNativeCodeHost, bind_mcp_code_execution_host, mcp_code_execution_host,
    mcp_code_run_id, mcp_scoped_identity_id,
};
pub use self::paging::{
    MCP_PAGE_CURSOR_INVALID_CODE, McpPageBudget, McpPageCursorError, McpPageSource, McpResultEnd,
    McpRetrievalHealth, clamp_foreign_cache_ttl_ms, mcp_canonical_json, mcp_page_argument_digest,
};
pub(crate) use self::paging::{McpPageCursorState, McpPageSnapshot};
pub use self::registry::McpConnectorActorRegistry;
pub use self::results::{
    McpBoardKeyframe, McpResultMetadata, McpSetupPayload, McpSetupPayloadError,
    mcp_effective_scope_label, mcp_effective_scope_value, mcp_recovery_suggestions,
    mcp_setup_payload, mcp_verb_board_section,
};
pub(crate) use self::schema_tools::{
    booking_availability_input_schema, booking_book_input_schema, booking_cancel_input_schema,
    booking_reschedule_input_schema,
};
pub use self::surface::{
    MCP_BOARD_BUDGET_TOK, MCP_CODE_RUN_SCHEMA_VERSION, MCP_EXECUTE_CODE_TOOL,
    MCP_EXECUTE_CODE_UNAVAILABLE_CODE, MCP_MAX_LIVE_PAGE_CONTINUATIONS, MCP_PAGE_ITEM_CAP,
    MCP_RESULT_CACHE_SCOPE, MCP_RESULT_META_SCHEMA_VERSION, MCP_RESULT_TTL_MS,
    MCP_SETUP_INSTRUCTIONS, MCP_SETUP_TOOL, MCP_STREAM_CONNECTION_PREFIX,
    MCP_VERB_GRAMMAR_SCHEMA_VERSION, McpEndpointTool, McpEndpointToolSchema, McpGeneratedVerbTool,
    McpRegisteredSurface, McpSurfaceConstructionError, McpSurfaceMode, McpVerbBinding,
    McpVerbFamily, exported_verb_rows, generated_verb_tools, project_verb_rows, registered_surface,
};
pub use self::tool_catalog::{
    MCP_BOOK_OPERATIONS, MCP_CALENDAR_OPERATIONS, MCP_SERVER_NAME, MCP_TOOL_ARGS_SCHEMA_VERSION,
    McpToolName, McpToolSchema, McpToolValidationError, McpValidatedToolArgs, mcp_tool_schema,
    mcp_tool_schemas, validate_mcp_tool_args,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{codec::*, endpoint_args::*, schema_parts::*, schema_tools::*, tool_catalog::*};

#[cfg(test)]
use oneiron::context_board::{BoardBlockHeader, BoardBudgetRequest, StreamConnectionId};
#[cfg(test)]
use oneiron::context_pack::MCP_CONTEXT_PACK_REF_SCHEMA_VERSION;
#[cfg(test)]
use oneiron::{EdgeActorClass, EntityId, WriteActor};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
