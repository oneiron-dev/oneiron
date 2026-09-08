//! Retired MCP tool catalog: legacy names, schemas, and validation dispatch.

use super::args::{
    McpAskToolArgs, McpBookToolArgs, McpCalendarToolArgs, McpEditToolArgs, McpNavToolArgs,
    McpReadToolArgs, McpRoutedAskToolArgs,
};
use super::codec::{McpToolArguments, decode_tool_args};
use super::endpoint_args::{McpExecuteCodeToolArgs, McpSetupToolArgs, McpVerbToolArgs};
use super::schema_tools::{
    ask_tool_schema, book_tool_schema, calendar_tool_schema, edit_tool_schema, nav_tool_schema,
    read_tool_schema, routed_ask_tool_schema,
};
use serde::Serialize;
use serde_json::Value;

pub const MCP_TOOL_ARGS_SCHEMA_VERSION: &str = "mcp_tool_args.v1";

pub(super) const MCP_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

pub(super) const ENTITY_ID_PATTERN: &str = "^[0-9a-f]{32}$";

/// JSON-schema spelling of the engine's short-ref grammar, advertised to MCP
/// clients.
///
/// `{2,}` — not `{2}` — because prefix LENGTH is a registry fact and this schema
/// is not the registry (ONE-1930). A pattern pinned at exactly two letters would
/// advertise a narrower grammar than `validate_short_ref_parts` enforces, and
/// clients would pre-reject ids the server accepts. The floor of two is the same
/// one `oneiron::entity_id::MIN_PRESENTATION_PREFIX_LEN` carries, and
/// `short_ref_schema_pattern_matches_the_validator` pins the two together.
pub(super) const SHORT_REF_PATTERN: &str = "^[a-z]{2,}[0-9]+:[0-9A-Fa-f]{2}$";

pub(super) const EDIT_ACTION_FIELDS: &[&str] = &[
    "subject",
    "predicate",
    "value",
    "confidence",
    "evidence",
    "valid_from",
    "valid_to",
    "salience",
    "world",
    "scope",
    "old_claim_id",
    "claim_id",
    "reason",
    "explanation",
    "entity_type",
    "occurred",
    "data",
    "initial_claims",
    "brief",
    "job_id",
    "outcome",
    "summary",
    "result_claims",
    "channel",
    "payload",
    "supersession_status",
    "source_revision_ref",
    "body_snapshot_ref",
    "reasoning_effort",
];

/// Closed operation set of the `oneiron.calendar` tool (CAL-09).
///
/// One tool with a schema-validated `op` discriminator keeps the catalog
/// closed-ish: the calendar surface grows operations, never tool names.
pub const MCP_CALENDAR_OPERATIONS: &[&str] = &["read", "search", "freebusy", "invite"];

/// Closed operation set of the `oneiron.book` tool (BK-08).
///
/// The same one-tool/op-enum discipline `oneiron.calendar` established: the
/// booking surface grows operations, never tool names. The order is the
/// instructions block's canonical order, so discovery, `tools/list`, and the
/// embedded block advertise the four ops identically.
pub const MCP_BOOK_OPERATIONS: &[&str] = &["availability", "book", "reschedule", "cancel"];

/// The MCP server name this daemon announces.
///
/// One constant so the `initialize` handshake and the server axis a
/// scoped-MCP grant is checked against cannot drift apart.
pub const MCP_SERVER_NAME: &str = "oneiron";

/// The RETIRED plain-verb catalog (ONE-1704 M1).
///
/// These seven names are no longer a wire surface. Neither registered endpoint
/// lists them and `tools/call` cannot resolve them on either endpoint: name
/// resolution goes through [`McpRegisteredSurface::resolve`] and nothing else,
/// so every one of them answers `unknown_tool`. What survives here is a private
/// argument/schema catalog plus the executor bodies the shared gated vault API
/// still reaches internally — a library, not a callable second surface, and not
/// a migration fallback. Nothing re-adds a wire name for them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpToolName {
    Nav,
    Read,
    Edit,
    Ask,
    RoutedAsk,
    Calendar,
    Book,
}

impl McpToolName {
    const ALL: [Self; 7] = [
        Self::Nav,
        Self::Read,
        Self::Edit,
        Self::Ask,
        Self::RoutedAsk,
        Self::Calendar,
        Self::Book,
    ];

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &Self::ALL
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nav => "oneiron.nav",
            Self::Read => "oneiron.read",
            Self::Edit => "oneiron.edit",
            Self::Ask => "oneiron.ask",
            Self::RoutedAsk => "oneiron.ask_routed",
            Self::Calendar => "oneiron.calendar",
            Self::Book => "oneiron.book",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "oneiron.nav" => Some(Self::Nav),
            "oneiron.read" => Some(Self::Read),
            "oneiron.edit" => Some(Self::Edit),
            "oneiron.ask" => Some(Self::Ask),
            "oneiron.ask_routed" => Some(Self::RoutedAsk),
            "oneiron.calendar" => Some(Self::Calendar),
            "oneiron.book" => Some(Self::Book),
            _ => None,
        }
    }

    /// Operation discriminators this tool accepts, empty for tools that carry
    /// no `op` field.
    #[must_use]
    pub const fn operations(self) -> &'static [&'static str] {
        match self {
            Self::Calendar => MCP_CALENDAR_OPERATIONS,
            Self::Book => MCP_BOOK_OPERATIONS,
            _ => &[],
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Nav => "Navigate the Oneiron plain verb surface without mutating the vault.",
            Self::Read => "Read one resolved Oneiron entity, short ref, or context-pack reference.",
            Self::Edit => "Validate a named Oneiron memory edit verb before any vault mutation.",
            Self::Ask => {
                "Ask over a supplied context pack while preserving actor and consent metadata."
            }
            Self::RoutedAsk => {
                "Ask over a supplied context pack with explicit foreign-client routing metadata."
            }
            Self::Calendar => {
                "Read, search, or project busy time over Oneiron calendar EVENTs, or schedule one calendar invite through the outbound gate."
            }
            Self::Book => {
                "List a booking page's public slots, hold and confirm a booking, or reschedule or cancel one, addressing the page and the booking only by opaque token."
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct McpToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[must_use]
pub fn mcp_tool_schemas() -> Vec<McpToolSchema> {
    McpToolName::all()
        .iter()
        .copied()
        .map(mcp_tool_schema)
        .collect()
}

#[must_use]
pub fn mcp_tool_schema(tool: McpToolName) -> McpToolSchema {
    let input_schema = match tool {
        McpToolName::Nav => nav_tool_schema(),
        McpToolName::Read => read_tool_schema(),
        McpToolName::Edit => edit_tool_schema(),
        McpToolName::Ask => ask_tool_schema(),
        McpToolName::RoutedAsk => routed_ask_tool_schema(),
        McpToolName::Calendar => calendar_tool_schema(),
        McpToolName::Book => book_tool_schema(),
    };

    McpToolSchema {
        name: tool.as_str(),
        description: tool.description(),
        input_schema,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "tool", content = "args", rename_all = "snake_case")]
pub enum McpValidatedToolArgs {
    Nav(McpNavToolArgs),
    Read(McpReadToolArgs),
    Edit(Box<McpEditToolArgs>),
    Ask(McpAskToolArgs),
    RoutedAsk(McpRoutedAskToolArgs),
    Calendar(McpCalendarToolArgs),
    Book(Box<McpBookToolArgs>),
    /// ONE-1704 primary endpoint: the one setup call.
    Setup(Box<McpSetupToolArgs>),
    /// ONE-1704 primary endpoint: the REPL against the same gated vault API.
    ExecuteCode(Box<McpExecuteCodeToolArgs>),
    /// ONE-1704 tool-first endpoint: one GENERATED tool per exported verb row.
    Verb(Box<McpVerbToolArgs>),
}

pub fn validate_mcp_tool_args(
    tool: McpToolName,
    args: impl Into<McpToolArguments>,
) -> Result<McpValidatedToolArgs, McpToolValidationError> {
    let args = args.into();
    match tool {
        McpToolName::Nav => {
            decode_tool_args::<McpNavToolArgs>(tool, args).map(McpValidatedToolArgs::Nav)
        }
        McpToolName::Read => {
            decode_tool_args::<McpReadToolArgs>(tool, args).map(McpValidatedToolArgs::Read)
        }
        McpToolName::Edit => decode_tool_args::<McpEditToolArgs>(tool, args)
            .map(Box::new)
            .map(McpValidatedToolArgs::Edit),
        McpToolName::Ask => {
            decode_tool_args::<McpAskToolArgs>(tool, args).map(McpValidatedToolArgs::Ask)
        }
        McpToolName::RoutedAsk => decode_tool_args::<McpRoutedAskToolArgs>(tool, args)
            .map(McpValidatedToolArgs::RoutedAsk),
        McpToolName::Calendar => {
            decode_tool_args::<McpCalendarToolArgs>(tool, args).map(McpValidatedToolArgs::Calendar)
        }
        McpToolName::Book => decode_tool_args::<McpBookToolArgs>(tool, args)
            .map(Box::new)
            .map(McpValidatedToolArgs::Book),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpToolValidationError {
    #[error("{tool} args are not valid for the tool schema: {message}")]
    Decode { tool: &'static str, message: String },
    #[error("{tool}.{field}: {message}")]
    Field {
        tool: &'static str,
        field: &'static str,
        message: String,
    },
}

/// Anything that can name the tool a validation failure belongs to.
///
/// The legacy plain-verb catalog names itself through [`McpToolName`]; an
/// endpoint-registered tool (ONE-1704) is already a `&'static str` because its
/// name comes from the exported verb row or an endpoint constant. One trait so
/// both reach the SAME validators instead of growing a second copy of the
/// entity-ref, blankness, and envelope rules.
pub(super) trait McpToolLabel: Copy {
    fn tool_label(self) -> &'static str;
}

impl McpToolLabel for McpToolName {
    fn tool_label(self) -> &'static str {
        self.as_str()
    }
}

impl McpToolLabel for &'static str {
    fn tool_label(self) -> &'static str {
        self
    }
}

impl McpToolValidationError {
    pub(super) fn field(
        tool: impl McpToolLabel,
        field: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self::Field {
            tool: tool.tool_label(),
            field,
            message: message.into(),
        }
    }
}
