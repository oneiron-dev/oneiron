//! MCP connector actor registry.
//!
//! The registry is deliberately not an authority carrier. It resolves an
//! external connector credential to the actor identity and scope that the MCP
//! gateway should attach to the existing vault write path. Approval authority
//! remains in Gate `actor_ceilings` policy rows.

use std::{collections::BTreeMap, fmt};

use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, WriteActor,
    context_pack::{MCP_CONTEXT_PACK_REF_SCHEMA_VERSION, McpContextPackRef},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub const MCP_TOOL_ARGS_SCHEMA_VERSION: &str = "mcp_tool_args.v1";
const MCP_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const ENTITY_ID_PATTERN: &str = "^[0-9a-f]{32}$";
/// JSON-schema spelling of the engine's short-ref grammar, advertised to MCP
/// clients.
///
/// `{2,}` — not `{2}` — because prefix LENGTH is a registry fact and this schema
/// is not the registry (ONE-1930). A pattern pinned at exactly two letters would
/// advertise a narrower grammar than `validate_short_ref_parts` enforces, and
/// clients would pre-reject ids the server accepts. The floor of two is the same
/// one `oneiron::MIN_PRESENTATION_PREFIX_LEN` carries, and
/// `short_ref_schema_pattern_matches_the_validator` pins the two together.
const SHORT_REF_PATTERN: &str = "^[a-z]{2,}[0-9]+:[0-9A-Fa-f]{2}$";
const EDIT_ACTION_FIELDS: &[&str] = &[
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
/// The same discipline `oneiron.calendar` established: one tool with a
/// schema-validated `op` discriminator, so the booking surface grows
/// operations and never tool names. Every operation runs behind ONE-1817's
/// caps inside the shared server executor.
pub const MCP_BOOK_OPERATIONS: &[&str] = &["availability", "book", "reschedule", "cancel"];

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
                "Read availability, hold and confirm, reschedule, or cancel a booking on one Oneiron booking page through its opaque page token."
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
    Book(McpBookToolArgs),
}

pub fn validate_mcp_tool_args(
    tool: McpToolName,
    args: Value,
) -> Result<McpValidatedToolArgs, McpToolValidationError> {
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
        McpToolName::Book => {
            decode_tool_args::<McpBookToolArgs>(tool, args).map(McpValidatedToolArgs::Book)
        }
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

impl McpToolValidationError {
    fn field(tool: McpToolName, field: &'static str, message: impl Into<String>) -> Self {
        Self::Field {
            tool: tool.as_str(),
            field,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpNavToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub mode: McpNavMode,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub context_pack: Option<McpContextPackRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpNavMode {
    Search,
    Timeline,
    List,
    Hydrate,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpReadToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub target: McpReadTarget,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpReadTarget {
    #[serde(default)]
    pub entity_ref: Option<String>,
    #[serde(default)]
    pub short_ref: Option<String>,
    #[serde(default)]
    pub context_pack: Option<McpContextPackRef>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpEditToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub verb: McpEditVerb,
    pub idempotency_key: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub subject: Option<McpEditSubject>,
    #[serde(default)]
    pub predicate: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub evidence: Option<Value>,
    #[serde(default)]
    pub valid_from: Option<u64>,
    #[serde(default)]
    pub valid_to: Option<u64>,
    #[serde(default)]
    pub salience: Option<f32>,
    #[serde(default)]
    pub world: Option<String>,
    #[serde(default)]
    pub scope: Option<Value>,
    #[serde(default)]
    pub old_claim_id: Option<String>,
    #[serde(default)]
    pub claim_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub entity_type: Option<u8>,
    #[serde(default)]
    pub occurred: Option<McpOccurredRange>,
    #[serde(default)]
    pub data: Option<Value>,
    #[serde(default)]
    pub initial_claims: Option<Vec<Value>>,
    #[serde(default)]
    pub brief: Option<Value>,
    #[serde(default, rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub result_claims: Option<Vec<Value>>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub supersession_status: Option<String>,
    #[serde(default)]
    pub source_revision_ref: Option<String>,
    #[serde(default)]
    pub body_snapshot_ref: Option<String>,
    #[serde(default)]
    pub reasoning_effort: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpEditVerb {
    ProposeClaim,
    AttestEdgeProvenance,
    SupersedeClaim,
    RetractClaim,
    ProposeEntity,
    PostTask,
    ReportTask,
    ChannelSend,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpEditSubject {
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub edge: Option<McpEditEdgeSubject>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpEditEdgeSubject {
    pub source: String,
    pub kind: u8,
    pub target: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpOccurredRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpAskToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub context_pack: McpContextPackRef,
    pub consent: McpConsentMetadata,
    pub query: String,
    #[serde(default)]
    pub effort: Option<McpAskEffort>,
    #[serde(default)]
    pub citation_mode: Option<McpCitationMode>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpRoutedAskToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub context_pack: McpContextPackRef,
    pub consent: McpConsentMetadata,
    pub query: String,
    pub route: McpAskRoute,
    #[serde(default)]
    pub effort: Option<McpAskEffort>,
    #[serde(default)]
    pub citation_mode: Option<McpCitationMode>,
}

/// `oneiron.calendar` arguments.
///
/// The actor/consent envelope is the same one every tool carries; the calendar
/// vocabulary lives entirely inside [`McpCalendarOperation`], so the catalog
/// grows one tool rather than four.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCalendarToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub operation: McpCalendarOperation,
}

/// The closed `read|search|freebusy|invite` operation set.
///
/// Each arm is independently closed: a field that belongs to another operation
/// is a validation failure, not an ignored extra.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpCalendarOperation {
    Read {
        event_ref: String,
    },
    Search {
        #[serde(default)]
        calendars: Vec<McpCalendarSelector>,
        #[serde(default)]
        range: Option<McpCalendarRange>,
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    Freebusy {
        #[serde(default)]
        calendars: Vec<McpCalendarSelector>,
        range: McpCalendarRange,
    },
    /// C7's exact typed payload — never an outbound draft.
    Invite {
        method: oneiron::CalendarInviteSurfaceMethod,
        uid: String,
        sequence: u32,
        ics_blob_ref: String,
        recipient: String,
    },
}

impl McpCalendarOperation {
    /// The wire discriminator for this arm.
    #[must_use]
    pub const fn op(&self) -> &'static str {
        match self {
            Self::Read { .. } => "read",
            Self::Search { .. } => "search",
            Self::Freebusy { .. } => "freebusy",
            Self::Invite { .. } => "invite",
        }
    }
}

/// `oneiron.book` arguments (BK-08).
///
/// Same envelope every tool carries — schema version, actor, consent — with the
/// whole booking vocabulary inside [`McpBookOperation`], so the catalog grows
/// one tool rather than four. The operation payloads are ONE-1819's engine
/// DTOs verbatim: this file validates them, it does not redefine them.
///
/// A booking page is addressed ONLY by its opaque `page_token`. There is no
/// field an internal page or booking `EntityId` could travel in.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpBookToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub operation: McpBookOperation,
}

/// The closed `availability|book|reschedule|cancel` operation set.
///
/// Each arm is independently closed: a field belonging to another operation is
/// a validation failure, not an ignored extra.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpBookOperation {
    Availability {
        page_token: String,
        input: oneiron::booking::agent_api::BookingAvailabilityInput,
    },
    Book {
        page_token: String,
        input: oneiron::booking::agent_api::BookingBookInput,
    },
    Reschedule {
        page_token: String,
        input: oneiron::booking::agent_api::BookingRescheduleInput,
    },
    Cancel {
        page_token: String,
        input: oneiron::booking::agent_api::BookingCancelInput,
    },
}

impl McpBookToolArgs {
    /// The connector actor this call asserts. The gateway compares it against
    /// the authenticated credential before anything executes.
    #[must_use]
    pub const fn actor(&self) -> &McpActorMetadata {
        &self.actor
    }

    /// Which booking operation this call is.
    #[must_use]
    pub const fn operation(&self) -> oneiron::booking::agent_api::BookingAgentOperation {
        use oneiron::booking::agent_api::BookingAgentOperation;
        match self.operation {
            McpBookOperation::Availability { .. } => BookingAgentOperation::Availability,
            McpBookOperation::Book { .. } => BookingAgentOperation::Book,
            McpBookOperation::Reschedule { .. } => BookingAgentOperation::Reschedule,
            McpBookOperation::Cancel { .. } => BookingAgentOperation::Cancel,
        }
    }

    /// The opaque page token this call addresses.
    #[must_use]
    pub fn page_token(&self) -> &str {
        match &self.operation {
            McpBookOperation::Availability { page_token, .. }
            | McpBookOperation::Book { page_token, .. }
            | McpBookOperation::Reschedule { page_token, .. }
            | McpBookOperation::Cancel { page_token, .. } => page_token,
        }
    }
}

impl McpBookOperation {
    /// The wire discriminator for this arm.
    #[must_use]
    pub const fn op(&self) -> &'static str {
        match self {
            Self::Availability { .. } => "availability",
            Self::Book { .. } => "book",
            Self::Reschedule { .. } => "reschedule",
            Self::Cancel { .. } => "cancel",
        }
    }
}

/// One calendar selector; `system` is ignored until CAL-02's passport index.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCalendarSelector {
    #[serde(default)]
    pub system: Option<String>,
}

/// Inclusive UTC window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCalendarRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAskEffort {
    Minimal,
    Standard,
    Deep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCitationMode {
    ClaimRefs,
    ClaimRefsAndSpans,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpAskRoute {
    pub model_tier: String,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub substrate_ref: Option<String>,
    #[serde(default)]
    pub reasoning_effort: Option<McpAskEffort>,
    #[serde(default)]
    pub max_latency_ms: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpActorMetadata {
    pub actor_ref: String,
    pub actor_class: McpActorClass,
    pub gate_actor_class: McpActorClass,
    pub gate_actor_ref: String,
    pub scope: McpToolScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpActorClass {
    Human,
    Agent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolScope {
    #[serde(default)]
    pub world_ref: Option<String>,
    #[serde(default)]
    pub facet_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpConsentMetadata {
    pub policy_ref: String,
    pub purpose: String,
    #[serde(default)]
    pub approval_ref: Option<String>,
    #[serde(default)]
    pub consent_receipt_ref: Option<String>,
    #[serde(default)]
    pub require_human_approval: bool,
}

trait ValidateMcpArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError>;
}

impl ValidateMcpArgs for McpNavToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_optional_nonblank(tool, "query", self.query.as_deref())?;
        validate_optional_nonblank(tool, "cursor", self.cursor.as_deref())?;
        if self.limit == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "limit",
                "must be greater than zero",
            ));
        }
        validate_optional_context_pack(tool, self.context_pack.as_ref())
    }
}

impl ValidateMcpArgs for McpReadToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        self.target.validate(tool)
    }
}

impl ValidateMcpArgs for McpCalendarToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        match &self.operation {
            McpCalendarOperation::Read { event_ref } => {
                validate_entity_ref(tool, "operation.event_ref", event_ref)
            }
            McpCalendarOperation::Search {
                calendars,
                range,
                text,
                limit,
            } => {
                validate_calendar_selectors(tool, calendars)?;
                if let Some(range) = range {
                    validate_calendar_range(tool, *range)?;
                }
                validate_optional_nonblank(tool, "operation.text", text.as_deref())?;
                if *limit == Some(0) {
                    return Err(McpToolValidationError::field(
                        tool,
                        "operation.limit",
                        "must be greater than zero",
                    ));
                }
                Ok(())
            }
            McpCalendarOperation::Freebusy { calendars, range } => {
                validate_calendar_selectors(tool, calendars)?;
                validate_calendar_range(tool, *range)
            }
            McpCalendarOperation::Invite {
                uid,
                ics_blob_ref,
                recipient,
                ..
            } => {
                validate_nonblank(tool, "operation.uid", uid)?;
                validate_nonblank(tool, "operation.ics_blob_ref", ics_blob_ref)?;
                validate_nonblank(tool, "operation.recipient", recipient)
            }
        }
    }
}

fn validate_calendar_selectors(
    tool: McpToolName,
    calendars: &[McpCalendarSelector],
) -> Result<(), McpToolValidationError> {
    for selector in calendars {
        validate_optional_nonblank(
            tool,
            "operation.calendars.system",
            selector.system.as_deref(),
        )?;
    }
    Ok(())
}

fn validate_calendar_range(
    tool: McpToolName,
    range: McpCalendarRange,
) -> Result<(), McpToolValidationError> {
    if range.start > range.end {
        return Err(McpToolValidationError::field(
            tool,
            "operation.range",
            "start must not exceed end",
        ));
    }
    Ok(())
}

impl ValidateMcpArgs for McpEditToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "idempotency_key", &self.idempotency_key)?;

        match self.verb {
            McpEditVerb::ProposeClaim => self.validate_propose_claim(tool),
            McpEditVerb::AttestEdgeProvenance => self.validate_attest_edge_provenance(tool),
            McpEditVerb::SupersedeClaim => self.validate_supersede_claim(tool),
            McpEditVerb::RetractClaim => self.validate_retract_claim(tool),
            McpEditVerb::ProposeEntity => self.validate_propose_entity(tool),
            McpEditVerb::PostTask => self.validate_post_task(tool),
            McpEditVerb::ReportTask => self.validate_report_task(tool),
            McpEditVerb::ChannelSend => self.validate_channel_send(tool),
        }
    }
}

impl McpEditToolArgs {
    /// The claim ref this verb NAMES as its lifecycle target, if it names one
    /// (ONE-1936). The mapping is explicit per verb rather than "whichever id
    /// field happens to be set", because the guard's whole value is that the
    /// caller's chosen target is the thing checked:
    ///
    /// * `supersede_claim` → `old_claim_id` (the claim being replaced);
    /// * `retract_claim` → `claim_id` (the claim being withdrawn);
    /// * `attest_edge_provenance` → `old_claim_id`, present only for a
    ///   REPLACEMENT-style attestation. A first attestation for an edge has no
    ///   prior wrapper and therefore no lifecycle target.
    ///
    /// Every other verb proposes something new and has no target at all.
    #[must_use]
    pub fn lifecycle_target_ref(&self) -> Option<&str> {
        match self.verb {
            McpEditVerb::SupersedeClaim | McpEditVerb::AttestEdgeProvenance => {
                self.old_claim_id.as_deref()
            }
            McpEditVerb::RetractClaim => self.claim_id.as_deref(),
            McpEditVerb::ProposeClaim
            | McpEditVerb::ProposeEntity
            | McpEditVerb::PostTask
            | McpEditVerb::ReportTask
            | McpEditVerb::ChannelSend => None,
        }
    }

    fn validate_propose_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
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
            ],
        )?;
        self.validate_required_subject(tool, "subject")?
            .validate(tool)?;
        self.validate_required_predicate(tool)?;
        self.validate_required_value(tool, "value")?;
        self.validate_required_confidence(tool)?;
        validate_optional_entity_ref(tool, "world", self.world.as_deref())?;
        self.validate_optional_salience(tool)
    }

    fn validate_attest_edge_provenance(
        &self,
        tool: McpToolName,
    ) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
                "subject",
                "confidence",
                "old_claim_id",
                "supersession_status",
                "source_revision_ref",
                "body_snapshot_ref",
                "reasoning_effort",
            ],
        )?;
        self.validate_required_subject(tool, "subject")?
            .validate_edge_only(tool, "subject")?;
        self.validate_required_confidence(tool)?;
        // Replacement-style attestation names the wrapper it replaces; a FIRST
        // attestation for an edge has no prior and omits it (ONE-1936).
        validate_optional_entity_ref(tool, "old_claim_id", self.old_claim_id.as_deref())?;
        validate_optional_nonblank(
            tool,
            "supersession_status",
            self.supersession_status.as_deref(),
        )?;
        validate_optional_nonblank(
            tool,
            "source_revision_ref",
            self.source_revision_ref.as_deref(),
        )?;
        validate_optional_nonblank(tool, "body_snapshot_ref", self.body_snapshot_ref.as_deref())?;
        validate_optional_nonblank(tool, "reasoning_effort", self.reasoning_effort.as_deref())
    }

    fn validate_supersede_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
                "old_claim_id",
                "predicate",
                "value",
                "confidence",
                "evidence",
                "valid_from",
                "valid_to",
                "salience",
                "reason",
            ],
        )?;
        validate_required_entity_ref(tool, "old_claim_id", self.old_claim_id.as_deref())?;
        self.validate_required_predicate(tool)?;
        self.validate_required_value(tool, "value")?;
        self.validate_required_confidence(tool)?;
        validate_optional_nonblank(tool, "reason", self.reason.as_deref())?;
        self.validate_optional_salience(tool)
    }

    fn validate_retract_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["claim_id", "reason", "explanation"])?;
        validate_required_entity_ref(tool, "claim_id", self.claim_id.as_deref())?;
        validate_nonblank(
            tool,
            "reason",
            self.reason
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "reason", "is required"))?,
        )?;
        validate_optional_nonblank(tool, "explanation", self.explanation.as_deref())
    }

    fn validate_propose_entity(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &["entity_type", "occurred", "data", "initial_claims"],
        )?;
        self.entity_type
            .ok_or_else(|| McpToolValidationError::field(tool, "entity_type", "is required"))?;
        self.occurred
            .as_ref()
            .ok_or_else(|| McpToolValidationError::field(tool, "occurred", "is required"))?
            .validate(tool)?;
        self.validate_required_value(tool, "data")?;
        if self
            .initial_claims
            .as_ref()
            .is_some_and(|initial_claims| initial_claims.len() > 16)
        {
            return Err(McpToolValidationError::field(
                tool,
                "initial_claims",
                "must contain at most 16 claims",
            ));
        }
        Ok(())
    }

    fn validate_post_task(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["brief"])?;
        self.validate_required_value(tool, "brief")
    }

    fn validate_report_task(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["job_id", "outcome", "summary", "result_claims"])?;
        validate_nonblank(
            tool,
            "job_id",
            self.attempt_id
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "job_id", "is required"))?,
        )?;
        validate_nonblank(
            tool,
            "outcome",
            self.outcome
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "outcome", "is required"))?,
        )?;
        validate_nonblank(
            tool,
            "summary",
            self.summary
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "summary", "is required"))?,
        )?;
        if self
            .result_claims
            .as_ref()
            .is_some_and(|result_claims| result_claims.len() > 8)
        {
            return Err(McpToolValidationError::field(
                tool,
                "result_claims",
                "must contain at most 8 claims",
            ));
        }
        Ok(())
    }

    fn validate_channel_send(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["channel", "payload"])?;
        validate_nonblank(
            tool,
            "channel",
            self.channel
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "channel", "is required"))?,
        )?;
        self.validate_required_value(tool, "payload")
    }

    fn validate_only_edit_fields(
        &self,
        tool: McpToolName,
        allowed: &[&'static str],
    ) -> Result<(), McpToolValidationError> {
        for (field, present) in self.present_edit_fields() {
            if present && !allowed.contains(&field) {
                validate_absent(tool, field, true)?;
            }
        }
        Ok(())
    }

    fn present_edit_fields(&self) -> [(&'static str, bool); 29] {
        [
            ("subject", self.subject.is_some()),
            ("predicate", self.predicate.is_some()),
            ("value", self.value.is_some()),
            ("confidence", self.confidence.is_some()),
            ("evidence", self.evidence.is_some()),
            ("valid_from", self.valid_from.is_some()),
            ("valid_to", self.valid_to.is_some()),
            ("salience", self.salience.is_some()),
            ("world", self.world.is_some()),
            ("scope", self.scope.is_some()),
            ("old_claim_id", self.old_claim_id.is_some()),
            ("claim_id", self.claim_id.is_some()),
            ("reason", self.reason.is_some()),
            ("explanation", self.explanation.is_some()),
            ("entity_type", self.entity_type.is_some()),
            ("occurred", self.occurred.is_some()),
            ("data", self.data.is_some()),
            ("initial_claims", self.initial_claims.is_some()),
            ("brief", self.brief.is_some()),
            ("job_id", self.attempt_id.is_some()),
            ("outcome", self.outcome.is_some()),
            ("summary", self.summary.is_some()),
            ("result_claims", self.result_claims.is_some()),
            ("channel", self.channel.is_some()),
            ("payload", self.payload.is_some()),
            ("supersession_status", self.supersession_status.is_some()),
            ("source_revision_ref", self.source_revision_ref.is_some()),
            ("body_snapshot_ref", self.body_snapshot_ref.is_some()),
            ("reasoning_effort", self.reasoning_effort.is_some()),
        ]
    }

    fn validate_required_subject(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<&McpEditSubject, McpToolValidationError> {
        self.subject
            .as_ref()
            .ok_or_else(|| McpToolValidationError::field(tool, field, "is required"))
    }

    fn validate_required_predicate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(
            tool,
            "predicate",
            self.predicate
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "predicate", "is required"))?,
        )
    }

    fn validate_required_value(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<(), McpToolValidationError> {
        match field {
            "value" if self.value.is_some() => Ok(()),
            "data" if self.data.is_some() => Ok(()),
            "brief" if self.brief.is_some() => Ok(()),
            "payload" if self.payload.is_some() => Ok(()),
            _ => Err(McpToolValidationError::field(tool, field, "is required")),
        }
    }

    fn validate_required_confidence(
        &self,
        tool: McpToolName,
    ) -> Result<(), McpToolValidationError> {
        let confidence = self
            .confidence
            .ok_or_else(|| McpToolValidationError::field(tool, "confidence", "is required"))?;
        validate_confidence(tool, "confidence", confidence)
    }

    fn validate_optional_salience(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match self.salience {
            Some(salience) if salience.is_finite() => Ok(()),
            Some(_) => Err(McpToolValidationError::field(
                tool,
                "salience",
                "must be finite",
            )),
            None => Ok(()),
        }
    }
}

impl McpEditSubject {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match (self.entity.as_deref(), self.edge.as_ref()) {
            (Some(entity), None) => validate_entity_ref(tool, "subject.entity", entity),
            (None, Some(edge)) => edge.validate(tool, "subject.edge", false),
            _ => Err(McpToolValidationError::field(
                tool,
                "subject",
                "must include exactly one of entity or edge",
            )),
        }
    }

    fn validate_edge_only(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<(), McpToolValidationError> {
        match (&self.entity, &self.edge) {
            (None, Some(edge)) => edge.validate(tool, "subject.edge", true),
            _ => Err(McpToolValidationError::field(
                tool,
                field,
                "must include an edge subject",
            )),
        }
    }
}

impl McpEditEdgeSubject {
    fn validate(
        &self,
        tool: McpToolName,
        field: &'static str,
        provenance_only: bool,
    ) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "subject.edge.source", &self.source)?;
        validate_entity_ref(tool, "subject.edge.target", &self.target)?;
        if EdgeKind::try_from_u8(self.kind).is_none()
            || self.kind > 19
            || (provenance_only && self.kind < 9)
        {
            let message = if provenance_only {
                "must be a registered provenance edge kind in 9..=19"
            } else {
                "must be a registered edge kind in 0..=19"
            };
            return Err(McpToolValidationError::field(tool, field, message));
        }
        Ok(())
    }
}

impl McpOccurredRange {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        if self.start > self.end {
            return Err(McpToolValidationError::field(
                tool,
                "occurred.start",
                "must be less than or equal to occurred.end",
            ));
        }
        Ok(())
    }
}

impl ValidateMcpArgs for McpAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)
    }
}

impl ValidateMcpArgs for McpRoutedAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)?;
        self.route.validate(tool)
    }
}

impl McpReadTarget {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match (
            self.entity_ref.as_deref(),
            self.short_ref.as_deref(),
            self.context_pack.as_ref(),
        ) {
            (Some(entity_ref), None, None) => {
                validate_entity_ref(tool, "target.entity_ref", entity_ref)
            }
            (None, Some(short_ref), None) => {
                validate_short_ref(tool, "target.short_ref", short_ref)
            }
            (None, None, Some(context_pack)) => {
                validate_context_pack_field(tool, "target.context_pack", context_pack)
            }
            _ => Err(McpToolValidationError::field(
                tool,
                "target",
                "must include exactly one of entity_ref, short_ref, or context_pack",
            )),
        }
    }
}

impl McpAskRoute {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "route.model_tier", &self.model_tier)?;
        validate_optional_nonblank(tool, "route.model_id", self.model_id.as_deref())?;
        validate_optional_nonblank(tool, "route.substrate_ref", self.substrate_ref.as_deref())?;
        if self.max_latency_ms == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "route.max_latency_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl ValidateMcpArgs for McpBookToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_booking_page_token(tool, self.page_token())?;
        match &self.operation {
            McpBookOperation::Availability { input, .. } => {
                validate_nonblank(tool, "operation.input.event_type", &input.event_type.0)?;
                validate_nonblank(tool, "operation.input.visitor_tz", &input.visitor_tz)?;
                validate_nonblank(tool, "operation.input.session_ref", &input.session_ref)?;
                if input.window.start >= input.window.end {
                    return Err(McpToolValidationError::field(
                        tool,
                        "operation.input.window",
                        "must satisfy start < end",
                    ));
                }
                Ok(())
            }
            McpBookOperation::Book { input, .. } => validate_book_stage(tool, input),
            McpBookOperation::Reschedule { input, .. } => {
                validate_booking_action_token(
                    tool,
                    "operation.input.reschedule_token",
                    &input.reschedule_token,
                )?;
                validate_nonblank(tool, "operation.input.visitor_tz", &input.visitor_tz)?;
                validate_nonblank(
                    tool,
                    "operation.input.idempotency_key",
                    &input.idempotency_key,
                )?;
                validate_booking_slot(tool, "operation.input.selected_slot", input.selected_slot)
            }
            McpBookOperation::Cancel { input, .. } => {
                validate_booking_action_token(
                    tool,
                    "operation.input.cancel_token",
                    &input.cancel_token,
                )?;
                validate_nonblank(
                    tool,
                    "operation.input.idempotency_key",
                    &input.idempotency_key,
                )
            }
        }
    }
}

fn validate_book_stage(
    tool: McpToolName,
    input: &oneiron::booking::agent_api::BookingBookInput,
) -> Result<(), McpToolValidationError> {
    use oneiron::booking::agent_api::BookingBookInput;

    match input {
        BookingBookInput::Hold(hold) => {
            validate_nonblank(tool, "operation.input.input.event_type", &hold.event_type.0)?;
            validate_nonblank(tool, "operation.input.input.visitor_tz", &hold.visitor_tz)?;
            validate_nonblank(tool, "operation.input.input.session_ref", &hold.session_ref)?;
            validate_nonblank(
                tool,
                "operation.input.input.idempotency_key",
                &hold.idempotency_key,
            )?;
            if let Some(lease) = hold.checkout_lease_token.as_deref() {
                validate_booking_action_token(
                    tool,
                    "operation.input.input.checkout_lease_token",
                    lease,
                )?;
            }
            validate_booking_slot(
                tool,
                "operation.input.input.selected_slot",
                hold.selected_slot,
            )
        }
        BookingBookInput::Confirm(confirm) => {
            validate_booking_action_token(
                tool,
                "operation.input.input.hold_token",
                &confirm.hold_token,
            )?;
            validate_nonblank(
                tool,
                "operation.input.input.booker_email",
                &confirm.booker_email,
            )?;
            validate_nonblank(
                tool,
                "operation.input.input.session_ref",
                &confirm.session_ref,
            )?;
            validate_nonblank(
                tool,
                "operation.input.input.idempotency_key",
                &confirm.idempotency_key,
            )?;
            for answer in &confirm.intake {
                validate_nonblank(tool, "operation.input.input.intake.field_key", &answer.field_key)?;
            }
            Ok(())
        }
    }
}

fn validate_booking_slot(
    tool: McpToolName,
    field: &'static str,
    slot: oneiron::booking::agent_api::SelectedSlot,
) -> Result<(), McpToolValidationError> {
    if slot.start_utc >= slot.end_utc {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "must satisfy start_utc < end_utc",
        ));
    }
    Ok(())
}

/// A booking page token is opaque and public. Refusing the canonical entity-id
/// shape here is what keeps "an internal id is not a public token" mechanical
/// on the MCP door as well as the HTTP one.
fn validate_booking_page_token(
    tool: McpToolName,
    page_token: &str,
) -> Result<(), McpToolValidationError> {
    validate_nonblank(tool, "operation.page_token", page_token)?;
    if is_entity_id_shaped(page_token) {
        return Err(McpToolValidationError::field(
            tool,
            "operation.page_token",
            "must be an opaque booking page token, not an internal entity id",
        ));
    }
    Ok(())
}

/// An action-scoped booking token is a bearer credential, never an identifier.
fn validate_booking_action_token(
    tool: McpToolName,
    field: &'static str,
    token: &str,
) -> Result<(), McpToolValidationError> {
    validate_nonblank(tool, field, token)?;
    if is_entity_id_shaped(token) {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "must be an action-scoped booking token, not an internal entity id",
        ));
    }
    Ok(())
}

fn is_entity_id_shaped(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl McpActorMetadata {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "actor.actor_ref", &self.actor_ref)?;
        validate_entity_ref(tool, "actor.gate_actor_ref", &self.gate_actor_ref)?;
        if self.actor_class != self.gate_actor_class {
            return Err(McpToolValidationError::field(
                tool,
                "actor.gate_actor_class",
                "must match actor_class for foreign MCP clients",
            ));
        }
        self.scope.validate(tool)
    }
}

impl McpToolScope {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_optional_entity_ref(tool, "actor.scope.world_ref", self.world_ref.as_deref())?;
        validate_optional_entity_ref(tool, "actor.scope.facet_ref", self.facet_ref.as_deref())
    }
}

impl McpConsentMetadata {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "consent.policy_ref", &self.policy_ref)?;
        validate_nonblank(tool, "consent.purpose", &self.purpose)?;
        validate_optional_nonblank(tool, "consent.approval_ref", self.approval_ref.as_deref())?;
        validate_optional_nonblank(
            tool,
            "consent.consent_receipt_ref",
            self.consent_receipt_ref.as_deref(),
        )
    }
}

fn decode_tool_args<T>(tool: McpToolName, args: Value) -> Result<T, McpToolValidationError>
where
    T: DeserializeOwned + ValidateMcpArgs,
{
    let parsed =
        serde_json::from_value::<T>(args).map_err(|error| McpToolValidationError::Decode {
            tool: tool.as_str(),
            message: error.to_string(),
        })?;
    parsed.validate(tool)?;
    Ok(parsed)
}

fn validate_schema_version(tool: McpToolName, version: &str) -> Result<(), McpToolValidationError> {
    if version == MCP_TOOL_ARGS_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            "schema_version",
            format!("must be {MCP_TOOL_ARGS_SCHEMA_VERSION}"),
        ))
    }
}

fn validate_context_pack(
    tool: McpToolName,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    validate_context_pack_field(tool, "context_pack", context_pack)
}

fn validate_context_pack_field(
    tool: McpToolName,
    field: &'static str,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    context_pack
        .validate()
        .map_err(|error| McpToolValidationError::field(tool, field, error.to_string()))
}

fn validate_optional_context_pack(
    tool: McpToolName,
    context_pack: Option<&McpContextPackRef>,
) -> Result<(), McpToolValidationError> {
    match context_pack {
        Some(context_pack) => validate_context_pack(tool, context_pack),
        None => Ok(()),
    }
}

fn validate_nonblank(
    tool: McpToolName,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    if value.trim().is_empty() {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must not be blank",
        ))
    } else {
        Ok(())
    }
}

fn validate_short_ref(
    tool: McpToolName,
    field: &'static str,
    reference: &str,
) -> Result<(), McpToolValidationError> {
    validate_nonblank(tool, field, reference)?;
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "must be in shortId:contentHashHex form",
        ));
    };
    validate_short_ref_parts(tool, field, short_id, content_hash)
}

/// Validates the two halves of a short ref against the engine's presentation-id
/// grammar (`oneiron::parse_presentation_id`), the same door
/// `api/core.rs::parse_short_ref_parts` and `facade::resolve_entity_ref` use.
///
/// Syntax only: an undeclared prefix parses here and fails at resolution, and
/// prefix LENGTH is a registry fact rather than something this validator pins.
fn validate_short_ref_parts(
    tool: McpToolName,
    field: &'static str,
    short_id: &str,
    content_hash: &str,
) -> Result<(), McpToolValidationError> {
    if oneiron::parse_presentation_id(short_id).is_err() {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "short id must be at least two lowercase letters followed by decimal digits",
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "content hash must be exactly two hex digits",
        ));
    }
    u8::from_str_radix(content_hash, 16)
        .map_err(|_| McpToolValidationError::field(tool, field, "content hash must be hex"))?;
    Ok(())
}

fn validate_optional_nonblank(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_nonblank(tool, field, value),
        None => Ok(()),
    }
}

fn validate_confidence(
    tool: McpToolName,
    field: &'static str,
    value: f32,
) -> Result<(), McpToolValidationError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must be a finite number in 0..=1",
        ))
    }
}

fn validate_required_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    let value = value
        .ok_or_else(|| McpToolValidationError::field(tool, field, "is required for this verb"))?;
    validate_entity_ref(tool, field, value)
}

fn validate_optional_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_entity_ref(tool, field, value),
        None => Ok(()),
    }
}

fn validate_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    let parsed = EntityId::from_hex(value).map_err(|_| {
        McpToolValidationError::field(tool, field, "must be a canonical 32-character entity id")
    })?;
    if parsed.to_hex() == value {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must be a canonical 32-character entity id",
        ))
    }
}

fn validate_absent(
    tool: McpToolName,
    field: &'static str,
    present: bool,
) -> Result<(), McpToolValidationError> {
    if present {
        Err(McpToolValidationError::field(
            tool,
            field,
            "is not valid for this verb",
        ))
    } else {
        Ok(())
    }
}

fn nav_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/nav.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "mode": { "type": "string", "enum": ["search", "timeline", "list", "hydrate"] },
            "query": nonblank_string_schema(),
            "limit": { "type": "integer", "minimum": 1 },
            "cursor": nonblank_string_schema(),
            "context_pack": context_pack_ref_schema(),
        }),
        &["schema_version", "actor", "consent", "mode"],
    )
}

fn read_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/read.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "target": read_target_schema(),
        }),
        &["schema_version", "actor", "consent", "target"],
    )
}

fn edit_tool_schema() -> Value {
    let mut schema = tool_schema_root(
        "https://oneiron.local/schemas/mcp/edit.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "verb": {
                "type": "string",
                "enum": [
                    "propose_claim",
                    "attest_edge_provenance",
                    "supersede_claim",
                    "retract_claim",
                    "propose_entity",
                    "post_task",
                    "report_task",
                    "channel_send",
                ],
            },
            "idempotency_key": nonblank_string_schema(),
            "dry_run": { "type": "boolean" },
            "subject": edit_subject_schema(),
            "predicate": nonblank_string_schema(),
            "value": {},
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
            "evidence": {},
            "valid_from": { "type": "integer", "minimum": 0 },
            "valid_to": { "type": "integer", "minimum": 0 },
            "salience": { "type": "number" },
            "world": entity_id_schema(),
            "scope": {},
            "old_claim_id": entity_id_schema(),
            "claim_id": entity_id_schema(),
            "reason": nonblank_string_schema(),
            "explanation": nonblank_string_schema(),
            "entity_type": { "type": "integer", "minimum": 0, "maximum": 255 },
            "occurred": occurred_range_schema(),
            "data": {},
            "initial_claims": { "type": "array", "maxItems": 16, "items": {} },
            "brief": {},
            "job_id": nonblank_string_schema(),
            "outcome": nonblank_string_schema(),
            "summary": nonblank_string_schema(),
            "result_claims": { "type": "array", "maxItems": 8, "items": {} },
            "channel": nonblank_string_schema(),
            "payload": {},
            "supersession_status": nonblank_string_schema(),
            "source_revision_ref": nonblank_string_schema(),
            "body_snapshot_ref": nonblank_string_schema(),
            "reasoning_effort": nonblank_string_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "consent",
            "verb",
            "idempotency_key",
        ],
    );
    schema
        .as_object_mut()
        .expect("tool schema root is an object")
        .insert(
            "allOf".to_owned(),
            json!([
                {
                    "if": {
                        "properties": { "verb": { "const": "propose_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["subject", "predicate", "value", "confidence"],
                        "not": edit_forbidden_except(&[
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
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "attest_edge_provenance" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["subject", "confidence"],
                        "properties": {
                            "subject": edit_provenance_subject_schema(),
                        },
                        "not": edit_forbidden_except(&[
                            "subject",
                            "confidence",
                            "old_claim_id",
                            "supersession_status",
                            "source_revision_ref",
                            "body_snapshot_ref",
                            "reasoning_effort",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "supersede_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["old_claim_id", "predicate", "value", "confidence"],
                        "not": edit_forbidden_except(&[
                            "old_claim_id",
                            "predicate",
                            "value",
                            "confidence",
                            "evidence",
                            "valid_from",
                            "valid_to",
                            "salience",
                            "reason",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "retract_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["claim_id", "reason"],
                        "not": edit_forbidden_except(&["claim_id", "reason", "explanation"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "propose_entity" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["entity_type", "occurred", "data"],
                        "not": edit_forbidden_except(&[
                            "entity_type",
                            "occurred",
                            "data",
                            "initial_claims",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "post_task" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["brief"],
                        "not": edit_forbidden_except(&["brief"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "report_task" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["job_id", "outcome", "summary"],
                        "not": edit_forbidden_except(&["job_id", "outcome", "summary", "result_claims"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "channel_send" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["channel", "payload"],
                        "not": edit_forbidden_except(&["channel", "payload"]),
                    },
                },
            ]),
        );
    schema
}

fn ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
        ],
    )
}

fn routed_ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask_routed.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "route": ask_route_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
            "route",
        ],
    )
}

fn calendar_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/calendar.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "operation": calendar_operation_schema(),
        }),
        &["schema_version", "actor", "consent", "operation"],
    )
}

/// One closed branch per operation. The `op` discriminator is the only shared
/// key; every other field belongs to exactly one arm.
fn calendar_operation_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["op", "event_ref"],
                json!({
                    "op": { "const": "read" },
                    "event_ref": entity_id_schema(),
                }),
            ),
            closed_object_schema(
                &["op"],
                json!({
                    "op": { "const": "search" },
                    "calendars": calendar_selectors_schema(),
                    "range": calendar_range_schema(),
                    "text": nonblank_string_schema(),
                    "limit": { "type": "integer", "minimum": 1 },
                }),
            ),
            closed_object_schema(
                &["op", "range"],
                json!({
                    "op": { "const": "freebusy" },
                    "calendars": calendar_selectors_schema(),
                    "range": calendar_range_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "method", "uid", "sequence", "ics_blob_ref", "recipient"],
                json!({
                    "op": { "const": "invite" },
                    "method": { "type": "string", "enum": ["REQUEST", "CANCEL"] },
                    "uid": nonblank_string_schema(),
                    "sequence": { "type": "integer", "minimum": 0 },
                    "ics_blob_ref": nonblank_string_schema(),
                    "recipient": nonblank_string_schema(),
                }),
            ),
        ],
    })
}

fn book_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/book.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "operation": book_operation_schema(),
        }),
        &["schema_version", "actor", "consent", "operation"],
    )
}

/// One closed branch per booking operation. `op` is the only shared key; every
/// other field belongs to exactly one arm, so a `cancel` payload smuggled into
/// an `availability` call is a validation failure rather than an ignored extra.
fn book_operation_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["op", "page_token", "input"],
                json!({
                    "op": { "const": "availability" },
                    "page_token": booking_page_token_schema(),
                    "input": booking_availability_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "page_token", "input"],
                json!({
                    "op": { "const": "book" },
                    "page_token": booking_page_token_schema(),
                    "input": booking_book_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "page_token", "input"],
                json!({
                    "op": { "const": "reschedule" },
                    "page_token": booking_page_token_schema(),
                    "input": booking_reschedule_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "page_token", "input"],
                json!({
                    "op": { "const": "cancel" },
                    "page_token": booking_page_token_schema(),
                    "input": booking_cancel_input_schema(),
                }),
            ),
        ],
    })
}

/// The opaque public page handle. Advertised as a bounded non-blank string so a
/// client cannot pre-encode an internal identifier and expect it to resolve.
fn booking_page_token_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": "\\S",
    })
}

fn booking_opaque_token_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": "\\S",
    })
}

fn booking_availability_input_schema() -> Value {
    closed_object_schema(
        &[
            "event_type",
            "window",
            "visitor_tz",
            "constraint",
            "session_ref",
        ],
        json!({
            "event_type": nonblank_string_schema(),
            "window": booking_time_range_schema(),
            "visitor_tz": nonblank_string_schema(),
            "constraint": nullable_schema(booking_constraint_input_schema()),
            "session_ref": nonblank_string_schema(),
        }),
    )
}

fn booking_book_input_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["stage", "input"],
                json!({
                    "stage": { "const": "hold" },
                    "input": booking_hold_input_schema(),
                }),
            ),
            closed_object_schema(
                &["stage", "input"],
                json!({
                    "stage": { "const": "confirm" },
                    "input": booking_confirm_input_schema(),
                }),
            ),
        ],
    })
}

/// The hold payload carries no TTL field, by construction: a hold's lifetime is
/// the server default or the cap a verified server-issued lease allows.
fn booking_hold_input_schema() -> Value {
    closed_object_schema(
        &[
            "event_type",
            "selected_slot",
            "visitor_tz",
            "constraint",
            "session_ref",
            "checkout_lease_token",
            "idempotency_key",
        ],
        json!({
            "event_type": nonblank_string_schema(),
            "selected_slot": booking_selected_slot_schema(),
            "visitor_tz": nonblank_string_schema(),
            "constraint": nullable_schema(booking_constraint_object_schema()),
            "session_ref": nonblank_string_schema(),
            "checkout_lease_token": nullable_schema(booking_opaque_token_schema()),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn booking_confirm_input_schema() -> Value {
    closed_object_schema(
        &[
            "hold_token",
            "booker_email",
            "intake",
            "session_ref",
            "idempotency_key",
        ],
        json!({
            "hold_token": booking_opaque_token_schema(),
            "booker_email": nonblank_string_schema(),
            "intake": {
                "type": "array",
                "maxItems": 32,
                "items": closed_object_schema(
                    &["field_key", "value"],
                    json!({
                        "field_key": nonblank_string_schema(),
                        "value": { "type": "string", "maxLength": 2048 },
                    }),
                ),
            },
            "session_ref": nonblank_string_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn booking_reschedule_input_schema() -> Value {
    closed_object_schema(
        &[
            "reschedule_token",
            "selected_slot",
            "visitor_tz",
            "idempotency_key",
        ],
        json!({
            "reschedule_token": booking_opaque_token_schema(),
            "selected_slot": booking_selected_slot_schema(),
            "visitor_tz": nonblank_string_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn booking_cancel_input_schema() -> Value {
    closed_object_schema(
        &["cancel_token", "idempotency_key"],
        json!({
            "cancel_token": booking_opaque_token_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn booking_selected_slot_schema() -> Value {
    closed_object_schema(
        &["start_utc", "end_utc"],
        json!({
            "start_utc": { "type": "integer", "minimum": 0 },
            "end_utc": { "type": "integer", "minimum": 0 },
        }),
    )
}

fn booking_time_range_schema() -> Value {
    closed_object_schema(
        &["start", "end"],
        json!({
            "start": { "type": "integer", "minimum": 0 },
            "end": { "type": "integer", "minimum": 0 },
        }),
    )
}

/// The tagged constraint input. `free_text` is bounded parser input, never
/// solver input: the shared executor replaces it with a canonical object before
/// any solve.
fn booking_constraint_input_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["kind", "value"],
                json!({
                    "kind": { "const": "object" },
                    "value": booking_constraint_object_schema(),
                }),
            ),
            closed_object_schema(
                &["kind", "value"],
                json!({
                    "kind": { "const": "free_text" },
                    "value": { "type": "string", "minLength": 1, "maxLength": 4096 },
                }),
            ),
        ],
    })
}

/// ONE-1816's canonical constraint, advertised at its pinned schema version.
fn booking_constraint_object_schema() -> Value {
    closed_object_schema(
        &["schema_version", "utc_window", "allow_flex_pool"],
        json!({
            "schema_version": {
                "const": oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION,
            },
            "weekdays": {
                "type": "array",
                "maxItems": 7,
                "items": {
                    "enum": [
                        "monday", "tuesday", "wednesday", "thursday",
                        "friday", "saturday", "sunday",
                    ],
                },
            },
            "local_time_windows": {
                "type": "array",
                "maxItems": 8,
                "items": closed_object_schema(
                    &["start_minute", "end_minute"],
                    json!({
                        "start_minute": { "type": "integer", "minimum": 0, "maximum": 1440 },
                        "end_minute": { "type": "integer", "minimum": 0, "maximum": 1440 },
                    }),
                ),
            },
            "utc_window": nullable_schema(booking_time_range_schema()),
            "allow_flex_pool": { "type": "boolean" },
        }),
    )
}

/// `T | null`, expressed as a union rather than a multi-typed `type` keyword so
/// the closed-object invariant still applies to the non-null branch.
fn nullable_schema(schema: Value) -> Value {
    json!({ "oneOf": [schema, { "type": "null" }] })
}

fn calendar_selectors_schema() -> Value {
    json!({
        "type": "array",
        "items": closed_object_schema(&[], json!({ "system": nonblank_string_schema() })),
    })
}

fn calendar_range_schema() -> Value {
    closed_object_schema(
        &["start", "end"],
        json!({
            "start": { "type": "integer", "minimum": 0 },
            "end": { "type": "integer", "minimum": 0 },
        }),
    )
}

fn closed_object_schema(required: &[&'static str], properties: Value) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn tool_schema_root(id: &'static str, properties: Value, required: &[&'static str]) -> Value {
    json!({
        "$schema": MCP_SCHEMA_DRAFT,
        "$id": id,
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn edit_forbidden_except(allowed: &[&str]) -> Value {
    let forbidden = EDIT_ACTION_FIELDS
        .iter()
        .copied()
        .filter(|field| !allowed.contains(field))
        .collect::<Vec<_>>();
    forbidden_properties_schema(&forbidden)
}

fn forbidden_properties_schema(properties: &[&str]) -> Value {
    let disallowed = properties
        .iter()
        .map(|field| json!({ "required": [field] }))
        .collect::<Vec<_>>();
    json!({ "anyOf": disallowed })
}

fn schema_version_property() -> Value {
    json!({
        "type": "string",
        "const": MCP_TOOL_ARGS_SCHEMA_VERSION,
    })
}

fn entity_id_schema() -> Value {
    json!({
        "type": "string",
        "pattern": ENTITY_ID_PATTERN,
    })
}

fn short_ref_schema() -> Value {
    json!({
        "type": "string",
        "pattern": SHORT_REF_PATTERN,
    })
}

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S",
    })
}

fn actor_class_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["human", "agent"],
    })
}

fn actor_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["actor_ref", "actor_class", "gate_actor_class", "gate_actor_ref", "scope"],
        "oneOf": [
            {
                "properties": {
                    "actor_class": { "const": "human" },
                    "gate_actor_class": { "const": "human" },
                },
            },
            {
                "properties": {
                    "actor_class": { "const": "agent" },
                    "gate_actor_class": { "const": "agent" },
                },
            },
        ],
        "properties": {
            "actor_ref": entity_id_schema(),
            "actor_class": actor_class_schema(),
            "gate_actor_class": actor_class_schema(),
            "gate_actor_ref": entity_id_schema(),
            "scope": scope_schema(),
        },
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "world_ref": entity_id_schema(),
            "facet_ref": entity_id_schema(),
        },
    })
}

fn consent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["policy_ref", "purpose"],
        "properties": {
            "policy_ref": nonblank_string_schema(),
            "purpose": nonblank_string_schema(),
            "approval_ref": nonblank_string_schema(),
            "consent_receipt_ref": nonblank_string_schema(),
            "require_human_approval": { "type": "boolean" },
        },
    })
}

fn context_pack_ref_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version"],
        "anyOf": [
            { "required": ["pack_ref"] },
            { "required": ["retrieval_run_id"] },
            {
                "required": ["result_ids"],
                "properties": {
                    "result_ids": { "minItems": 1 },
                },
            },
        ],
        "properties": {
            "schema_version": {
                "type": "string",
                "const": MCP_CONTEXT_PACK_REF_SCHEMA_VERSION,
            },
            "context_version": nonblank_string_schema(),
            "pack_ref": nonblank_string_schema(),
            "retrieval_run_id": nonblank_string_schema(),
            "result_ids": {
                "type": "array",
                "items": entity_id_schema(),
            },
            "budget_ref": nonblank_string_schema(),
        },
    })
}

fn read_target_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "oneOf": [
            { "required": ["entity_ref"] },
            { "required": ["short_ref"] },
            { "required": ["context_pack"] },
        ],
        "properties": {
            "entity_ref": entity_id_schema(),
            "short_ref": short_ref_schema(),
            "context_pack": context_pack_ref_schema(),
        },
    })
}

fn edit_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "oneOf": [
            { "required": ["entity"] },
            { "required": ["edge"] },
        ],
        "properties": {
            "entity": entity_id_schema(),
            "edge": edit_edge_subject_schema(),
        },
    })
}

fn edit_provenance_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["edge"],
        "properties": {
            "edge": edit_provenance_edge_subject_schema(),
        },
    })
}

fn edit_edge_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "kind", "target"],
        "properties": {
            "source": entity_id_schema(),
            "kind": { "type": "integer", "minimum": 0, "maximum": 19 },
            "target": entity_id_schema(),
        },
    })
}

fn edit_provenance_edge_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "kind", "target"],
        "properties": {
            "source": entity_id_schema(),
            "kind": { "type": "integer", "minimum": 9, "maximum": 19 },
            "target": entity_id_schema(),
        },
    })
}

fn occurred_range_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["start", "end"],
        "properties": {
            "start": { "type": "integer", "minimum": 0 },
            "end": { "type": "integer", "minimum": 0 },
        },
    })
}

fn ask_effort_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["minimal", "standard", "deep"],
    })
}

fn citation_mode_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["claim_refs", "claim_refs_and_spans"],
    })
}

fn ask_route_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["model_tier"],
        "properties": {
            "model_tier": nonblank_string_schema(),
            "model_id": nonblank_string_schema(),
            "substrate_ref": nonblank_string_schema(),
            "reasoning_effort": ask_effort_schema(),
            "max_latency_ms": { "type": "integer", "minimum": 1 },
        },
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct McpCredentialHashKey([u8; 32]);

impl McpCredentialHashKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for McpCredentialHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialHashKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct McpCredentialFingerprint([u8; 32]);

impl fmt::Debug for McpCredentialFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialFingerprint(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorScope {
    pub world_ref: Option<EntityId>,
    pub facet_ref: Option<EntityId>,
}

impl McpConnectorScope {
    #[must_use]
    pub const fn vault_wide() -> Self {
        Self {
            world_ref: None,
            facet_ref: None,
        }
    }

    #[must_use]
    pub const fn scoped(world_ref: Option<EntityId>, facet_ref: Option<EntityId>) -> Self {
        Self {
            world_ref,
            facet_ref,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorActorRecord {
    actor_ref: EntityId,
    actor_class: EdgeActorClass,
    scope: McpConnectorScope,
    expires_at: Option<u64>,
    revoked_at: Option<u64>,
}

impl McpConnectorActorRecord {
    #[must_use]
    pub const fn new(
        actor_ref: EntityId,
        actor_class: EdgeActorClass,
        scope: McpConnectorScope,
    ) -> Self {
        Self {
            actor_ref,
            actor_class,
            scope,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[must_use]
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub const fn with_revoked_at(mut self, revoked_at: u64) -> Self {
        self.revoked_at = Some(revoked_at);
        self
    }

    #[must_use]
    pub const fn gate_actor_class(&self) -> &'static str {
        self.actor_class.gate_actor_class()
    }

    #[must_use]
    pub fn gate_actor_ref(&self) -> String {
        self.actor_ref.to_hex()
    }

    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }

    const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    fn is_stale(&self, now: u64) -> bool {
        self.revoked_at.is_some_and(|revoked_at| now >= revoked_at) || self.is_expired(now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpResolvedActor {
    pub actor_ref: EntityId,
    pub actor_class: EdgeActorClass,
    pub gate_actor_class: &'static str,
    pub gate_actor_ref: String,
    pub scope: McpConnectorScope,
}

impl McpResolvedActor {
    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorRegistrationError {
    #[error("credential must not be blank")]
    EmptyCredential,
    #[error("credential is already registered")]
    DuplicateCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorResolutionError {
    #[error("credential not found")]
    UnknownCredential,
    #[error("credential has expired")]
    ExpiredCredential,
    #[error("credential has been revoked")]
    RevokedCredential,
    #[error("actor ceiling row not found")]
    MissingActorCeiling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpConnectorActorRevokeStatus {
    Revoked,
    AlreadyRevoked { revoked_at: u64 },
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpConnectorActorRegistry {
    credential_hash_key: McpCredentialHashKey,
    records: BTreeMap<McpCredentialFingerprint, McpConnectorActorRecord>,
}

impl fmt::Debug for McpConnectorActorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpConnectorActorRegistry")
            .field("credential_hash_key", &"<redacted>")
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl McpConnectorActorRegistry {
    #[must_use]
    pub const fn new(credential_hash_key: McpCredentialHashKey) -> Self {
        Self {
            credential_hash_key,
            records: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        credential: impl Into<String>,
        record: McpConnectorActorRecord,
    ) -> Result<(), McpConnectorActorRegistrationError> {
        let credential = credential.into();
        let Some(credential) = normalize_credential(&credential) else {
            return Err(McpConnectorActorRegistrationError::EmptyCredential);
        };
        let fingerprint = self.fingerprint_credential(credential);
        if self.records.contains_key(&fingerprint) {
            return Err(McpConnectorActorRegistrationError::DuplicateCredential);
        }
        self.records.insert(fingerprint, record);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        credential: &str,
        revoked_at: u64,
    ) -> Result<McpConnectorActorRevokeStatus, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get_mut(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if let Some(existing_revoked_at) = record.revoked_at {
            return Ok(McpConnectorActorRevokeStatus::AlreadyRevoked {
                revoked_at: existing_revoked_at,
            });
        }

        record.revoked_at = Some(revoked_at);
        Ok(McpConnectorActorRevokeStatus::Revoked)
    }

    pub fn resolve(
        &self,
        credential: &str,
        now: u64,
        actor_ceiling_exists: impl FnOnce(&str, &str) -> bool,
    ) -> Result<McpResolvedActor, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if record.is_revoked() {
            return Err(McpConnectorActorResolutionError::RevokedCredential);
        }
        if record.is_expired(now) {
            return Err(McpConnectorActorResolutionError::ExpiredCredential);
        }

        let gate_actor_class = record.gate_actor_class();
        let gate_actor_ref = record.gate_actor_ref();
        if !actor_ceiling_exists(gate_actor_class, &gate_actor_ref) {
            return Err(McpConnectorActorResolutionError::MissingActorCeiling);
        }

        Ok(McpResolvedActor {
            actor_ref: record.actor_ref,
            actor_class: record.actor_class,
            gate_actor_class,
            gate_actor_ref,
            scope: record.scope.clone(),
        })
    }

    pub fn unregister(&mut self, credential: &str) -> bool {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return false;
        };
        self.records.remove(&fingerprint).is_some()
    }

    pub fn prune_revoked_or_expired(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| !record.is_stale(now));
        before - self.records.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn fingerprint_lookup_credential(&self, credential: &str) -> Option<McpCredentialFingerprint> {
        normalize_credential(credential).map(|credential| self.fingerprint_credential(credential))
    }

    fn fingerprint_credential(&self, credential: &str) -> McpCredentialFingerprint {
        McpCredentialFingerprint(
            *blake3::keyed_hash(&self.credential_hash_key.0, credential.as_bytes()).as_bytes(),
        )
    }
}

fn normalize_credential(credential: &str) -> Option<&str> {
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

#[cfg(test)]
mod tests;
