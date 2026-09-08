//! MCP tool argument envelopes: the request shapes for every tool verb.

use super::tool_catalog::{MCP_SERVER_NAME, McpToolName};
use oneiron::booking::agent_api::{
    BookingAgentOperation, BookingAvailabilityInput, BookingBookInput, BookingCancelInput,
    BookingOperationRequest, BookingRescheduleInput,
};
use oneiron::context_pack::McpContextPackRef;
use oneiron::outbound_consent::DataClass;
use oneiron::outbound_consent::ScopedMcpCallContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// `oneiron.book` arguments.
///
/// The envelope mirrors [`McpCalendarToolArgs`] field for field, plus the
/// booking page's opaque token: the booking vocabulary lives entirely inside
/// [`McpBookOperation`], so the catalog grows one tool rather than four.
///
/// `page_token` is a public opaque handle. Neither this struct nor any type it
/// reaches carries an `EntityId`, so an MCP caller cannot name an internal
/// page, booking, contact, or calendar subject.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpBookToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub page_token: String,
    pub operation: McpBookOperation,
}

/// The closed `availability|book|reschedule|cancel` operation set.
///
/// Each arm is independently closed and carries exactly the typed input the
/// shared server executor accepts, so an MCP request and an HTTP request for
/// the same operation are the same value by the time either reaches the
/// executor.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpBookOperation {
    Availability { input: BookingAvailabilityInput },
    Book { input: BookingBookInput },
    Reschedule { input: BookingRescheduleInput },
    Cancel { input: BookingCancelInput },
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

    /// The engine-side operation this arm names.
    #[must_use]
    pub const fn agent_operation(&self) -> BookingAgentOperation {
        match self {
            Self::Availability { .. } => BookingAgentOperation::Availability,
            Self::Book { .. } => BookingAgentOperation::Book,
            Self::Reschedule { .. } => BookingAgentOperation::Reschedule,
            Self::Cancel { .. } => BookingAgentOperation::Cancel,
        }
    }
}

impl McpBookToolArgs {
    /// The connector actor this call claims, which the gateway must match
    /// against the authenticated credential before anything executes.
    #[must_use]
    pub const fn actor(&self) -> &McpActorMetadata {
        &self.actor
    }

    /// The engine-side operation this call names.
    #[must_use]
    pub const fn operation(&self) -> BookingAgentOperation {
        self.operation.agent_operation()
    }

    /// The payload-aware axes a scoped-MCP grant is evaluated against.
    ///
    /// Derived from the call itself, never from the caller's assertion: the
    /// server name is this daemon's, the tool is `oneiron.book`, the endpoint
    /// is the operation the args actually carry, and the data class follows
    /// the payload. Confirm names a person by email and is therefore
    /// personal-class; the other three carry only public slot data and opaque
    /// tokens.
    #[must_use]
    pub fn scoped_mcp_call(&self) -> ScopedMcpCallContext {
        ScopedMcpCallContext {
            server: MCP_SERVER_NAME.to_owned(),
            tool: McpToolName::Book.as_str().to_owned(),
            payload_data_class: match &self.operation {
                McpBookOperation::Book {
                    input: BookingBookInput::Confirm(_),
                } => DataClass::Personal,
                _ => DataClass::Public,
            },
            resolved_endpoint: format!("booking.{}", self.operation.op()),
        }
    }

    /// The shared executor request this call becomes.
    ///
    /// The MCP door builds the SAME [`BookingOperationRequest`] the HTTP
    /// routes build, so there is nothing transport-specific left to diverge.
    #[must_use]
    pub fn into_operation_request(self) -> BookingOperationRequest {
        match self.operation {
            McpBookOperation::Availability { input } => {
                BookingOperationRequest::Availability(input)
            }
            McpBookOperation::Book { input } => BookingOperationRequest::Book(input),
            McpBookOperation::Reschedule { input } => BookingOperationRequest::Reschedule(input),
            McpBookOperation::Cancel { input } => BookingOperationRequest::Cancel(input),
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
