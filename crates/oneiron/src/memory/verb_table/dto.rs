//! Wire DTO adapters for the facade verb table: each adapter packs one
//! [`Memory`](super::super::Memory) signature into the table's uniform
//! call shape. All DTOs are engine serde types in `memory`, so every wire
//! keeps engine DTOs as its request/response types by construction.

use serde::{Deserialize, Serialize};

use super::super::{
    ClaimInput, Effort, MemoryError, MemoryResult, NeighborOpts, OutboundDraftInput,
    OutboundScheduleContext, RecallScope, SafeDeleteReason,
};
use crate::calendar::CalendarSel;

// ── wire DTO adapters ───────────────────────────────────────────────────

/// Batched claim writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRequest {
    /// Claims to commit, one individually gated write per element.
    pub claims: Vec<ClaimInput>,
}

/// One claim ref.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimRefRequest {
    /// Short-id ref or 32-hex id of the claim.
    #[serde(alias = "claimRef")]
    pub claim_ref: String,
}

/// One entity ref.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRefRequest {
    /// Short-id ref or 32-hex id of the entity.
    #[serde(alias = "entityRef")]
    pub entity_ref: String,
}

/// One bounded listing input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimitRequest {
    /// Maximum rows; defaults to 100.
    #[serde(
        default = "default_receipts_limit",
        deserialize_with = "receipts_limit"
    )]
    pub limit: usize,
}

/// Entity hydration input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HydrateRequest {
    /// Short-id refs or 32-hex ids to read.
    pub refs: Vec<String>,
}

/// One BM25 query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryRequest {
    /// Query text.
    pub query: String,
    /// Maximum hits (required; no unbounded scans).
    pub limit: usize,
}

/// One neighborhood query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborsRequest {
    /// Anchor entity ref (short-id ref or hex).
    #[serde(alias = "entityRef")]
    pub entity_ref: String,
    /// Edge-kind / weight / limit options.
    pub opts: NeighborOpts,
}

/// One exact-world view recall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallViewRequest {
    /// Query text.
    pub query: String,
    /// World/facet narrowing.
    pub scope: RecallScope,
    /// Registry kind narrowing, when set.
    pub kind: Option<String>,
    /// Predicate narrowing, when set.
    pub predicate: Option<String>,
    /// Maximum items.
    pub limit: usize,
}

/// One effort-dialed recall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallRequestDto {
    /// Query text.
    pub query: String,
    /// Retrieval effort; omitted means standard.
    pub effort: Option<Effort>,
    /// World/facet narrowing; omitted means the vault floor.
    pub scope: Option<RecallScope>,
    /// Maximum items; omitted means 10.
    pub limit: Option<usize>,
    /// OF-096 pack format, when rendering.
    pub format: Option<String>,
}

/// One named safe-delete request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeDeleteRequest {
    /// Entity ref (short-id ref or hex).
    #[serde(alias = "entityRef")]
    pub entity_ref: String,
    /// Named reason (`user_delete` | `user_hard_delete` | `gdpr_delete` | `policy_delete`).
    pub reason: SafeDeleteReason,
}

/// The engine-side forget selector (mirrors the napi/uniffi selector exactly).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForgetSelector {
    /// Claim short ref (or 32-hex id).
    pub short_ref: Option<String>,
    /// Subject ref, used together with `predicate`.
    pub subject_ref: Option<String>,
    /// Predicate, used together with `subject_ref`.
    pub predicate: Option<String>,
}

/// One blob-version append (bytes cross as base64, as on the napi boundary).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppendBlobVersionRequest {
    /// Artifact ref (short-id ref or hex).
    pub artifact_ref: String,
    /// Raw version bytes, base64-encoded.
    pub content_base64: String,
    /// Producing run ref, when agent-produced.
    pub run_ref: Option<String>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; omitted means `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One blob-version read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadBlobVersionRequest {
    /// Artifact ref (short-id ref or hex).
    pub artifact_ref: String,
    /// Version number (1-based).
    pub version: u64,
}

/// One blob-version read answer (bytes cross as base64).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlobBytesResponse {
    /// Raw version bytes, base64-encoded; `None` when the version is absent.
    pub content_base64: Option<String>,
}

/// One attributed-take write (targets cross as refs, never raw ids).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorTakeRequest {
    /// Take target kind: `subject` or `claim`.
    pub target_kind: String,
    /// Target entity ref (short-id ref or hex).
    pub target_ref: String,
    /// Take markdown.
    pub markdown: String,
}

/// One outbound schedule (draft plus the optional host schedule context).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduleOutboundRequest {
    /// The outbound draft.
    pub draft: OutboundDraftInput,
    /// Host schedule context; omitted means the default context.
    pub context: Option<ScheduleOutboundContextDto>,
}

/// Wire form of [`OutboundScheduleContext`] (all plain serde scalars).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScheduleOutboundContextDto {
    /// Civil UTC offset in minutes, when known.
    pub utc_offset_minutes: Option<i16>,
    /// IANA timezone label, when known.
    pub iana_timezone: Option<String>,
    /// Whether the caller named an explicit instant.
    #[serde(default)]
    pub human_explicit_instant: bool,
    /// APNs interruption level (`passive` | `active` | `time_sensitive` | `critical`).
    pub apns_interruption_level: Option<String>,
    /// Host-resolved level (`plain_chat` | `push`).
    pub resolved_level: Option<String>,
}

impl ScheduleOutboundContextDto {
    pub(super) fn into_engine(self) -> MemoryResult<OutboundScheduleContext> {
        use crate::delivery_window::{
            DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel,
        };
        let apns_interruption_level = self
            .apns_interruption_level
            .map(|level| {
                DeliveryWindowApnsInterruptionLevel::parse(&level).ok_or_else(|| {
                    MemoryError::bad_request_with(
                        format!("unknown APNs interruption level {level:?}"),
                        &["Use one of: passive, active, time_sensitive, critical."],
                    )
                })
            })
            .transpose()?;
        let resolved_level = self
            .resolved_level
            .map(|level| {
                DeliveryWindowResolvedLevel::parse(&level).ok_or_else(|| {
                    MemoryError::bad_request_with(
                        format!("unknown resolved level {level:?}"),
                        &["Use one of: plain_chat, push."],
                    )
                })
            })
            .transpose()?;
        Ok(OutboundScheduleContext {
            utc_offset_minutes: self.utc_offset_minutes,
            iana_timezone: self.iana_timezone,
            human_explicit_instant: self.human_explicit_instant,
            apns_interruption_level,
            resolved_level,
        })
    }
}

/// One calendar freebusy projection input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalendarFreebusyRequest {
    /// Calendar selectors.
    pub calendars: Vec<CalendarSel>,
    /// Range start, Unix seconds (inclusive).
    pub start: u64,
    /// Range end, Unix seconds (inclusive).
    pub end: u64,
}

/// One Dreamer attempt poll input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobRefRequest {
    /// 32-hex attempt id.
    pub job_ref: String,
}

/// One extractive ask over ranked recall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskRequest {
    /// The caller prose question, exactly as asked.
    pub question: String,
    /// World/facet narrowing; omitted means the vault floor.
    pub scope: Option<RecallScope>,
    /// Item ceiling; omitted means 10.
    pub limit: Option<usize>,
    /// OF-096 pack format, when rendering.
    pub format: Option<String>,
}

/// One SDK stub-documentation search.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchRequest {
    /// Substring matched against verb names and one-line docs.
    pub query: String,
    /// Maximum hits; omitted means 10.
    pub limit: Option<usize>,
}

/// One stub-documentation hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// Stable wire name (snake_case).
    pub wire: String,
    /// SDK method spelling (camelCase).
    pub sdk: String,
    /// Required scope (`read` | `write`).
    pub scope: String,
    /// One-line description.
    pub doc: String,
    /// The typed engine request.
    pub request_type: String,
    /// The typed engine response.
    pub response_type: String,
}

/// A bounded, read-only program of typed facade calls. Calls run in order
/// inside one host dispatch; no arbitrary guest code or authority is accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// The read instructions to evaluate. Nested execution is refused.
    pub calls: Vec<super::FacadeRequest>,
}

/// Results of a read program, in instruction order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Typed results of all instructions; the first failure stops execution.
    pub results: Vec<super::FacadeResponse>,
}

/// One per-artifact publish grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantArtifactPublishRequest {
    /// Artifact ref the grant covers.
    pub artifact: String,
    /// Grantee entity ref (short-id ref or hex).
    pub grantee_ref: String,
    /// Unix seconds.
    pub now: u64,
}

/// One publish-grant answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantArtifactPublishResponse {
    /// 32-hex id of the stored grant.
    pub grant_ref: String,
}

/// One Gmail per-message approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApproveGmailMessageRequest {
    /// Outbound intent ref the approval binds to.
    pub intent_ref: String,
    /// Sender identity entity ref (short-id ref or hex).
    pub identity_ref: String,
    /// Immutable message the approval binds to.
    pub message: crate::channel_identity_provider::gmail_send::GmailSendMessage,
}

/// The unit response, for verbs that answer only success.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitResponse {
    /// Always true; the verb answers only success.
    pub ok: bool,
}

fn receipts_limit<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
    Ok(Option::<usize>::deserialize(deserializer)?.unwrap_or_else(default_receipts_limit))
}

const fn default_receipts_limit() -> usize {
    100
}

/// Plans emergency rescheduling under the bound owner's authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEmergencyRescheduleRequest {
    pub request: crate::booking::emergency_reschedule::EmergencyRescheduleRequest,
    /// Calendar owners use canonical hex references.
    pub calendars: Vec<(String, Vec<CalendarSel>)>,
    pub now_utc: u64,
}
/// Full planning result, including per-event refusals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBatchPlanDto {
    pub plans: Vec<crate::booking::emergency_reschedule::EmergencyPlan>,
    pub refusals: Vec<(String, String)>,
}

/// One actor-bound batch of reaction pills.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPillsRequest {
    pub message_refs: Vec<String>,
    pub viewer_ref: Option<String>,
}
/// Reaction inbox cursor, bound to the facade actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionsSinceRequest {
    pub person_ref: Option<String>,
    pub since: u64,
}
/// One provider reaction event. Ingestion requires a system actor binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirroredReactionRequest {
    pub message_ref: String,
    pub by_ref: String,
    pub glyph: String,
    pub at: u64,
    pub ext: crate::conversation::reaction::ReactionExternalId,
}

/// Bounded reverse projection of artifact provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactsBornFromRequest {
    pub trigger_kind: String,
    pub trigger_ref: String,
    pub limit: usize,
}
