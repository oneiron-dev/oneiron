use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;

#[cfg(test)]
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;

pub(crate) const TASK_BODY_ROLE_KEY: &str = "role";

/// Pinned TASK role byte for the productivity pack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskRole {
    Task = 1,
    Goal = 2,
    Milestone = 3,
    Habit = 4,
    HabitCheckin = 5,
}

impl TaskRole {
    pub const ALL: [Self; 5] = [
        Self::Task,
        Self::Goal,
        Self::Milestone,
        Self::Habit,
        Self::HabitCheckin,
    ];

    #[must_use]
    pub const fn role_byte(self) -> u8 {
        match self {
            Self::Task => 1,
            Self::Goal => 2,
            Self::Milestone => 3,
            Self::Habit => 4,
            Self::HabitCheckin => 5,
        }
    }

    #[must_use]
    pub const fn from_role_byte(role: u8) -> Option<Self> {
        match role {
            1 => Some(Self::Task),
            2 => Some(Self::Goal),
            3 => Some(Self::Milestone),
            4 => Some(Self::Habit),
            5 => Some(Self::HabitCheckin),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn task_body_for_test(role: TaskRole) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("writing MessagePack TASK body to Vec cannot fail");
    bytes
}

pub(crate) fn task_role_from_body_bytes(bytes: &[u8]) -> crate::error::Result<TaskRole> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| crate::error::Error::InvalidTaskBody("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(crate::error::Error::InvalidTaskBody(
            "trailing bytes after body map",
        ));
    }
    let entries = value.as_map().ok_or(crate::error::Error::InvalidTaskBody(
        "body must be a MessagePack map",
    ))?;
    let mut role = None;
    for (key, value) in entries {
        let key = key.as_str().ok_or(crate::error::Error::InvalidTaskBody(
            "body keys must be strings",
        ))?;
        if key != TASK_BODY_ROLE_KEY {
            continue;
        }
        if role.is_some() {
            return Err(crate::error::Error::InvalidTaskBody(
                "duplicate task role key",
            ));
        }
        let role_byte = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(crate::error::Error::InvalidTaskBody(
                "task role must be a byte",
            ))?;
        role = Some(
            TaskRole::from_role_byte(role_byte)
                .ok_or(crate::error::Error::InvalidTaskBody("unknown task role"))?,
        );
    }
    role.ok_or(crate::error::Error::InvalidTaskBody("missing task role"))
}

/// A scored entity result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredEntity {
    /// Entity identifier.
    pub id: EntityId,
    /// Ranking score.
    pub score: f32,
}

/// Retrieval signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum FieldProfile {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    pub entity_type: u8,
    pub score: f32,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
    /// Candidates assigned the low gravity signal because they had vector
    /// similarity above the cosine-ghost threshold and no BM25 text channel
    /// presence.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records silently excluded by the D19 read-path status gate
    /// (ARCH-0003: surface only `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false`) or by the fail-closed type-0 body decode, across
    /// the pipeline stage and pack hydration (results + neighbors). A claim
    /// suppressed in both stages counts once per stage.
    pub claims_suppressed: usize,
    /// Token accounting populated by serialization/projection paths.
    ///
    /// Raw `ContextPackBuilder::run()` results are not serialized and leave
    /// this as `PackTokenStats::default()`. Use serialized/projection builder
    /// paths when exact output-token accounting is required.
    pub tokens: PackTokenStats,
    pub items_truncated: PackItemAccounting,
    pub items_dropped: PackItemAccounting,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackTokenStats {
    /// Stable tokenizer identifier used for every count in this struct.
    ///
    /// Empty when stats came from an unserialized raw pack.
    pub tokenizer_id: String,
    /// Exact token count of the final serialized context-pack bytes.
    ///
    /// This includes format envelope, separators, and serialized stats when
    /// they are emitted.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    ///
    /// Section counts are computed from the row-level accounting text used by
    /// budget allocation. They intentionally exclude format envelope and
    /// separators, so their sum is not expected to equal `total_tokens`.
    pub sections: Vec<PackSectionTokenStats>,
    /// Per-item row-token accounting.
    ///
    /// Item counts use the same row-level basis as `sections`, not exact
    /// emitted substrings for each output format.
    pub items: Vec<PackItemTokenStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSectionTokenStats {
    /// Logical section name, for example `results`, `neighbors`, or `merged`.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item, including the content-hash suffix.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackItemAccountingReason {
    ItemBudget,
    TokenBudget,
}

impl PackItemAccountingReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemBudget => "item_budget",
            Self::TokenBudget => "token_budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackItemAccounting {
    pub count: usize,
    pub reason: PackItemAccountingReason,
}

impl PackItemAccounting {
    #[must_use]
    pub fn item_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::ItemBudget,
        }
    }

    #[must_use]
    pub fn token_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::TokenBudget,
        }
    }
}

/// Machine-readable reason an otherwise successful context-pack query surfaced
/// no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Stable deletion reason surfaced by short-id hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

/// Where hydrate found deletion evidence for a short-id row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Deletion metadata returned when a short-id row resolves to deleted state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HydratedShortIdDeletion {
    pub source: HydratedShortIdDeletionSource,
    pub reason: Option<HydratedShortIdDeletionReason>,
    pub deleted_at: Option<u64>,
    pub request_id: Option<String>,
    pub hard: bool,
}

/// Renderer-facing lifecycle state for one record in a memory timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimelineRecordState {
    /// The record exists and is not closed by the supersession graph.
    Live,
    /// The record exists and has been superseded by at least one newer record.
    Superseded,
    /// The record exists as explicitly retracted claim history.
    Retracted,
    /// The record exists only as a deletion shell with tombstone metadata.
    Deleted,
    /// The graph still references an entity id whose record is absent locally.
    Missing,
}

/// One node in a bitemporal supersession timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimelineRecord {
    pub id: EntityId,
    pub state: MemoryTimelineRecordState,
    pub entity_type: Option<u8>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub body_bytes: Option<usize>,
    pub deletion: Option<HydratedShortIdDeletion>,
    pub supersedes: Vec<EntityId>,
    pub superseded_by: Vec<EntityId>,
}

/// Stable, ordered supersession-chain data for one anchor entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimeline {
    pub anchor: EntityId,
    pub records: Vec<MemoryTimelineRecord>,
}

/// Human-readable memory verbs exposed by API surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMemoryVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

impl NamedMemoryVerb {
    /// Parses a public route verb, accepting stable aliases while resolving to
    /// one canonical typed operation family.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "remember" | "put" | "put_entity" => Some(Self::Remember),
            "supersede" | "replace" | "revise" | "supersede_claim" => Some(Self::Supersede),
            "retract" | "withdraw" | "retract_claim" => Some(Self::Retract),
            "delete" | "forget" | "soft_delete" | "user_delete" => Some(Self::Delete),
            "hard_delete" | "erase" | "purge" | "user_hard_delete" => Some(Self::HardDelete),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Remember => "remember",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Delete => "delete",
            Self::HardDelete => "hard_delete",
        }
    }

    pub const fn operation_kind(self) -> MemoryOperationKind {
        match self {
            Self::Remember => MemoryOperationKind::PutEntity,
            Self::Supersede => MemoryOperationKind::SupersedeClaim,
            Self::Retract => MemoryOperationKind::RetractClaim,
            Self::Delete | Self::HardDelete => MemoryOperationKind::DeleteEntity,
        }
    }
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Structured context for an empty context-pack response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyContext {
    pub reason: EmptyReason,
    pub total_in_scope: usize,
    pub hint: String,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
    pub empty: Option<EmptyContext>,
}

pub const EIRI_CONTEXT_VERSION_V4: &str = "v4";

/// Stable Eiri Context v4 memory-board slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EiriMemoryBoardSlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

impl EiriMemoryBoardSlot {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::Turns => "turns",
            Self::Summaries => "summaries",
            Self::Facets => "facets",
            Self::Companions => "companions",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Claims => 0,
            Self::Turns => 1,
            Self::Summaries => 2,
            Self::Facets => 3,
            Self::Companions => 4,
            Self::Other => 5,
        }
    }
}

/// Source section for one memory-board row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EiriMemoryBoardSource {
    Result,
    Neighbor,
}

impl EiriMemoryBoardSource {
    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Result => 0,
            Self::Neighbor => 1,
        }
    }
}

/// Per-slot row caps for an Eiri Context v4 memory board.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub companions: usize,
    pub other: usize,
}

impl EiriMemoryBoardBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        companions: usize,
        other: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            companions,
            other,
        }
    }

    #[must_use]
    pub const fn get(self, slot: EiriMemoryBoardSlot) -> usize {
        match slot {
            EiriMemoryBoardSlot::Claims => self.claims,
            EiriMemoryBoardSlot::Turns => self.turns,
            EiriMemoryBoardSlot::Summaries => self.summaries,
            EiriMemoryBoardSlot::Facets => self.facets,
            EiriMemoryBoardSlot::Companions => self.companions,
            EiriMemoryBoardSlot::Other => self.other,
        }
    }

    pub fn increment(&mut self, slot: EiriMemoryBoardSlot) {
        let counter = match slot {
            EiriMemoryBoardSlot::Claims => &mut self.claims,
            EiriMemoryBoardSlot::Turns => &mut self.turns,
            EiriMemoryBoardSlot::Summaries => &mut self.summaries,
            EiriMemoryBoardSlot::Facets => &mut self.facets,
            EiriMemoryBoardSlot::Companions => &mut self.companions,
            EiriMemoryBoardSlot::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Companion scope that influenced Eiri Context v4 assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriCompanionAssembly {
    pub caller: Option<String>,
    pub scope: Option<String>,
    pub scope_source: Option<String>,
    pub person_ref: Option<String>,
    pub persona_ref: Option<String>,
    pub expression: Option<String>,
}

/// One stable row in the Eiri Context v4 memory board.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardRow {
    pub row_index: usize,
    pub slot: EiriMemoryBoardSlot,
    pub source: EiriMemoryBoardSource,
    pub id: String,
    pub short_id: String,
    pub content_hash: String,
    pub entity_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub score: f32,
}

/// Deterministic Eiri Context v4 memory-board envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoard {
    pub version: String,
    pub budget: EiriMemoryBoardBudget,
    pub rows: Vec<EiriMemoryBoardRow>,
    pub companion: Option<EiriCompanionAssembly>,
}

/// Session-scoped RAG cursor returned by Eiri Context v4 surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriSessionRagState {
    pub session_id: String,
    pub revision: u64,
    pub query_count: u64,
    pub last_retrieval_run_id: Option<String>,
    pub last_result_ids: Vec<String>,
}

impl EiriSessionRagState {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            revision: 0,
            query_count: 0,
            last_retrieval_run_id: None,
            last_result_ids: Vec::new(),
        }
    }
}

impl Default for EiriSessionRagState {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Read-only ambient context returned by the companion resume endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionContext {
    pub api_version: String,
    pub counts: BTreeMap<String, u64>,
    pub last_activity: Option<u64>,
    #[serde(default)]
    pub rag_state: EiriSessionRagState,
}

/// Pending notification surfaced during companion resume hydration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NotificationItem {
    pub id: String,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Existing work item that still needs caller-side processing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnprocessedItem {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Token meter snapshot included in every companion resume bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBudget {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub tokens_remaining: u64,
}

impl ResumeBudget {
    #[must_use]
    pub fn from_meter(tokens_used: u64, tokens_limit: u64) -> Self {
        Self {
            tokens_used,
            tokens_limit,
            tokens_remaining: tokens_limit.saturating_sub(tokens_used),
        }
    }
}

/// Single-call companion hydration bundle.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBundle {
    pub session: SessionContext,
    pub notifications: Vec<NotificationItem>,
    pub unprocessed: Vec<UnprocessedItem>,
    pub budget: ResumeBudget,
}

impl ResumeBundle {
    #[must_use]
    pub fn new(
        session: SessionContext,
        notifications: Vec<NotificationItem>,
        unprocessed: Vec<UnprocessedItem>,
        budget: ResumeBudget,
    ) -> Self {
        Self {
            session,
            notifications,
            unprocessed,
            budget,
        }
    }
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.45,
            turns: 0.10,
            summaries: 0.25,
            other: 0.20,
        }
    }
}

/// Item budget for context-pack retrieval before the final global truncation.
///
/// Primary entity budgets are enforced per retrieval kind after query filters
/// and before `limit` truncation. `selected_edges` caps edge-walk neighbor
/// selection; it is not an entity type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextPackRetrievalBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub other: usize,
    pub selected_edges: usize,
}

impl ContextPackRetrievalBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        other: usize,
        selected_edges: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            other,
            selected_edges,
        }
    }

    #[must_use]
    pub fn from_limit(
        result_limit: usize,
        allocation: TokenAllocation,
        selected_edges: usize,
    ) -> Self {
        let split_other = allocation.other / 2.0;
        let weights = [
            allocation.claims,
            allocation.turns,
            allocation.summaries,
            split_other,
            split_other,
        ];
        let mut budgets = allocate_context_pack_item_budgets(result_limit, weights);
        if result_limit > 0 {
            for (budget, weight) in budgets.iter_mut().zip(weights) {
                if *budget == 0 && weight.is_finite() && weight > 0.0 {
                    *budget = 1;
                }
            }
        }
        Self {
            claims: budgets[0],
            turns: budgets[1],
            summaries: budgets[2],
            facets: budgets[3],
            other: budgets[4],
            selected_edges,
        }
    }
}

fn allocate_context_pack_item_budgets(limit: usize, weights: [f32; 5]) -> [usize; 5] {
    if limit == 0 {
        return [0; 5];
    }

    let mut sanitized = [0.0_f32; 5];
    for (index, weight) in weights.into_iter().enumerate() {
        if weight.is_finite() && weight > 0.0 {
            sanitized[index] = weight;
        }
    }

    let total_weight: f32 = sanitized.iter().sum();
    if total_weight <= 0.0 {
        let base = limit / sanitized.len();
        let mut budgets = [base; 5];
        for budget in budgets.iter_mut().take(limit % sanitized.len()) {
            *budget = budget.saturating_add(1);
        }
        return budgets;
    }

    let mut budgets = [0_usize; 5];
    let mut remainders = [(0_usize, 0.0_f32); 5];
    let mut allocated = 0_usize;
    for (index, weight) in sanitized.iter().copied().enumerate() {
        if weight <= 0.0 {
            continue;
        }
        let exact = (limit as f32) * (weight / total_weight);
        let whole = exact.floor() as usize;
        budgets[index] = whole;
        remainders[index] = (index, exact - whole as f32);
        allocated = allocated.saturating_add(whole);
    }

    let mut leftover = limit.saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        if sanitized[index] > 0.0 {
            budgets[index] = budgets[index].saturating_add(1);
            leftover -= 1;
        }
    }
    budgets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_role_from_body_bytes_rejects_malformed_bodies() {
        fn encode(value: &Value) -> Vec<u8> {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, value).expect("encode msgpack test body");
            bytes
        }

        let role_byte = TaskRole::Task.role_byte();

        // A map carrying two "role" entries: decoders that resolve first-vs-last
        // key differently must not silently disagree; this is rejected outright.
        let duplicate_role = encode(&Value::Map(vec![
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
        ]));
        match task_role_from_body_bytes(&duplicate_role) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "duplicate task role key");
            }
            other => panic!("expected duplicate-role-key rejection, got {other:?}"),
        }

        let non_map = encode(&Value::from(role_byte));
        match task_role_from_body_bytes(&non_map) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body must be a MessagePack map");
            }
            other => panic!("expected non-map rejection, got {other:?}"),
        }

        let non_string_key = encode(&Value::Map(vec![(
            Value::from(1_u64),
            Value::from(role_byte),
        )]));
        match task_role_from_body_bytes(&non_string_key) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body keys must be strings");
            }
            other => panic!("expected non-string-key rejection, got {other:?}"),
        }
    }

    #[test]
    fn context_pack_retrieval_budget_default_token_allocation_splits_other_weight() {
        let budget = ContextPackRetrievalBudget::from_limit(20, TokenAllocation::default(), 7);

        assert_eq!(budget.claims, 9);
        assert_eq!(budget.turns, 2);
        assert_eq!(budget.summaries, 5);
        assert_eq!(budget.facets, 2);
        assert_eq!(budget.other, 2);
        assert_eq!(budget.selected_edges, 7);
    }

    #[test]
    fn context_pack_retrieval_budget_default_small_limit_keeps_positive_buckets_eligible() {
        let budget = ContextPackRetrievalBudget::from_limit(3, TokenAllocation::default(), 0);

        assert!(budget.claims > 0);
        assert!(budget.turns > 0);
        assert!(budget.summaries > 0);
        assert!(budget.facets > 0);
        assert!(budget.other > 0);
    }
}
