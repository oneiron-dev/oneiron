//! Moved from `crates/oneiron/src/campaign/surface/saved_query.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::query_records::surface::SavedQueryArchiveRequest;
pub use crate::memory::query_records::surface::SavedQueryEvaluateRequest;
pub use crate::memory::query_records::surface::SavedQueryMembersRequest;
pub use crate::memory::query_records::surface::SavedQueryMembershipPageView;
pub use crate::memory::query_records::surface::SavedQueryMembershipRowView;
pub use crate::memory::query_records::surface::SavedQueryMemoReceipt;
pub use crate::memory::query_records::surface::SavedQueryReadRequest;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::query_memos::MatchVerdict;
use serde::Deserialize;
use serde::Serialize;

/// One entity's manual-evaluation receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryEntityReceipt {
    /// The entity evaluated.
    pub entity_ref: EntityId,
    /// The verdict.
    pub verdict: MatchVerdict,
    /// Why the verdict was reached.
    pub why: String,
    /// Hex evidence hash the verdict is memoized under.
    pub evidence_hash: String,
    /// Whether a stored memo answered without running the matcher.
    pub memo_hit: bool,
    /// Whether a stage-2 judge actually ran for this entity.
    pub judge_ran: bool,
    /// The persisted memo under this evidence, when the verdict wrote or
    /// read one; an authority refusal is never memoized and carries none.
    pub memo: Option<SavedQueryMemoReceipt>,
    /// Newly measured judgment, with model pins and reported usage/cost.
    /// None for a hard matcher, an authority refusal or a memo hit.
    pub judge: Option<crate::saved_query::receipts::SavedQueryJudgeReceipt>,
}

/// `self.saved_query.evaluate`'s output: one bounded manual evaluation's
/// receipts, under the query owner's own read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryEvaluationReceipt {
    /// The saved query.
    pub query_ref: EntityId,
    /// The owner actor the evaluation ran as — never the viewer.
    pub owner_actor: EntityId,
    /// Definition version the evaluation ran against.
    pub definition_version: u64,
    /// Entities evaluated in this call.
    pub evaluated: u32,
    /// Evaluations answered by a memo (no new measurement).
    pub memo_hits: u32,
    /// Stage-2 judgements actually executed.
    pub judges_run: u32,
    /// Last entity visited when a per-wake bound stopped the call early;
    /// pass it back as `after` (of a candidates-less page) to continue.
    pub resume_after: Option<EntityId>,
    /// One receipt per evaluated entity, in evaluation order.
    pub outcomes: Vec<SavedQueryEntityReceipt>,
}
