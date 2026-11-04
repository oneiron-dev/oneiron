//! Wire shapes of the six saved-query verbs (`self.saved_query.*`).
//!
//! These are the SDK rows' own input and output types. Their JSON is the
//! shape the resource routes already take (`/saved-queries`), decoded there
//! by `invoke_campaign_surface` and here by the verb table, so every door
//! accepts the same documents. The engine's own definition types carry
//! entity ids bare and are not serde-derived; this file only moves between
//! the wire and those types — filter validation, the version CAS and the
//! archive transition stay CA-02's, and evaluation stays
//! [`crate::saved_query::SavedQueryEvaluator`]'s.

use crate::entity_id::EntityId;
use crate::saved_query::{MatchVerdict, VerdictMemoRow};
use serde::{Deserialize, Serialize};

pub use crate::memory::query_records::surface::SavedQueryArchiveRequest;
pub use crate::memory::query_records::surface::SavedQueryCreateRequest;
pub use crate::memory::query_records::surface::SavedQueryDefinitionView;
pub use crate::memory::query_records::surface::SavedQueryEvalSpec;
pub use crate::memory::query_records::surface::SavedQueryEvaluateRequest;
pub use crate::memory::query_records::surface::SavedQueryFilterSpec;
pub use crate::memory::query_records::surface::SavedQueryMatcherSpec;
pub use crate::memory::query_records::surface::SavedQueryMembersRequest;
pub use crate::memory::query_records::surface::SavedQueryMembershipPageView;
pub use crate::memory::query_records::surface::SavedQueryMembershipRowView;
pub use crate::memory::query_records::surface::SavedQueryMemoReceipt;
pub use crate::memory::query_records::surface::SavedQueryReadRequest;
pub use crate::memory::query_records::surface::SavedQueryReadResult;
pub use crate::memory::query_records::surface::SavedQueryRecordView;
pub use crate::memory::query_records::surface::SavedQueryScopeSpec;
pub use crate::memory::query_records::surface::SavedQueryUpdateRequest;

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
    pub judge: Option<crate::saved_query::SavedQueryJudgeReceipt>,
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

pub(crate) use crate::memory::query_records::surface::saved_query_membership_page_view;
pub(crate) use crate::memory::query_records::surface::saved_query_record_view;

/// The wire receipt of a persisted verdict memo.
#[must_use]
pub fn saved_query_memo_receipt(row: &VerdictMemoRow) -> SavedQueryMemoReceipt {
    SavedQueryMemoReceipt {
        definition_version: row.definition_version,
        verdict: row.verdict,
        why: row.why.clone(),
        content_hash: row.envelope.content_hash.clone(),
        model_id: row.envelope.model_id.clone(),
        version: row.envelope.version.clone(),
        params_hash: row.envelope.params_hash.clone(),
        evaluated_at: row.evaluated_at,
    }
}
