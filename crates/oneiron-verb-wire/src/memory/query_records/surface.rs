//! Moved from `crates/oneiron/src/memory/query_records/surface.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::campaign_records::membership::MembershipReadRequest;
use crate::memory::campaign_records::membership::MembershipRowSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::query_memos::MatchVerdict;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// `self.saved_query.read`'s input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryReadRequest {
    /// The saved query.
    pub query_ref: EntityId,
}

/// `self.saved_query.archive`'s input. Archive keeps the query addressable;
/// there is no saved-query delete verb, by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryArchiveRequest {
    /// The saved query.
    pub query_ref: EntityId,
    /// Version the caller believes is current.
    pub expected_definition_version: u64,
}

/// `self.saved_query.members`'s input: one cursor-bounded page of the
/// membership this query derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembersRequest {
    /// The saved query.
    pub query_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Requested page size; 0 takes the default.
    #[serde(default)]
    pub limit: u32,
    /// Optional epoch ceiling: the cohort as of that membership epoch.
    #[serde(default)]
    pub at_epoch: Option<u64>,
}

impl SavedQueryMembersRequest {
    /// The engine page request this wire request reads.
    pub fn read_request(&self) -> MembershipReadRequest {
        MembershipReadRequest {
            owner_ref: self.query_ref,
            cursor: self.cursor.clone(),
            limit: self.limit,
            at_epoch: self.at_epoch,
        }
    }
}

/// `self.saved_query.evaluate`'s input: one manual, bounded evaluation of
/// the query under its owner's own read. Named `candidates` are evaluated
/// in order; with none, one page of the vault's people after `after` is,
/// bounded by the definition's own per-wake caps either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryEvaluateRequest {
    /// The saved query, which the caller must own.
    pub query_ref: EntityId,
    /// Entities to evaluate, in order; absent pages the vault's people.
    #[serde(default)]
    pub candidates: Vec<EntityId>,
    /// People-page cursor: the last person a prior evaluation visited.
    #[serde(default)]
    pub after: Option<EntityId>,
}

/// One entity's folded membership row on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembershipRowView {
    /// The member.
    pub entity_ref: EntityId,
    /// `entered` or `exited`.
    pub state: String,
    /// Valid time of the newest entry.
    pub entered_valid: u64,
    /// Detection time of the newest entry.
    pub entered_detected: u64,
    /// Valid time of the newest exit, when currently out.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest exit, when currently out.
    pub exited_detected: Option<u64>,
    /// Cause of the newest folded event.
    pub cause: Option<String>,
    /// Where the row comes from: on a query's page, always that query.
    pub source: MembershipRowSource,
}

/// One page of membership rows, as `self.saved_query.members` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembershipPageView {
    /// Rows in stable cursor order.
    pub rows: Vec<SavedQueryMembershipRowView>,
    /// Cursor for the next page; null when this page is the last.
    pub next_cursor: Option<String>,
}

/// One persisted verdict memo, as an evaluation receipt carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMemoReceipt {
    /// Definition version at evaluation time.
    pub definition_version: u64,
    /// Memoized verdict.
    pub verdict: MatchVerdict,
    /// Memoized justification.
    pub why: String,
    /// Hex evidence hash the verdict was derived from.
    pub content_hash: String,
    /// Model id for a judged verdict, or the matcher kind token otherwise.
    pub model_id: String,
    /// Evaluator version token.
    pub version: String,
    /// Hex digest of the canonical matcher specification.
    pub params_hash: String,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
}
