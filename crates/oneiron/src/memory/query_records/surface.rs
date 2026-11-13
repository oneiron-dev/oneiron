//! Wire request, record, membership and memo values for standing queries.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatchVerdict,
    MatcherSpec, QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryLifecycle, SavedQueryRecord,
    UpdateSavedQueryRequest,
};
use crate::entity_id::EntityId;
use crate::memory::campaign_records::{
    MembershipPage, MembershipReadRequest, MembershipRow, MembershipRowSource,
};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::query_records::surface::{
    SavedQueryArchiveRequest, SavedQueryDefinitionView, SavedQueryEvalSpec,
    SavedQueryEvaluateRequest, SavedQueryFilterSpec, SavedQueryMatcherSpec,
    SavedQueryMembersRequest, SavedQueryMembershipPageView, SavedQueryMembershipRowView,
    SavedQueryMemoReceipt, SavedQueryReadRequest, SavedQueryReadResult, SavedQueryRecordView,
    SavedQueryScopeSpec, SavedQueryUpdateRequest,
};

/// `self.saved_query.create`'s input. There is no owner field: the owner is
/// the bound actor, bound at the write boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryCreateRequest {
    /// Definition schema version; 1.
    #[serde(default = "saved_query_schema_version")]
    pub schema_version: u32,
    /// Declared scope; absent is unrestricted.
    #[serde(default)]
    pub scope: SavedQueryScopeSpec,
    /// Stage-1 filter.
    pub filter: SavedQueryFilterSpec,
    /// Stage-2 matcher.
    pub matcher: SavedQueryMatcherSpec,
    /// Execution policy.
    pub eval: SavedQueryEvalSpec,
}

impl SavedQueryCreateRequest {
    /// The engine request this wire request writes.
    pub(crate) fn engine_request(&self) -> CreateSavedQueryRequest {
        CreateSavedQueryRequest {
            schema_version: self.schema_version,
            scope: self.scope.scope(),
            filter: self.filter.filter(),
            matcher: self.matcher.matcher(),
            eval: self.eval.policy(),
        }
    }
}

const fn saved_query_schema_version() -> u32 {
    SAVED_QUERY_SCHEMA_VERSION
}

/// The wire record of a stored saved query.
pub(crate) fn saved_query_record_view(record: &SavedQueryRecord) -> SavedQueryRecordView {
    SavedQueryRecordView {
        query_ref: record.query_ref,
        definition: SavedQueryDefinitionView {
            schema_version: record.definition.schema_version,
            owner_actor: record.definition.owner_actor,
            scope: SavedQueryScopeSpec::of(&record.definition.scope),
            definition_version: record.definition.definition_version,
            filter: SavedQueryFilterSpec::of(&record.definition.filter),
            matcher: SavedQueryMatcherSpec::of(&record.definition.matcher),
            eval: SavedQueryEvalSpec::of(record.definition.eval),
            lifecycle: record.definition.lifecycle.clone(),
        },
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

/// The wire page of a membership page.
pub(crate) fn saved_query_membership_page_view(
    page: &MembershipPage,
) -> SavedQueryMembershipPageView {
    SavedQueryMembershipPageView {
        rows: page.rows.iter().map(membership_row_view).collect(),
        next_cursor: page.next_cursor.clone(),
    }
}

fn membership_row_view(row: &MembershipRow) -> SavedQueryMembershipRowView {
    SavedQueryMembershipRowView {
        entity_ref: row.entity_ref,
        state: row.state.clone(),
        entered_valid: row.entered_valid,
        entered_detected: row.entered_detected,
        exited_valid: row.exited_valid,
        exited_detected: row.exited_detected,
        cause: row.cause.clone(),
        source: row.source.clone(),
    }
}
