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

#[doc(hidden)]
pub use oneiron_verb_wire::campaign::surface::saved_query::{
    SavedQueryEntityReceipt, SavedQueryEvaluationReceipt,
};

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
