//! Standing-query definitions, scope intersection and lifecycle values.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::filter::{FilterAst, MatcherSpec};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// Schema version of the definition shape this build reads and writes.
pub const SAVED_QUERY_SCHEMA_VERSION: u32 = 1;

/// A versioned saved-query definition.
///
/// Not serde-derived: [`EntityId`] has no serde impl and `entity_id.rs` is a CA
/// non-claim, so entity references cross the wire as canonical hex through
/// `definition_to_json` / `definition_from_json` — the same door CA-01 uses
/// for `CrmStageValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedQueryDefinition {
    /// Definition schema version.
    pub schema_version: u32,
    /// The principal whose reach bounds every evaluation of this query.
    pub owner_actor: EntityId,
    /// The class `owner_actor` was verified as when it created the query.
    /// Its read key is resolved under this class at every evaluation, and a
    /// judge's spend is charged to it.
    pub owner_actor_class: EdgeActorClass,
    /// Scope the owner DECLARED. The effective scope is this intersected with
    /// the owner's reach at evaluation time.
    pub scope: QueryScope,
    /// Monotonic version, incremented by every accepted update.
    pub definition_version: u64,
    /// Stage-1 filter.
    pub filter: FilterAst,
    /// Stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Execution policy and wake bounds.
    pub eval: EvalPolicy,
    /// Lifecycle state.
    pub lifecycle: SavedQueryLifecycle,
}

#[doc(hidden)]
use oneiron_verb_wire::memory::query_records::definition::intersect_axis;
#[doc(hidden)]
pub use oneiron_verb_wire::memory::query_records::definition::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, QueryScope, SavedQueryLifecycle,
    UpdateSavedQueryRequest,
};

/// A stored saved query.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedQueryRecord {
    /// Identity of the saved query.
    pub query_ref: EntityId,
    /// Current definition.
    pub definition: SavedQueryDefinition,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}
