//! Moved from `crates/oneiron/src/memory/query_records/definition.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::query_records::filter::FilterAst;
use crate::memory::query_records::filter::MatcherSpec;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// World/facet reach.
///
/// An EMPTY axis means "unrestricted on that axis", which is what makes
/// [`QueryScope::intersect`] total: intersecting an unrestricted axis with a
/// restricted one yields the restricted one, and intersecting two disjoint
/// restricted axes yields an axis that is restricted to nothing — the
/// fail-closed case [`QueryScope::is_closed_against`] names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryScope {
    /// WORLD entities in reach; empty means unrestricted.
    pub worlds: Vec<EntityId>,
    /// Facet tokens in reach; empty means unrestricted.
    pub facets: Vec<String>,
}

impl QueryScope {
    /// Intersects a DECLARED scope with a grant scope, per-axis.
    ///
    /// Returns `None` when an axis both sides restricted intersects to nothing:
    /// that is a closed scope, distinct from the unrestricted empty axis, and
    /// the caller must fail closed rather than treat it as "no restriction".
    #[must_use]
    pub fn intersect(&self, grants: &Self) -> Option<Self> {
        let worlds = intersect_axis(&self.worlds, &grants.worlds)?;
        let facets = intersect_axis(&self.facets, &grants.facets)?;
        Some(Self { worlds, facets })
    }

    /// Whether intersecting this DECLARED scope with `grants` closes an axis.
    #[must_use]
    pub fn is_closed_against(&self, grants: &Self) -> bool {
        self.intersect(grants).is_none()
    }

    /// Whether an entity carrying `membership` is inside THIS scope.
    ///
    /// `membership` is the entity's own world/facet reach as
    /// [`SavedQueryEvaluator`] observed it — its `in_world` and `has_facet`
    /// edges, narrowed to this scope. A restricted axis demands a witness on
    /// that axis, so an entity with no world membership at all is OUTSIDE a
    /// world-scoped query rather than universally inside it. An unrestricted
    /// axis admits everything, which is what makes the default scope total.
    #[must_use]
    pub fn admits(&self, membership: &Self) -> bool {
        let axis_admits = |declared: &[EntityId], held: &[EntityId]| {
            declared.is_empty() || held.iter().any(|value| declared.contains(value))
        };
        axis_admits(&self.worlds, &membership.worlds)
            && (self.facets.is_empty()
                || membership
                    .facets
                    .iter()
                    .any(|facet| self.facets.contains(facet)))
    }
}

/// Per-axis intersection with the "empty means unrestricted" rule.
pub fn intersect_axis<T: Clone + Ord>(declared: &[T], granted: &[T]) -> Option<Vec<T>> {
    let sorted = |values: &[T]| values.iter().cloned().collect::<BTreeSet<T>>();
    match (declared.is_empty(), granted.is_empty()) {
        (true, true) => Some(Vec::new()),
        (true, false) => Some(sorted(granted).into_iter().collect()),
        (false, true) => Some(sorted(declared).into_iter().collect()),
        (false, false) => {
            let granted = sorted(granted);
            let kept = sorted(declared)
                .into_iter()
                .filter(|value| granted.contains(value))
                .collect::<Vec<T>>();
            (!kept.is_empty()).then_some(kept)
        }
    }
}

/// Execution mode and per-wake bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalPolicy {
    /// Declared execution mode.
    pub mode: EvalMode,
    /// Hard cap on entities visited per wake batch.
    pub max_entities_per_wake: u32,
    /// Hard cap on stage-2 LLM judgements per wake batch.
    pub max_judges_per_wake: u32,
}

/// Declared execution mode.
///
/// A host re-checks a [`Self::Reactive`] query for each person a claim write
/// moves, read off the vault's change log
/// ([`super::saved_query_changes_after`]), and still sweeps it in bounded
/// wakes for what that feed cannot see; OF-241's live-query tee may replace
/// the feed when it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalMode {
    /// Re-evaluate when relevant evidence moves.
    Reactive,
    /// Re-evaluate on enrollment epochs / wake batches.
    Wake,
    /// Re-evaluate only when explicitly asked.
    Manual,
}

impl EvalMode {
    /// Wire token for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reactive => "reactive",
            Self::Wake => "wake",
            Self::Manual => "manual",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reactive" => Some(Self::Reactive),
            "wake" => Some(Self::Wake),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// Lifecycle state of a saved query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SavedQueryLifecycle {
    /// Evaluable.
    Active,
    /// Held with a visible error. Pack drift that cannot be repaired lands
    /// here rather than silently disabling or partially evaluating the query.
    Paused {
        /// Operator-visible reason.
        error: String,
    },
    /// Explicitly switched off by an owner. Unlike archive, a watch flag
    /// can be switched back on without minting a second query identity.
    Disabled,
    /// Retired. Archive is a transition, not a deletion: the record stays
    /// addressable for ONE-1778.
    Archived,
}

impl SavedQueryLifecycle {
    /// Whether a query in this state may be evaluated.
    #[must_use]
    pub const fn is_evaluable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Create request. There is no owner field: the owner is bound from the
/// authenticated principal at the write boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateSavedQueryRequest {
    /// Definition schema version.
    pub schema_version: u32,
    /// Declared scope.
    pub scope: QueryScope,
    /// Stage-1 filter.
    pub filter: FilterAst,
    /// Stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Execution policy.
    pub eval: EvalPolicy,
}

/// Update request. Also carries no owner field.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateSavedQueryRequest {
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement scope.
    pub scope: QueryScope,
    /// Replacement stage-1 filter.
    pub filter: FilterAst,
    /// Replacement stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Replacement execution policy.
    pub eval: EvalPolicy,
}
