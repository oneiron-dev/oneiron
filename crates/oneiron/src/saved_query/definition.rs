use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::campaign::CRM_PACK_ID;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{StructuralKindRegistration, TypeByteZone};

// Referenced only by an intra-doc link on `QueryScope::admits`; gated so the
// name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use super::evaluator::SavedQueryEvaluator;
use super::filter::{FilterAst, MatcherSpec};

/// Stable short-id namespace for SAVED_QUERY entities. Two lowercase ASCII
/// letters per the short-id convention; a namespace token, never a type byte.
pub const SAVED_QUERY_SHORT_ID_PREFIX: &str = "sq";

/// Schema version of the definition shape this build reads and writes.
pub const SAVED_QUERY_SCHEMA_VERSION: u32 = 1;

/// Registers the SAVED_QUERY structural kind for a NEW vault.
///
/// `assigned_type_byte` comes from the byte-space-v3 registration flow run by
/// the vault/pack initializer; this module never chooses, infers, or hard-codes
/// a byte. Mirrors [`crate::campaign::register_campaign_kind`] exactly: the CRM
/// pack has ONE identity, and both kinds enter through the same registrar.
///
/// # Errors
///
/// Propagates the existing registration errors unchanged — a byte outside the
/// `Crm` band yields `StructuralKindZoneViolation`, and a taken byte or prefix
/// yields `StructuralKindTypeByteCollision` / `StructuralKindPrefixCollision`.
/// SAVED_QUERY adds no registration failure mode of its own.
pub fn register_saved_query_kind(
    vault: &Vault,
    assigned_type_byte: u8,
) -> Result<StructuralKindRegistration> {
    vault.register_structural_kind(
        assigned_type_byte,
        SAVED_QUERY_SHORT_ID_PREFIX,
        TypeByteZone::CompiledProduct,
        CRM_PACK_ID,
    )
}

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
fn intersect_axis<T: Clone + Ord>(declared: &[T], granted: &[T]) -> Option<Vec<T>> {
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
/// [`Self::Reactive`] is STORED but not wired: reactive delivery adopts OF-241
/// when it exists. Until then every mode executes through the same explicit
/// on-demand and bounded-wake calls, so a reactive query is never silently
/// inert — it is evaluated by whatever calls the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
