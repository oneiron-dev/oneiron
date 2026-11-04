//! The world-access authority values (ONE-1420): one authority set of base
//! reality plus sorted, unique world ids, the per-turn world selection, and
//! one resolution's three tiers with their claim provenance. The claim
//! layer (`claim::world_access`) encodes, decodes and resolves them; the
//! agent definitions and the read pipeline carry them.
use std::collections::BTreeSet;

use oneiron_authority::federation::{ScopeAxis, ScopeId};
use oneiron_contracts::claim::base_world_id;

use crate::entity_id::EntityId;
use crate::error::Result;

/// One world-access authority value: base reality plus a sorted, unique set of
/// world ids.
///
/// The same shape carries all three tiers — the owner's ALLOWED-SET, the
/// stored DEFAULT-SUBSET, and the per-turn ActiveSet — so subset checking is
/// one predicate ([`WorldAuthoritySet::is_subset_of`]) rather than three.
/// [`Default`] is the EMPTY authority (`include_base == false`, no worlds):
/// the fail-closed value an absent grant resolves to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorldAuthoritySet {
    /// Whether base reality — claims with no `world` key, and every non-claim
    /// entity — is readable under this set.
    include_base: bool,
    /// The readable world ids. Sorted and unique by construction.
    worlds: BTreeSet<EntityId>,
}

impl WorldAuthoritySet {
    /// Builds an authority set from any world-id iterator, normalizing it to
    /// sorted-unique order. Every world is kept, however many a scope selects
    /// (FIX 8668).
    ///
    /// # Errors
    ///
    /// None today: a set of any size is valid.
    pub fn new(include_base: bool, worlds: impl IntoIterator<Item = EntityId>) -> Result<Self> {
        Ok(Self {
            include_base,
            worlds: worlds.into_iter().collect(),
        })
    }

    /// Whether base reality is readable under this set.
    #[must_use]
    pub fn include_base(&self) -> bool {
        self.include_base
    }

    /// The readable world ids in sorted, unique order.
    #[must_use]
    pub fn worlds(&self) -> &BTreeSet<EntityId> {
        &self.worlds
    }

    /// This authority as the One Scope worlds axis: base reality is the
    /// ordinary member `base_world_id` (R13), and an empty set is bottom.
    /// Base has its own boolean here: a listed id equal to the reserved base
    /// id cannot stand in for it.
    #[must_use]
    pub fn scope_axis(&self) -> ScopeAxis<ScopeId> {
        let base = base_world_id();
        self.worlds
            .iter()
            .filter(|id| **id != base)
            .copied()
            .chain(self.include_base.then_some(base))
            .map(ScopeId)
            .collect()
    }

    /// A Scope worlds axis as an authority set, or `None` when the axis is
    /// open: an open axis names no worlds to list.
    ///
    /// # Errors
    ///
    /// None today: [`Self::new`] keeps a named set of any size.
    pub fn from_scope_axis(axis: &ScopeAxis<ScopeId>) -> Result<Option<Self>> {
        let base = ScopeId(base_world_id());
        match axis {
            ScopeAxis::All => Ok(None),
            ScopeAxis::Bottom => Ok(Some(Self::default())),
            ScopeAxis::Some(ids) => Self::new(
                ids.contains(&base),
                ids.iter().filter(|id| **id != base).map(|id| id.0),
            )
            .map(Some),
        }
    }

    /// What both sets admit: the meet on the Scope worlds axis. It holds no
    /// more worlds than either.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        // Two named sets meet at a named set or bottom, never the open axis.
        Self::from_scope_axis(&self.scope_axis().meet(&other.scope_axis()))
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Membership of an ordinary claim world, or base reality for non-claims:
    /// the worlds axis's `contains`, without building the axis per row.
    pub(crate) fn admits(&self, world: Option<EntityId>) -> bool {
        match world.filter(|world| *world != base_world_id()) {
            Some(world) => self.worlds.contains(&world),
            None => self.include_base,
        }
    }

    /// Whether every member of `self` is also a member of `allowed`: the
    /// Scope worlds axis's narrowing order.
    ///
    /// Base reality is a MEMBER of this containment, not a side channel:
    /// asking for base without an owner grant for base is a widening and is
    /// refused like any world id would be.
    #[must_use]
    pub fn is_subset_of(&self, allowed: &Self) -> bool {
        self.scope_axis().is_narrowing_of(&allowed.scope_axis())
    }

    /// Whether this authority admits nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scope_axis().is_bottom()
    }
}

/// The per-turn world selection carried on [`crate::pipeline::PipelineBuilder`] — in memory for
/// exactly one query, never written to the vault.
///
/// `agent_ref` names the CLAIM subject whose stored authority rows the
/// resolver reads; it is not itself a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWorldSelection {
    /// The agent entity the ALLOWED-SET / DEFAULT-SUBSET rows are about.
    pub agent_ref: EntityId,
    /// `None` means use the resolved DEFAULT-SUBSET.
    pub selected: Option<WorldAuthoritySet>,
}

/// The outcome of one authority resolution: the three tiers plus the claim
/// provenance each tier came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorldAuthority {
    /// The owner grant: the intersection of every qualifying ALLOWED-SET row.
    pub allowed_set: WorldAuthoritySet,
    /// The stored default, already checked against `allowed_set`.
    pub default_subset: WorldAuthoritySet,
    /// What this turn actually reads: the explicit selection, else the default.
    pub active_set: WorldAuthoritySet,
    /// The ALLOWED-SET claim rows folded into `allowed_set`, in scan order.
    pub allowed_claim_ids: Vec<EntityId>,
    /// The DEFAULT-SUBSET claim row `default_subset` was read from.
    pub default_claim_id: Option<EntityId>,
}
