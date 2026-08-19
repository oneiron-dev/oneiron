//! Entity lifecycle state ([`EntityLifecycleState`]), its CRDT join, the
//! zero-head-split ledger witness, and the vault-level lifecycle reads.

use std::collections::BTreeSet;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::vault::Vault;

use super::ledger_fold::{
    IdentityTopologyAction, fold_effective_identity_topology_events_for_store_in_txn,
    fold_identity_topology_log,
};
use super::op_vocabulary::IdentityTopologyOp;
use super::store_entity_helpers::{
    identity_topology_event_for_store_in_txn, identity_topology_events_for_store_in_txn,
};
use super::stored_event::StoredIdentityOpAction;

/// Entity lifecycle state derived from the identity-topology op log.
///
/// `Merged` / `Split` are REDIRECT-SHELL states, not tombstones: the entity
/// body stays fully readable forever and no `TombstoneReason` exists for
/// them (merge-away is not deletion — ARCH-0055 §10 vs ARCH-0038).
///
/// The derive order is the pinned CRDT join precedence
/// (`Active < Merged < Split`); see [`merge_lifecycle_states`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityLifecycleState {
    /// Live identity — the default; every op may target it.
    Active,
    /// Redirect shell left behind by a merge (r1): resolves to exactly one
    /// surviving head through the `merged_into` edge.
    Merged,
    /// Redirect shell left behind by a split (r2): resolves to its head SET
    /// through `split_into` edges (Senzing 0/1/N stable-id semantics).
    Split,
}

impl EntityLifecycleState {
    /// The pinned on-disk / wire string for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Merged => "merged",
            Self::Split => "split",
        }
    }

    /// Parses the pinned wire string back into a state.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "merged" => Some(Self::Merged),
            "split" => Some(Self::Split),
            _ => None,
        }
    }

    /// `true` for the redirect-shell states (`Merged` / `Split`).
    #[must_use]
    pub const fn is_redirect_shell(self) -> bool {
        matches!(self, Self::Merged | Self::Split)
    }

    /// Legal DIRECT transitions (the `ChannelIdentityState` house shape):
    /// `Active → Merged` (merge source), `Active → Split` (split original),
    /// and each shell back to `Active` (undo counter-event). Shells never
    /// transition into each other without passing through `Active` — an
    /// undo-then-reapply, both on the ledger. [`evaluate_transition`](super::evaluate_transition) and
    /// the fold's undo arm produce exactly these moves.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::Merged)
                | (Self::Active, Self::Split)
                | (Self::Merged, Self::Active)
                | (Self::Split, Self::Active)
        )
    }
}

/// Commutative, associative, idempotent join of two concurrently folded
/// lifecycle states (the `merge_pact_states` analogue for this family).
///
/// Fixed precedence `Split > Merged > Active`: a shell state observed on
/// either replica is never lost to a concurrent `Active` (the op happened;
/// its ledger event survives the join), and between concurrent shells the
/// split wins because it preserves the finer topology — residue stays
/// readable through all heads, while carrying the merge instead would
/// conflate referents, the one failure the family's precision bias exists
/// to avoid ("false merges are poison", research-0904 via ARCH-0055 §1).
/// The discarded op's event stays on the ledger and can be re-applied after
/// an undo. `max` over a total order is commutative, associative, and
/// idempotent by construction.
#[must_use]
pub fn merge_lifecycle_states(
    left: EntityLifecycleState,
    right: EntityLifecycleState,
) -> EntityLifecycleState {
    left.max(right)
}

/// Entities the ledger currently holds in a ZERO-HEAD split shell — the one
/// topology arm that leaves no `split_into` edge, so the type-76 log is its
/// only witness (ONE-1744). Everything that would otherwise read shell truth
/// from the edges alone consults this for that arm: the lifecycle read and
/// the redirect projection both do.
///
/// Derived from the EFFECTIVE fold, so an undone or superseded zero-head
/// split correctly drops out of the set.
/// Conservative "a zero-head split has been recorded in this vault" marker.
///
/// The witness fold below is O(event family), and the apply door needs the
/// answer for every participant of every op — which would make a run of N
/// topology ops O(N²). Zero-head splits are RARE, so this marker buys the
/// common case back: absent means none has ever been recorded, and the fold
/// is skipped entirely.
///
/// It is set, never cleared: an undone or evicted zero-head split leaves it
/// standing. That direction is the safe one — a stale-SET marker costs one
/// fold that returns the empty set, while a stale-CLEAR marker would hide a
/// live shell. Correctness never depends on it, only cost.
pub(crate) const IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY: &[u8] =
    b"m:identity_topology_zero_head_seen";

/// Records that a zero-head split exists, arming the witness fold.
pub(crate) fn note_zero_head_split_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    if store
        .vault_meta
        .get(&*wtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY)?
        .is_some()
    {
        return Ok(());
    }
    store
        .vault_meta
        .put(wtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY, &[1])?;
    Ok(())
}

/// [`zero_head_split_shells_for_store_in_txn`] behind the marker: skips the
/// fold outright on a vault that has never recorded a zero-head split.
pub(crate) fn zero_head_split_shells_if_any_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    if store
        .vault_meta
        .get(rtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY)?
        .is_none()
    {
        return Ok(BTreeSet::new());
    }
    zero_head_split_shells_for_store_in_txn(store, rtxn)
}

pub(crate) fn zero_head_split_shells_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let effective = fold_effective_identity_topology_events_for_store_in_txn(store, rtxn)?;
    let fold = fold_identity_topology_log(&effective);
    let mut shells = BTreeSet::new();
    for (entity, event_id) in &fold.current_event {
        if fold.states.get(entity) != Some(&EntityLifecycleState::Split) {
            continue;
        }
        let record = identity_topology_event_for_store_in_txn(store, rtxn, event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if matches!(&record.action, StoredIdentityOpAction::Split { heads, .. } if heads.is_empty())
        {
            shells.insert(*entity);
        }
    }
    Ok(shells)
}

pub(crate) fn identity_topology_shell_peers_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    entity: &EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(entity, kind);
    let mut peers = Vec::new();
    for (scanned, entry) in store.edges_out.prefix_iter(rtxn, &prefix)?.enumerate() {
        if scanned >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("identity topology"));
        }
        let (key, value) = entry?;
        peers.push(crate::edge::parse_strict_edge_record(&key, &value)?.target);
    }
    Ok(peers)
}

/// Every entity the SURVIVING type-76 apply family names as a shell-edge
/// source. This is the reconciler's touched set: the ids whose
/// `merged_into` / `split_into` rows the current ledger can still speak for.
/// It is also the redirect projection's rebuild candidate set (ONE-1744) —
/// the same derivation, since an entity with no topology event has no
/// redirect row either.
pub(crate) fn shell_edge_sources_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let stored_events = identity_topology_events_for_store_in_txn(store, rtxn)?;
    let mut touched = BTreeSet::new();
    for event in &stored_events {
        match &event.action {
            IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(merge)) => {
                touched.extend(merge.sources.iter().copied());
            }
            IdentityTopologyAction::Apply(IdentityTopologyOp::Split(split)) => {
                touched.insert(split.entity);
            }
            // Neither a counter-event nor a resolution names a shell-edge
            // source of its own: the undo's sources come from the event it
            // reverts, and an approved op is applied as its own event.
            IdentityTopologyAction::Apply(
                IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_),
            )
            | IdentityTopologyAction::Undo { .. }
            | IdentityTopologyAction::ResolveProposal { .. } => {}
        }
    }
    Ok(touched)
}

impl Vault {
    /// Entities the ledger currently holds in a zero-head split shell — see
    /// [`zero_head_split_shells_for_store_in_txn`].
    pub(crate) fn zero_head_split_shells_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        zero_head_split_shells_if_any_for_store_in_txn(&self.store, rtxn)
    }

    /// Current lifecycle state of `id`, read from its canonical redirect
    /// edges (D11: the edge is the state witness for every op that leaves
    /// one; the ledger fold and the apply path keep them in lockstep). An id
    /// with no shell edge is `Active` — EXCEPT the zero-head split, which
    /// shells its entity while writing no edge at all, so the ledger is
    /// consulted for exactly that arm (ONE-1744).
    pub fn entity_lifecycle_state(&self, id: &EntityId) -> Result<EntityLifecycleState> {
        let rtxn = self.store.env.read_txn()?;
        self.entity_lifecycle_state_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::entity_lifecycle_state`]. Fails
    /// closed with `CorruptedIndex` when an id carries BOTH shell edge
    /// kinds or more than one `merged_into` target — states no apply path
    /// can produce (a merge redirects to exactly ONE canonical head; only
    /// a split resolves to a set).
    pub(crate) fn entity_lifecycle_state_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<EntityLifecycleState> {
        self.entity_lifecycle_state_with_zero_head_shells_in_txn(rtxn, id, None)
    }

    /// [`Vault::entity_lifecycle_state_in_txn`] with a caller-supplied
    /// zero-head-shell witness. A caller resolving several ids against one
    /// txn folds the (rare, quota-bounded) event family ONCE and passes the
    /// set here; `None` folds it on demand, and only when the edges leave
    /// the question open.
    pub(crate) fn entity_lifecycle_state_with_zero_head_shells_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        zero_head_shells: Option<&BTreeSet<EntityId>>,
    ) -> Result<EntityLifecycleState> {
        let merged = self.filtered_edge_peers(
            rtxn,
            &self.store.edges_out,
            id,
            EdgeKind::MergedInto,
            None,
            "identity topology",
        )?;
        let split = self.filtered_edge_peers(
            rtxn,
            &self.store.edges_out,
            id,
            EdgeKind::SplitInto,
            None,
            "identity topology",
        )?;
        match (merged.len(), split.is_empty()) {
            // No shell edge: live, UNLESS the ledger holds a zero-head split
            // over this id. Without this the retired entity would read back
            // `Active` and the apply door would admit an op the fold then
            // rejects `NotActive` — ledger and edge truth diverging, which is
            // the wedge the reconciler exists to prevent.
            (0, true) => {
                let is_zero_head_shell = match zero_head_shells {
                    Some(shells) => shells.contains(id),
                    None => self.zero_head_split_shells_in_txn(rtxn)?.contains(id),
                };
                if is_zero_head_shell {
                    Ok(EntityLifecycleState::Split)
                } else {
                    Ok(EntityLifecycleState::Active)
                }
            }
            (1, true) => Ok(EntityLifecycleState::Merged),
            (0, false) => Ok(EntityLifecycleState::Split),
            _ => Err(Error::CorruptedIndex("identity topology shell")),
        }
    }
}
