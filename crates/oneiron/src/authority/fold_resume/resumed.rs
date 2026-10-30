//! The base's per-row reads a fold past it carries over the new chain's
//! states (OF-469). See [`Resumed`].

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::authority::fold_project::RowStates;

/// The base's per-row reads, carried over the chain's states: a resumed
/// fold's base, or an adopted checkpoint image's settled fold (OF-469).
pub(in crate::authority) struct Resumed<'a> {
    /// The valid machine profiles heading their own roster chain under an
    /// owner-held key, with that key, or as an admitted owner answer: the
    /// marks before custody is judged ([`MarkProof`]).
    pub(in crate::authority) marks: &'a [(AuthorityEntryHash, MarkProof)],
    /// The base's projected fold.
    pub(in crate::authority) fold: &'a AuthorityFold,
    /// The base's final merge's revocations, by key.
    pub(in crate::authority) revocations: &'a BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    /// The keys some main state of the base holds a live binding for.
    pub(in crate::authority) bound_keys: &'a BTreeSet<AuthorityKey>,
    /// The new main rows' states: the writer frontiers a projection adds,
    /// as a full fold's are main rows alone. A world key record's state
    /// still joins the merge and the writer census.
    pub(in crate::authority) chain: Vec<(AuthorityEntryHash, &'a FoldState)>,
    /// Every binding any state holds, by key, the new rows' included.
    pub(in crate::authority) writers: &'a BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    /// A frontier the base cannot answer: an earlier row may hold a binding
    /// the final one now judges differently.
    pub(in crate::authority) missed: Cell<bool>,
}

impl RowStates for Resumed<'_> {
    fn accepted_roster_marks(
        &self,
        merged: &FoldState,
        _valid: &BTreeSet<AuthorityEntryHash>,
    ) -> BTreeSet<AuthorityEntryHash> {
        // No chain row is a machine profile.
        self.marks
            .iter()
            .filter(|(_, proof)| proof.accepted(merged))
            .map(|(hash, _)| *hash)
            .collect()
    }

    fn revocation_affected_writers(&self, merged: &FoldState) -> BTreeSet<(EntityId, String)> {
        merged
            .actor_revocation_hashes
            .keys()
            .filter_map(|key| self.writers.get(key))
            .flatten()
            .cloned()
            .collect()
    }

    fn actor_write_frontiers(
        &self,
        merged: &FoldState,
        bindings: &BTreeMap<AuthorityKey, FoldedActorBinding>,
    ) -> BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>> {
        let mut out = BTreeMap::new();
        for (key, binding) in bindings {
            if binding.status != ActorBindingStatus::Active {
                continue;
            }
            let required = merged
                .actor_revocation_hashes
                .get(key)
                .cloned()
                .unwrap_or_default();
            let unchanged = self.fold.actor_bindings.get(key).is_some_and(|old| {
                old.status == ActorBindingStatus::Active
                    && old.actor_ref == binding.actor_ref
                    && old.actor_class == binding.actor_class
                    && self.revocations.get(key).cloned().unwrap_or_default() == required
            });
            let mut frontiers = if unchanged {
                self.fold
                    .actor_write_frontiers
                    .get(key)
                    .cloned()
                    .unwrap_or_default()
            } else {
                if self.bound_keys.contains(key) {
                    self.missed.set(true);
                }
                BTreeSet::new()
            };
            frontiers.extend(
                self.chain
                    .iter()
                    .filter(|(_, state)| {
                        crate::authority::causal_write::is_frontier(state, key, binding, &required)
                    })
                    .map(|(hash, _)| *hash),
            );
            out.insert(key.clone(), frontiers);
        }
        out
    }
}
