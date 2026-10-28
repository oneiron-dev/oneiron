//! What the checkpoint image build keeps of the last once fold (OF-469,
//! checkpoint v2), and what an act's causal points read of a capture at
//! arbitrary heads: see [`ImageFold`].

use std::collections::{BTreeMap, BTreeSet};

use super::super::checkpoint_image::{AUTHORITY_REPLAY_OVERFLOW, ReplayEvidence, parents_first_of};
use super::super::*;
use super::{OnceParts, add_bound_keys, add_writers};

/// What the checkpoint image build keeps of the last once fold (OF-469,
/// checkpoint v2): the fold state at each frontier row, not only at one main
/// head, and the merge, projection and safety indexes a fold past the image
/// reads. Unlike [`Once`] it asks for no single head and no settled main row:
/// an image holds forks and rejected rows as they are.
pub(in crate::authority) struct ImageFold {
    /// Each frontier row's state; None for a row the fold holds none for.
    pub(in crate::authority) per_parent: BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    /// The state at each judged row off the frontier, for an image's replay
    /// evidence (FIX 3007); [`ReplayEvidence::FrontierOnly`] on a capture
    /// that keeps none.
    pub(in crate::authority) replay: ReplayEvidence,
    /// The merge of every surviving state, before any restrictive fact.
    pub(in crate::authority) merged: FoldState,
    /// The projected once fold, before any install's stale window.
    pub(in crate::authority) fold: AuthorityFold,
    pub(in crate::authority) safety: crate::authority::checkpoint_image::CheckpointSafety,
}

impl ImageFold {
    pub(super) fn of(
        parts: OnceParts<'_>,
        frontier: &BTreeSet<AuthorityEntryHash>,
        replay: bool,
    ) -> Option<Self> {
        let OnceParts {
            by_hash,
            states,
            entry_ancestors,
            original_floors: _,
            merged,
            valid_entries,
            revoke_facts,
            retired_keys,
            closed_handoffs,
            unsettled,
            counted_ancestor_pairs,
            issues,
            final_merged,
            fold,
        } = parts;
        let final_merged = final_merged?;
        let is_main = |hash: &AuthorityEntryHash| {
            by_hash.get(hash).is_some_and(|entry| {
                crate::authority::world_privacy::side_world(&entry.op).is_none()
            })
        };
        let issuers =
            crate::authority::log_structure::authority_structure(by_hash.values()).issuers;
        let uncounted = by_hash
            .iter()
            .filter(|(_, entry)| crate::authority::log_budget::is_uncounted(entry, &issuers))
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        let mut writers = BTreeMap::<_, BTreeSet<_>>::new();
        let mut bound_keys = BTreeSet::new();
        let (mut confirm_ids, mut confirm_nonces) = (BTreeSet::new(), BTreeSet::new());
        for (hash, state) in states {
            add_writers(&mut writers, state);
            if is_main(hash) {
                add_bound_keys(&mut bound_keys, state);
            }
            if let Some(AuthorityOp::FederationConfirm(action)) =
                by_hash.get(hash).map(|entry| &entry.op)
            {
                confirm_ids.insert(action.confirm_id);
                confirm_nonces.insert(action.nonce);
            }
        }
        let marks = valid_entries
            .iter()
            .filter_map(|hash| {
                let AuthorityOp::MachineProfile(profile) = &by_hash.get(hash)?.op else {
                    return None;
                };
                let chain = states
                    .get(hash)?
                    .machines
                    .get(&profile.machine)?
                    .get(&MachineAdmitter::Roster)?;
                MarkProof::of(&chain.head)
                    .filter(|_| chain.head.entry == *hash)
                    .map(|proof| (*hash, proof))
            })
            .collect();
        let missing_parents = by_hash
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| !by_hash.contains_key(*parent))
            .copied()
            .collect();
        let frontier_ancestry = frontier
            .iter()
            .filter_map(|hash| {
                let past = entry_ancestors.get(hash)?;
                let counted = past.iter().filter(|row| !uncounted.contains(*row)).count();
                Some((*hash, (past.len() as u64, counted as u64)))
            })
            .collect();
        let safety = crate::authority::checkpoint_image::CheckpointSafety {
            pairs: entry_ancestors.values().map(|past| past.len() as u64).sum(),
            counted_pairs: counted_ancestor_pairs,
            frontier_ancestry,
            issuers,
            uncounted,
            revoke_facts,
            retired_keys,
            closed_handoffs,
            unsettled,
            issues,
            missing_parents,
            marks,
            revocations: final_merged.actor_revocation_hashes.clone(),
            writers,
            bound_keys,
            confirm_ids,
            confirm_nonces,
            nonce_provenance: merged.critical_write_confirm_nonce_provenance.clone(),
        };
        Some(Self {
            replay: if replay {
                replay_of(by_hash, states, frontier)
            } else {
                ReplayEvidence::FrontierOnly
            },
            per_parent: frontier
                .iter()
                .map(|hash| (*hash, states.get(hash).cloned()))
                .collect(),
            merged,
            fold: fold.clone(),
            safety,
        })
    }
}

/// The replay points of every judged row off `frontier`, from the settled
/// states; [`AUTHORITY_REPLAY_OVERFLOW`] where a state does not encode.
fn replay_of(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    frontier: &BTreeSet<AuthorityEntryHash>,
) -> ReplayEvidence {
    let parents: BTreeMap<_, _> = by_hash
        .iter()
        .filter(|(hash, _)| !frontier.contains(*hash))
        .map(|(hash, entry)| (*hash, entry.parent_hashes.clone()))
        .collect();
    ReplayEvidence::points_of(
        &parents_first_of(&parents),
        &|hash| parents.get(hash).cloned(),
        &|hash| states.get(hash).cloned(),
        &BTreeMap::new(),
    )
    .map_or(AUTHORITY_REPLAY_OVERFLOW, ReplayEvidence::Rows)
}
