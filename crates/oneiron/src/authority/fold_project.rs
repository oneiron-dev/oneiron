//! The fold's projection: from the raw merge of the surviving rows' states to
//! the folded authority. The reference fold and a resumed fold share it, so
//! the two differ only in how they reach the merge.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::FoldContext;
use super::revoke_proof::RevokeFacts;
use super::*;
use crate::EntityId;

/// A settled fold before projection: the raw merge of the surviving rows'
/// states, before any restrictive fact, and what settlement decided.
pub(super) struct Settled<'a> {
    pub(super) merged: Option<FoldState>,
    pub(super) valid_entries: BTreeSet<AuthorityEntryHash>,
    pub(super) by_hash: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    /// Already filtered to the settled branches.
    pub(super) revoke_facts: &'a RevokeFacts,
    pub(super) retired_keys: BTreeSet<AuthorityKey>,
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    pub(super) unsettled: bool,
    pub(super) counted_ancestor_pairs: u64,
    pub(super) issues: Vec<AuthorityFoldIssue>,
}

/// What the projection reads of each surviving row's own state beside the
/// merge, given the final merged state.
pub(super) trait RowStates {
    fn accepted_roster_marks(
        &self,
        merged: &FoldState,
        valid: &BTreeSet<AuthorityEntryHash>,
    ) -> BTreeSet<AuthorityEntryHash>;
    fn revocation_affected_writers(&self, merged: &FoldState) -> BTreeSet<(EntityId, String)>;
    fn actor_write_frontiers(
        &self,
        merged: &FoldState,
        bindings: &BTreeMap<AuthorityKey, FoldedActorBinding>,
    ) -> BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>;
}

/// Every surviving row's state, as the reference fold holds them.
pub(super) struct AllStates<'a> {
    pub(super) by_hash: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pub(super) states: &'a BTreeMap<AuthorityEntryHash, FoldState>,
}

impl RowStates for AllStates<'_> {
    fn accepted_roster_marks(
        &self,
        merged: &FoldState,
        valid: &BTreeSet<AuthorityEntryHash>,
    ) -> BTreeSet<AuthorityEntryHash> {
        super::stale_roster::accepted_roster_marks(merged, self.by_hash, self.states, valid)
    }

    fn revocation_affected_writers(&self, merged: &FoldState) -> BTreeSet<(EntityId, String)> {
        super::causal_write::revocation_affected_writers(self.states, Some(merged))
    }

    fn actor_write_frontiers(
        &self,
        merged: &FoldState,
        bindings: &BTreeMap<AuthorityKey, FoldedActorBinding>,
    ) -> BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>> {
        super::causal_write::causal_actor_frontiers(self.states, Some(merged), bindings, |hash| {
            self.by_hash
                .get(hash)
                .is_some_and(|entry| super::world_privacy::side_world(&entry.op).is_none())
        })
    }
}

/// The folded authority, and the merge once its restrictive facts apply.
pub(super) fn project_once(
    settled: Settled<'_>,
    rows: &dyn RowStates,
    context: FoldContext<'_>,
) -> (AuthorityFold, Option<FoldState>) {
    let Settled {
        mut merged,
        valid_entries,
        by_hash,
        revoke_facts,
        retired_keys,
        closed_handoffs,
        unsettled,
        counted_ancestor_pairs,
        mut issues,
    } = settled;
    // Collision poison is part of the externally auditable fold result, not
    // merely a settlement-time guard. Emit one deterministic issue per id.
    if let Some(state) = &merged {
        issues.extend(
            state
                .conflicted_critical_write_confirms
                .iter()
                .map(
                    |confirm_id| AuthorityFoldIssue::CriticalWriteConfirmConflict {
                        confirm_id: *confirm_id,
                    },
                ),
        );
    }
    if let Some(state) = &mut merged {
        revoke_facts.apply_to(state);
        for key in &retired_keys {
            if let Some(device) = state.roster.get_mut(key) {
                device.revoked = true;
            }
        }
    }
    let machines = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        super::machine_claims::folded_machines(state, unsettled)
    });
    // A key is judged in this install's final trust set: the pin while the
    // fold holds its root, as the install sets it, else the roster.
    let world_keys = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        let local = context
            .pin
            .filter(|pin| {
                state
                    .root_anchors
                    .get(&pin.anchor_key)
                    .is_some_and(|ids| ids.contains(&pin.id))
            })
            .map_or(MachineAdmitter::Roster, |pin| {
                MachineAdmitter::Anchor(pin.anchor_key)
            });
        let stands = |machine: crate::EntityId| {
            machines
                .get(&machine)
                .is_some_and(|folded: &FoldedMachine| {
                    folded
                        .trust_chains(&local)
                        .iter()
                        .all(|(_, chain)| !chain.removed)
                })
        };
        super::world_key_fold::folded_world_keys(state, by_hash, &stands)
    });
    let actor_bindings = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        folded_actor_bindings(state, context.consent_arm)
    });

    let accepted_roster_marks = merged.as_ref().map_or_else(BTreeSet::new, |state| {
        rows.accepted_roster_marks(state, &valid_entries)
    });
    let fold = AuthorityFold {
        append_heads: BTreeSet::new(),
        anchor_heads: BTreeMap::new(),
        scope_heads: BTreeMap::new(),
        append_sequences: BTreeMap::new(),
        actor_revocation_affected_writers: merged.as_ref().map_or_else(BTreeSet::new, |state| {
            rows.revocation_affected_writers(state)
        }),
        actor_write_frontiers: merged.as_ref().map_or_else(BTreeMap::new, |state| {
            rows.actor_write_frontiers(state, &actor_bindings)
        }),
        revoked_actor_keys: merged.as_ref().map_or_else(BTreeSet::new, |state| {
            state.actor_revocation_hashes.keys().cloned().collect()
        }),
        slips: merged
            .as_ref()
            .map_or_else(SlipAuthorityState::default, |state| state.slips.clone()),
        vault_id: merged.as_ref().map(|state| state.vault_id),
        valid_entries,
        roster: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.roster.clone()),
        retired_keys,
        closed_handoffs,
        genesis_fragile: merged.as_ref().is_some_and(|state| {
            state.genesis_recovery_dismissed && !state.recovery_redundancy_established
        }),
        federation_pacts: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.federation_pacts.clone()),
        federation_confirms: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.federation_confirms.clone()),
        critical_write_confirms: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.critical_write_confirms.clone()),
        consumed_critical_write_confirm_nonces: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| {
                state.consumed_critical_write_confirm_nonces.clone()
            }),
        conflicted_critical_write_confirms: merged.as_ref().map_or_else(BTreeSet::new, |state| {
            state.conflicted_critical_write_confirms.clone()
        }),
        federation_grant_bindings: merged.as_ref().map_or_else(BTreeMap::new, |state| {
            state.federation_grant_bindings.clone()
        }),
        actor_bindings,
        machines,
        pinned_root: None,
        root_anchors: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.root_anchors.clone()),
        anchor_entries: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.anchor_entries.clone()),
        accepted_roster_marks,
        worlds: merged.as_ref().map_or_else(BTreeMap::new, |state| {
            super::world_privacy::folded_worlds(state, context.pin, context.machine_standing)
        }),
        refused_world_edits: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.refused_world_edits.clone()),
        grant_travel: merged.as_ref().map_or_else(BTreeMap::new, |state| {
            super::grant_travel::folded_grants(state, context.pin, context.machine_standing)
        }),
        refused_grant_travel: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.refused_grant_travel.clone()),
        checkpoint_policy: merged.as_ref().map_or_else(Default::default, |state| {
            super::checkpoint_choice::folded_checkpoint_policy(
                state,
                context.pin,
                context.machine_standing,
            )
        }),
        home_pick: merged.as_ref().map_or_else(Default::default, |state| {
            super::home_pick::folded_home_pick(state, context.pin, context.machine_standing)
        }),
        conversation_training: merged.as_ref().map_or_else(Default::default, |state| {
            super::conversation_training::folded_conversation_training(
                state,
                context.pin,
                context.machine_standing,
            )
        }),
        owner_work: merged.as_ref().map_or_else(Default::default, |state| {
            super::owner_work::folded_owner_work(state, context.pin, context.machine_standing)
        }),
        install: merged.as_ref().map_or_else(InstallBound::default, |state| {
            super::install_fold::held_back(state, context.pin, context.machine_standing)
        }),
        world_keys,
        refused_world_keys: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.refused_world_keys.clone()),
        counted_ancestor_pairs,
        issues,
    };
    (fold, merged)
}
