//! Log-derived, typed restrictive facts, independent of roster survivors: actor
//! revocations and machine removals.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// One fully verified restrictive fact. Scratch ancestry is proof only; it
/// never enters `valid_entries`, the roster, or the permissive merged state.
#[derive(Clone, Debug)]
struct VerifiedActorRevoke {
    vault_id: AuthorityVaultId,
    entry_hash: AuthorityEntryHash,
    authority_key: AuthorityKey,
    epoch: u64,
}

/// A verified machine removal: the machine's chains on the removal's own
/// branch, whose head is the terminal revision.
#[derive(Clone, Debug)]
struct VerifiedMachineRemoval {
    vault_id: AuthorityVaultId,
    machine: EntityId,
    chains: BTreeMap<MachineAdmitter, MachineChain>,
}

#[derive(Default)]
pub(super) struct RevokeFacts {
    by_hash: BTreeMap<AuthorityEntryHash, VerifiedActorRevoke>,
    removals: BTreeMap<AuthorityEntryHash, VerifiedMachineRemoval>,
}

impl RevokeFacts {
    /// Join only restrictions scoped to the surviving vault. The ordinary
    /// transition and this projection use the same max/union implementation.
    pub(super) fn apply_to(&self, state: &mut FoldState) {
        let vault_id = state.vault_id;
        for fact in self
            .by_hash
            .values()
            .filter(|fact| fact.vault_id == vault_id)
        {
            record_actor_revoke(state, &fact.authority_key, fact.epoch, fact.entry_hash);
        }
        for removal in self
            .removals
            .values()
            .filter(|removal| removal.vault_id == vault_id)
        {
            super::machine_profile::merge_machine_chains(state, removal.machine, &removal.chains);
        }
    }
}

/// A signed withdrawal that may cross rejected permissive ancestry.
pub(super) fn restrictive_withdrawal(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::RevokeActor { .. } => true,
        AuthorityOp::MachineProfile(profile) => profile.role == MachineRole::Removed,
        _ => false,
    }
}

/// Every candidate comes from the already signature-filtered entry graph.
/// The proof uses the same `fold_entry_state` and shared stalled-ancestor
/// evaluator as the ordinary fold, with only global winner selection removed.
/// Neither input arrival order nor a persisted node-local marker is involved.
pub(super) fn derive_revoke_facts(
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> RevokeFacts {
    let mut facts = RevokeFacts::default();
    for (hash, entry) in entries {
        if !restrictive_withdrawal(&entry.op) {
            continue;
        }
        let Some(state) = verify_signed_branch(*hash, entries, ancestors, context) else {
            continue;
        };
        match &entry.op {
            AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } => {
                facts.by_hash.insert(
                    *hash,
                    VerifiedActorRevoke {
                        vault_id: state.vault_id,
                        entry_hash: *hash,
                        authority_key: authority_key.clone(),
                        epoch: *epoch,
                    },
                );
            }
            AuthorityOp::MachineProfile(profile) => {
                if let Some(chains) = state.machines.get(&profile.machine) {
                    facts.removals.insert(
                        *hash,
                        VerifiedMachineRemoval {
                            vault_id: state.vault_id,
                            machine: profile.machine,
                            chains: chains.clone(),
                        },
                    );
                }
            }
            _ => {}
        }
    }
    facts
}

fn verify_signed_branch(
    target: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut pending = ancestors.get(&target)?.clone();
    pending.insert(target);
    let mut signer_seqs = BTreeMap::new();
    for hash in &pending {
        let entry = entries.get(hash)?;
        // A branch with internal signer equivocation cannot invent a merged
        // authority roster. External siblings may win the global projection,
        // but cannot erase a verified restrictive fact on this branch.
        if ancestors.get(hash)?.contains(hash)
            || signer_seqs
                .insert((entry.signer_key().clone(), entry.seq), *hash)
                .is_some_and(|other| other != *hash)
        {
            return None;
        }
    }
    let branch_context = FoldContext {
        entry_ancestors: Some(ancestors),
        ..context
    };
    let mut states = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    loop {
        let mut progressed = false;
        for hash in pending.clone() {
            match super::ancestry_evaluator::evaluate_entry(
                &entries[&hash],
                hash,
                entries,
                &states,
                branch_context,
                super::ancestry_evaluator::EvaluationPhase::Normal,
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_)
                    if hash != target
                        && super::ancestry_evaluator::skippable_permissive(&entries[&hash].op) =>
                {
                    rejected.insert(hash);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_) => return None,
                EntryFold::Waiting => {}
            }
        }
        if let Some(state) = states.remove(&target) {
            return Some(state);
        }
        if progressed {
            continue;
        }
        // Pending children of a rejected ancestor are not proof that the child
        // was valid. Only their signed links may be traversed, and their ops
        // never apply.
        let skipped: BTreeSet<_> = rejected
            .iter()
            .copied()
            .chain(pending.iter().copied().filter(|hash| {
                *hash != target
                    && super::ancestry_evaluator::skippable_permissive(&entries[hash].op)
                    && ancestors
                        .get(hash)
                        .is_some_and(|past| !past.is_disjoint(&rejected))
            }))
            .collect();
        let mut rescued = false;
        for hash in pending.clone() {
            if !restrictive_withdrawal(&entries[&hash].op) {
                continue;
            }
            if let EntryFold::Ready(state) = super::ancestry_evaluator::evaluate_entry(
                &entries[&hash],
                hash,
                entries,
                &states,
                branch_context,
                super::ancestry_evaluator::EvaluationPhase::Stalled(&skipped),
            ) {
                states.insert(hash, state);
                pending.remove(&hash);
                rescued = true;
            }
        }
        if !rescued {
            return None;
        }
    }
}
