//! Log-derived, typed restrictive facts (actor revocations, slip withdrawals,
//! slip burns and machine removals), independent of roster survivors.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// One fully verified restrictive fact. Scratch ancestry is proof only; it
/// never enters `valid_entries`, the roster, or the permissive merged state.
#[derive(Clone, Debug)]
struct VerifiedRestriction {
    vault_id: AuthorityVaultId,
    entry_hash: AuthorityEntryHash,
    kind: Restriction,
}

#[derive(Clone, Debug)]
enum Restriction {
    Actor {
        authority_key: AuthorityKey,
        epoch: u64,
    },
    /// A verified `SlipRevoke`: the withdrawn id.
    SlipRevoke([u8; 32]),
    /// A verified `SlipConsume`: every id its proven branch had burnt, the
    /// single-use ancestors it spent among them.
    SlipBurn(BTreeSet<[u8; 32]>),
    /// A verified machine removal: the machine's chains on the removal's own
    /// branch, whose head is the terminal revision.
    MachineRemoval {
        machine: EntityId,
        chains: BTreeMap<MachineAdmitter, MachineChain>,
    },
}

#[derive(Default)]
pub(super) struct RevokeFacts {
    by_hash: BTreeMap<AuthorityEntryHash, VerifiedRestriction>,
}

impl RevokeFacts {
    /// Join only restrictions scoped to the surviving vault. The ordinary
    /// transition and this projection use the same max/union implementation:
    /// every set here only grows, so a restriction proved on its own signed
    /// branch stays applied whichever sibling wins the projection.
    pub(super) fn apply_to(&self, state: &mut FoldState) {
        let vault_id = state.vault_id;
        for fact in self
            .by_hash
            .values()
            .filter(|fact| fact.vault_id == vault_id)
        {
            match &fact.kind {
                Restriction::Actor {
                    authority_key,
                    epoch,
                } => record_actor_revoke(state, authority_key, *epoch, fact.entry_hash),
                Restriction::SlipRevoke(slip_id) => {
                    state.slips.revoked.insert(*slip_id);
                    state.slips.explicit_revoked.insert(*slip_id);
                }
                Restriction::SlipBurn(burnt) => {
                    state.slips.consumed.extend(burnt.iter().copied());
                }
                Restriction::MachineRemoval { machine, chains } => {
                    super::machine_profile::merge_machine_chains(state, *machine, chains);
                }
            }
        }
    }
}

/// A signed withdrawal that may cross rejected permissive ancestry.
pub(super) fn restrictive_withdrawal(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::RevokeActor { .. }
        | AuthorityOp::SlipRevoke { .. }
        | AuthorityOp::SlipConsume { .. } => true,
        op => removes_machine(op),
    }
}

pub(super) fn removes_machine(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile) if profile.role == MachineRole::Removed)
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
    let mut removal_floors = None;
    for (hash, entry) in entries {
        let removal = match &entry.op {
            AuthorityOp::RevokeActor { .. } => false,
            op if removes_machine(op) => true,
            _ => continue,
        };
        // A removal's ancestry is the ancestry the fold accepted, siblings at
        // one sequence and removals that arrived late included (Astra
        // #1423b, Sol #1423 r8).
        let context = match context.sequence_floors {
            Some(floors) if removal => FoldContext {
                sequence_floors: Some(
                    removal_floors.get_or_insert_with(|| floors_without_removals(entries, floors)),
                ),
                ..context
            },
            _ => context,
        };
        let Some(state) = verify_signed_branch(*hash, entries, ancestors, context, !removal) else {
            continue;
        };
        let kind = match &entry.op {
            AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } => Restriction::Actor {
                authority_key: authority_key.clone(),
                epoch: *epoch,
            },
            AuthorityOp::MachineProfile(profile) => {
                let Some(chains) = state.machines.get(&profile.machine) else {
                    continue;
                };
                Restriction::MachineRemoval {
                    machine: profile.machine,
                    chains: chains.clone(),
                }
            }
            _ => continue,
        };
        facts.by_hash.insert(
            *hash,
            VerifiedRestriction {
                vault_id: state.vault_id,
                entry_hash: *hash,
                kind,
            },
        );
    }
    facts
}

impl RevokeFacts {
    /// Adds the slip withdrawals and burns the projection dropped. Selecting
    /// one of two colliding confirmations removes the loser and every entry
    /// after it, a `SlipRevoke` or `SlipConsume` among them, and a revoked or
    /// spent slip would live again. An entry in `survivors` already applied
    /// its restriction through the ordinary fold; each dropped one is proved
    /// on its own signed branch, as an actor revocation is.
    pub(super) fn add_dropped_slip_restrictions(
        &mut self,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
        context: FoldContext<'_>,
        survivors: &BTreeMap<AuthorityEntryHash, FoldState>,
    ) {
        for (hash, entry) in entries {
            if survivors.contains_key(hash) {
                continue;
            }
            let restriction = match &entry.op {
                AuthorityOp::SlipRevoke { slip_id } => Restriction::SlipRevoke(*slip_id),
                AuthorityOp::SlipConsume { .. } => Restriction::SlipBurn(BTreeSet::new()),
                _ => continue,
            };
            let Some(state) = verify_signed_branch(*hash, entries, ancestors, context, false)
            else {
                continue;
            };
            let kind = match restriction {
                Restriction::SlipBurn(_) => Restriction::SlipBurn(state.slips.consumed),
                other => other,
            };
            self.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind,
                },
            );
        }
    }
}

impl RevokeFacts {
    /// Forgets every restriction that stands on a key a handoff retired: the
    /// old root revokes no actor and withdraws no slip the new root bound or
    /// minted, whatever its own old branch says.
    pub(super) fn forget_retired(
        &mut self,
        retirements: &super::retired_signers::Retirements,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) {
        self.by_hash
            .retain(|hash, _| !retirements.excludes(hash, entries, ancestors));
    }

    /// Forgets every restriction proved through a handoff that did not take
    /// effect. The heir a refused or pruned ReRoot names was never root, so
    /// it restricts nothing, however its own branch folds; a restriction the
    /// fold dropped counts only when every ReRoot in its ancestry `settled`.
    pub(super) fn forget_unsettled(
        &mut self,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) {
        self.by_hash.retain(|hash, _| {
            settled.contains_key(hash)
                || ancestors.get(hash).is_some_and(|line| {
                    line.iter().all(|ancestor| {
                        settled.contains_key(ancestor)
                            || !entries
                                .get(ancestor)
                                .is_some_and(|row| matches!(row.op, AuthorityOp::ReRoot { .. }))
                    })
                })
        });
    }
}

/// The local sequence floors less every machine removal's. A removal is
/// terminal on every replica, and a floor only records which of its signer's
/// rows arrived first, so a sibling seen earlier never refuses a removal; every
/// other row keeps its floor.
fn floors_without_removals(
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    floors: &BTreeMap<AuthorityEntryHash, u64>,
) -> BTreeMap<AuthorityEntryHash, u64> {
    floors
        .iter()
        .filter(|(hash, _)| {
            !entries
                .get(*hash)
                .is_some_and(|entry| removes_machine(&entry.op))
        })
        .map(|(hash, floor)| (*hash, *floor))
        .collect()
}

/// The target's own folded state, proved over its signed ancestry alone.
/// `refuse_equal_sequences` refuses a branch holding two entries of one signer
/// at one sequence, as an actor revocation's proof always has. A slip
/// restriction's or machine removal's proof follows the fold instead, which
/// admits concurrent siblings at one sequence and refuses only a sequence
/// that does not rise along the ancestry.
fn verify_signed_branch(
    target: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
    refuse_equal_sequences: bool,
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
            || (refuse_equal_sequences
                && signer_seqs
                    .insert((entry.signer_key().clone(), entry.seq), *hash)
                    .is_some_and(|other| other != *hash))
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
