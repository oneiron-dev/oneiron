//! Log-derived, typed restrictive facts (actor revocations, slip withdrawals,
//! slip burns and machine removals), independent of roster survivors.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// One fully verified restrictive fact. Scratch ancestry is proof only; it
/// never enters `valid_entries`, the roster, or the permissive merged state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct VerifiedRestriction {
    vault_id: AuthorityVaultId,
    entry_hash: AuthorityEntryHash,
    kind: Restriction,
    /// The rows its proven branch folded through an owner anchor's branch.
    routed: BTreeSet<AuthorityEntryHash>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// A verified machine removal: the removing admitter's chain on the
    /// removal's own branch, whose head is the terminal revision. Only the
    /// removal itself travels: nothing else that branch held.
    MachineRemoval {
        machine: EntityId,
        admitter: MachineAdmitter,
        chain: Box<MachineChain>,
    },
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
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
                Restriction::MachineRemoval {
                    machine,
                    admitter,
                    chain,
                } => {
                    super::machine_profile::merge_machine_chain(state, *machine, *admitter, chain);
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
    for (hash, entry) in entries {
        let removal = match &entry.op {
            AuthorityOp::RevokeActor { .. } => false,
            op if removes_machine(op) => true,
            _ => continue,
        };
        // A removal is terminal on every replica. It vouches for its own
        // signed branch as a handoff vouches for its line: a local floor only
        // records which of a signer's rows this vault saw first, so the proof
        // applies none inside the branch and accepts what the fold accepts
        // when the branch arrives on its own, siblings at one sequence
        // included (Astra #1423b, Sol #1423 r8 and r9). A row of it past its
        // floor still lands restriction only: the proof's copy acknowledges
        // nothing the ordinary fold's copy does not (Astra #1430b). The fold
        // with no vouch (`floor_vouched: None`) vouches for no branch either
        // (Sol P2 round 18, F2).
        let removal_vouch = removal && context.floor_vouched.is_some();
        let branch: BTreeSet<_> = if removal_vouch {
            ancestors
                .get(hash)
                .into_iter()
                .flatten()
                .chain([hash])
                .copied()
                .collect()
        } else {
            BTreeSet::new()
        };
        let context = if removal_vouch {
            FoldContext {
                floor_vouched: Some(&branch),
                ..context
            }
        } else {
            context
        };
        let Some(state) = verify_signed_branch(*hash, entries, ancestors, context, !removal) else {
            continue;
        };
        let (vault_id, routed) = (state.vault_id, state.anchor_entries.clone());
        let kind = match &entry.op {
            AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } => Restriction::Actor {
                authority_key: authority_key.clone(),
                epoch: *epoch,
            },
            AuthorityOp::MachineProfile(profile) => {
                let Some((admitter, chain)) = state
                    .machines
                    .get(&profile.machine)
                    .into_iter()
                    .flatten()
                    .find(|(_, chain)| chain.head.entry == *hash)
                else {
                    continue;
                };
                Restriction::MachineRemoval {
                    machine: profile.machine,
                    admitter: *admitter,
                    chain: Box::new(MachineChain {
                        head: chain.head.clone(),
                        owner_held: chain.owner_held.clone().filter(|held| held.entry == *hash),
                        owner_held_removals: chain
                            .owner_held_removals
                            .iter()
                            .filter(|(_, removal)| removal.entry == *hash)
                            .map(|(signer, removal)| (signer.clone(), removal.clone()))
                            .collect(),
                        // The removal's own revision, past its floor here
                        // still: the proof never erases that mark (Astra
                        // #1430b).
                        revisions: chain
                            .revisions
                            .iter()
                            .filter(|(revision, _)| *revision == hash)
                            .map(|(revision, held)| (*revision, std::sync::Arc::clone(held)))
                            .collect(),
                    }),
                }
            }
            _ => continue,
        };
        facts.by_hash.insert(
            *hash,
            VerifiedRestriction {
                vault_id,
                entry_hash: *hash,
                kind,
                routed,
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
                    routed: state.anchor_entries,
                },
            );
        }
    }
}

impl RevokeFacts {
    /// Forgets every restriction that stands on a key a handoff retired: the
    /// old root revokes no actor and withdraws no slip the new root bound or
    /// minted, whatever its own old branch says. A row the proof took through
    /// an owner anchor's branch rests on that anchor (Wonder W3-F1).
    pub(super) fn forget_retired(
        &mut self,
        retirements: &super::retired_signers::Retirements,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) {
        self.by_hash
            .retain(|hash, fact| !retirements.excludes(hash, entries, ancestors, &fact.routed));
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
