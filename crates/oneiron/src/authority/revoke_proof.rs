//! Log-derived, typed restrictive facts (actor revocations, slip withdrawals
//! and slip burns), independent of roster survivors.

use std::collections::{BTreeMap, BTreeSet};

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
            }
        }
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
        let AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } = &entry.op
        else {
            continue;
        };
        if let Some(state) = verify_signed_branch(*hash, entries, ancestors, context) {
            facts.by_hash.insert(
                *hash,
                VerifiedRestriction {
                    vault_id: state.vault_id,
                    entry_hash: *hash,
                    kind: Restriction::Actor {
                        authority_key: authority_key.clone(),
                        epoch: *epoch,
                    },
                },
            );
        }
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
            let Some(state) = verify_signed_branch(*hash, entries, ancestors, context) else {
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

/// The target's own folded state, proved over its signed ancestry alone.
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
            if !matches!(
                entries[&hash].op,
                AuthorityOp::RevokeActor { .. }
                    | AuthorityOp::SlipRevoke { .. }
                    | AuthorityOp::SlipConsume { .. }
            ) {
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
