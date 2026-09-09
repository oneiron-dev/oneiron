//! Scheduling gates, stalled-revocation bypass with freeze classifier, and chain probe.
//!
//! MUST BE READ TOGETHER WITH [`super::super::entry_transition`]. The two files are
//! mutually recursive by direct call; any fork, quorum, or equivocation correctness
//! change has to be reasoned about across both files.

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;

pub(in crate::authority) fn entry_waits_on_unresolved_equivocation(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let signer = entry.signer_key();
    context
        .unresolved_equivocation_groups
        .iter()
        .any(|(fork_key, fork_seq)| {
            // Raw claimed ancestry is sufficient only for scheduling: a
            // candidate must not make the parent it claims wait on that same
            // candidate. Quarantine exemptions use chain-validated ancestry.
            if entry_is_claimed_prefork_or_fork_candidate(context, fork_key, *fork_seq, hash) {
                return false;
            }
            (fork_key == signer && *fork_seq < entry.seq)
                || entry
                    .cosigns
                    .iter()
                    .any(|signature| signature.public_key == *fork_key)
                || matches!(&entry.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == fork_key)
                || (*fork_seq < entry.seq
                    && recovery_reboot_is_entangled_with_fork(entry, fork_key))
        })
}

fn recovery_reboot_is_entangled_with_fork(
    entry: &AuthorityLogEntry,
    fork_key: &AuthorityKey,
) -> bool {
    if !matches!(&entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    // Resolve earlier groups involving a reboot participant first so
    // quarantined authority cannot authorize recovery. Unrelated groups and
    // later groups do not affect this candidate's current admissibility.
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .any(|signature| signature.public_key == *fork_key)
}

pub(super) fn entry_waits_on_pending_parent_outside_group(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    group: &BTreeSet<AuthorityEntryHash>,
) -> bool {
    entry.parent_hashes.iter().any(|parent| {
        !states.contains_key(parent) && pending.contains(parent) && !group.contains(parent)
    })
}

/// Substitute parent states that let a stalled `RevokeActor` fold against its
/// nearest READY ancestry, or `None` when the bypass does not apply.
///
/// THE HOLE THIS CLOSES. `op_applies_despite_pending_widen` exempts a
/// revocation from the pending-widen freeze, but that exemption is tested
/// AFTER `fold_entry_state` has resolved parents, and an unresolved parent
/// returns `Waiting` first. So a compromised key stalls its own revocation by
/// parenting it on a grant the key itself filed under an unrelated pending
/// widen: the grant defers (correctly — grants must freeze), and the child
/// revocation inherits the wait for the whole veto window. The withdrawal of
/// consent is exactly the operation that must not be delayable by its target.
///
/// WHY IT IS SAFE. Substituting an ancestry state that predates the frozen
/// parent cannot manufacture authority for the revocation:
///
/// * `RevokeActor` is authority-REMOVING only. Applying it raises
///   `actor_binding_revocations[key]` to at least `epoch` and touches nothing
///   else, so the worst a stale base state can do is withhold the revocation's
///   effect — the pre-fix behavior — never widen anything.
/// * The watermark merges by MAX, so once the frozen parent does fold the
///   revocation stays in force: no ordering can lower a raised watermark.
/// * The substituted states are real folded states of real ancestors, so every
///   other gate the entry passes through (signature, vault, roster, consent,
///   quorum, seq) still runs against genuinely folded authority.
///
/// WHY IT STAYS ONE OP WIDE, AND ONE CAUSE DEEP. Two independent narrowings,
/// because the bypass is the only place a fold walks past an unfolded entry:
///
/// * Only `RevokeActor` may USE it. A grant folded against a pre-widen roster
///   is precisely what the freeze exists to prevent, so `BindActor` and
///   `RebindActor` keep waiting.
/// * Only a parent FROZEN BY THE WIDEN may be stepped over — see
///   [`entry_is_frozen_by_pending_widen`]. A parent that is waiting for any
///   other reason, was ruled `Invalid`, or is simply absent from the log
///   refuses the whole bypass, so a revocation can never be folded over
///   ancestry this vault has not validated. The skipped parent is stepped over,
///   never applied.
///
/// The walk is bounded by the ancestry it traverses and introduces no clock
/// dependency: a revocation is not time-based, and this decides nothing about
/// when any pending widen matures.
///
/// KNOWN DURABILITY RESIDUAL. A revocation rescued by this bypass survives the
/// widen merely maturing
/// (`revocation_folded_past_a_freeze_survives_the_widen_maturing`), but NOT the
/// skipped grant later becoming retroactively invalid through the matured
/// state — that durability is a GATE-2 packet item, not an in-lane fix. Closing
/// it needs a representation in which an accepted revocation's effect outlives
/// ancestry invalidation of the entries above it (a journal, or per-hash bypass
/// state), which is a design surface rather than a change to this function.
pub(in crate::authority) fn revocation_bypass_states(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, FoldState>> {
    if !matches!(entry.op, AuthorityOp::RevokeActor { .. }) {
        return None;
    }
    let mut substitutes = BTreeMap::new();
    for parent in &entry.parent_hashes {
        if states.contains_key(parent) {
            continue;
        }
        let nearest = nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)?;
        substitutes.insert(*parent, nearest);
    }
    // No unresolved parent means the entry stalled on something else entirely
    // (equivocation, seq, consent); leave every other path exactly as it was.
    if substitutes.is_empty() {
        return None;
    }
    let mut merged = states.clone();
    merged.extend(substitutes);
    Some(merged)
}

/// Walks up from a frozen entry to the merge of the nearest folded states.
///
/// Every branch must terminate in a READY ancestor, crossing only entries the
/// pending-widen freeze is holding. Anything else — an invalid ancestor, a
/// missing one, a root that never folded, a parent waiting for some other
/// reason — refuses the bypass outright.
fn nearest_unfrozen_ancestor_state(
    start: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut resolved: Option<FoldState> = None;
    let mut visited = BTreeSet::new();
    let mut frontier = vec![start];
    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(state) = states.get(&hash) {
            resolved = Some(match resolved {
                Some(current) if current.vault_id != state.vault_id => return None,
                Some(current) => merge_states(&current, state),
                None => state.clone(),
            });
            continue;
        }
        let entry = by_hash.get(&hash)?;
        if !pending.contains(&hash)
            || entry.parent_hashes.is_empty()
            || !entry_is_frozen_by_pending_widen(entry, by_hash, states, pending, context)
        {
            return None;
        }
        frontier.extend(entry.parent_hashes.iter().copied());
    }
    resolved
}

/// Whether `entry` is stalled by the pending-widen freeze specifically.
///
/// This is the bypass's load-bearing narrowing, so it is decided POSITIVELY
/// rather than by elimination: the entry's own ancestry must resolve, that
/// ancestry must actually carry a pending widen, and the entry's op must be one
/// the freeze defers. An entry that is waiting for any other reason fails this
/// and stops the walk.
///
/// The classification is read off the MERGED ancestry, because that is the only
/// picture the freeze itself ever sees. `fold_entry_state` merges every parent
/// state before testing `!state.pending_widens.is_empty()`, so a single
/// widen-bearing branch parks the entry no matter how many clean siblings it
/// has. Asking instead whether EVERY branch carries a widen would answer a
/// question the fold never poses, and the disagreement is attacker-selectable:
/// hanging one ordinary already-folded parent off a stall grant would make the
/// classifier call a frozen entry unfrozen and collapse the bypass
/// (`revoke_actor_folds_past_a_grant_frozen_through_only_one_of_its_parents`).
///
/// Every parent must still RESOLVE. That is the narrowing this shares with
/// [`nearest_unfrozen_ancestor_state`]: a branch that dead-ends in an invalid,
/// missing, or otherwise-waiting ancestor refuses the classification outright,
/// so "frozen" never widens to mean "stuck for some reason we did not identify."
fn entry_is_frozen_by_pending_widen(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> bool {
    if !context.enforce_seen_time_delay || op_applies_despite_pending_widen(&entry.op) {
        return false;
    }
    let mut merged: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) =
            nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)
        else {
            return false;
        };
        merged = Some(match merged {
            Some(current) if current.vault_id != state.vault_id => return false,
            Some(current) => merge_states(&current, &state),
            None => state,
        });
    }
    merged.is_some_and(|state| !state.pending_widens.is_empty())
}

pub(super) fn entry_is_validated_prefork_ancestor(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(chain_validated_candidates) = context.chain_validated_fork_candidates else {
        return false;
    };
    group.iter().any(|fork_hash| {
        chain_validated_candidates.contains(fork_hash)
            && ancestors
                .get(fork_hash)
                .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

fn entry_is_claimed_prefork_or_fork_candidate(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    if group.contains(&entry_hash) {
        return true;
    }
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    group.iter().any(|fork_hash| {
        ancestors
            .get(fork_hash)
            .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

/// Chain-validation probe: re-folds `target_hash` over its own complete
/// ancestry with fork state deliberately cleared.
///
/// It inherits exactly TWO things from the enclosing fold — the consent arm and
/// the admitted peer consent roots — because those define what "folds" MEANS.
/// A probe answering under different consent semantics than the fold it serves
/// would quietly disagree with it about which fork candidates are chain-valid.
pub(in crate::authority) fn entry_folds_on_available_ancestry(
    target_hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    let Some(target_ancestors) = ancestors.get(&target_hash) else {
        return false;
    };
    if target_ancestors
        .iter()
        .any(|ancestor| !by_hash.contains_key(ancestor))
    {
        return false;
    }
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let authority_fork_vault_ids = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending = target_ancestors.clone();
    pending.insert(target_hash);

    for _ in 0..=pending.len() {
        if states.contains_key(&target_hash) {
            return true;
        }
        let hashes: Vec<_> = pending.iter().copied().collect();
        let mut progressed = false;
        for hash in hashes {
            let Some(entry) = by_hash.get(&hash) else {
                return false;
            };
            match fold_entry_state(
                entry,
                hash,
                &states,
                FoldContext {
                    first_seen_at_secs: &first_seen_at_secs,
                    now_secs: None,
                    enforce_seen_time_delay: false,
                    vetoed_widens: &vetoed_widens,
                    authority_forks: &authority_forks,
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(ancestors),
                    chain_validated_fork_candidates: None,
                    ..context
                },
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
                EntryFold::Invalid(_) => return false,
            }
        }
        if !progressed {
            return false;
        }
    }
    false
}
