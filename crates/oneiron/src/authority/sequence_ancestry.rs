//! A row past its floor still counts where a later row of its signer that
//! descends from it reached that floor (`rows_floor`).
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// `original`, the rows floors (`rows_floor::rows_sequence_floors`), less
/// every row a later row of its signer vouches for: one that has it among
/// its ancestors, sits at or above its floor, and folds on its own complete
/// ancestry (`entry_folds_on_available_ancestry`). The branch that reached
/// its signer's highest sequence so counts whole, on every install alike.
pub(super) fn causal_sequence_floors(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    original: &BTreeMap<AuthorityEntryHash, u64>,
    context: FoldContext<'_>,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut floors = original.clone();
    loop {
        let before = floors.len();
        // Only a row of a signer with a row past its floor can vouch.
        let floored_signers: BTreeSet<_> = floors
            .keys()
            .filter_map(|hash| by_hash.get(hash))
            .map(AuthorityLogEntry::signer_key)
            .collect();
        for (tip_hash, tip) in by_hash {
            if !floored_signers.contains(tip.signer_key()) {
                continue;
            }
            let rollback_tip = original.get(tip_hash).is_some_and(|floor| tip.seq < *floor);
            // No floor refuses a roster row (`changes_roster`), so even below
            // its floor it vouches for every row of its signer below it in its
            // ancestry that a floor refuses (`floor_refuses`), whatever their
            // floors (Sol review F1, Astra round 2 F3 of
            // [ARRIVAL-FLOOR-SIBLING-DIVERGENCE]): an exempt roster row never
            // waits on a parent of its own signer that a floor refused. A
            // restriction keeps its floor and lands restriction only (Astra
            // F2).
            let roster_tip = super::entry_transition::changes_roster(&tip.op);
            if rollback_tip && !roster_tip {
                continue;
            }
            let covered: Vec<_> = ancestors[tip_hash]
                .iter()
                .filter(|hash| {
                    by_hash.get(*hash).is_some_and(|entry| {
                        let refused_below_roster_row =
                            roster_tip && super::entry_transition::floor_refuses(&entry.op);
                        entry.signer_key() == tip.signer_key()
                            && entry.seq < tip.seq
                            && floors.get(*hash).is_some_and(|floor| {
                                entry.seq < *floor
                                    && ((!rollback_tip && tip.seq >= *floor)
                                        || refused_below_roster_row)
                            })
                    })
                })
                .copied()
                .collect();
            if covered.is_empty() {
                continue;
            }
            let mut trial = floors.clone();
            for hash in &covered {
                trial.remove(hash);
            }
            // A raw parent claim or signature alone is not an authorization proof.
            // Require complete, independently valid ancestry, and preserve every
            // other signer's floor. A tip past its own floor vouches for
            // nothing unless it is a roster row; and a roster tip that does
            // not fold on its own ancestry vouches for nothing.
            if entry_folds_on_available_ancestry(
                *tip_hash,
                by_hash,
                ancestors,
                FoldContext {
                    sequence_floors: Some(&trial),
                    ..context
                },
            ) {
                floors = trial;
            }
        }
        if floors.len() == before {
            return floors;
        }
    }
}

/// Chain-validation probe: re-folds `target_hash` over its own complete
/// ancestry.
///
/// It inherits exactly TWO things from the enclosing fold — the consent arm and
/// the admitted peer consent roots — because those define what "folds" MEANS.
/// A probe answering under different consent semantics than the fold it serves
/// would quietly disagree with it about which history can vouch a sequence floor.
pub(super) fn entry_folds_on_available_ancestry(
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
                    entry_ancestors: Some(ancestors),
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
