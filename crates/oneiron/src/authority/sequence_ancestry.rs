//! A row past its floor still counts where a later row of its signer that
//! descends from it reached that floor (`rows_floor`).
use super::*;
use std::collections::BTreeMap;

/// `original`, the rows floors (`rows_floor::rows_sequence_floors`), less
/// every row a later row of its signer vouches for: one that has it among
/// its ancestors, sits at or above its floor, and folds on its own complete
/// ancestry (`entry_folds_on_available_ancestry`). The branch that reached
/// its signer's highest sequence so counts whole, on every install alike.
pub(super) fn causal_sequence_floors(
    by_hash: &JudgedRows,
    ancestors: &AncestorIndex,
    original: &BTreeMap<AuthorityEntryHash, u64>,
    context: FoldContext<'_>,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut floors = original.clone();
    loop {
        let before = floors.len();
        // Only a row of a signer with a row past its floor can vouch, and
        // only for those rows: each tip looks them up among its ancestors,
        // or its ancestors among them, whichever are fewer (Astra round 1 E2
        // of [SEQUENCE-FLOOR-DELIVERY-ORDER]). A signer with one row past
        // its floor so costs each of its rows one lookup, however long its
        // chains in other scopes.
        let mut floored_rows = BTreeMap::<_, Vec<AuthorityEntryHash>>::new();
        for hash in floors.keys() {
            if let Some(entry) = by_hash.get(hash) {
                floored_rows
                    .entry(entry.signer_key())
                    .or_default()
                    .push(*hash);
            }
        }
        for (tip_hash, tip) in by_hash.iter() {
            let Some(signer_floored) = floored_rows.get(tip.signer_key()) else {
                continue;
            };
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
            let tip_ancestors = ancestors.get(tip_hash).expect("the index holds every row");
            let vouched = |hash: &&AuthorityEntryHash| {
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
            };
            // `covered` is only taken out of `trial`, so its order is free.
            let covered: Vec<_> = if signer_floored.len() <= tip_ancestors.len() {
                signer_floored
                    .iter()
                    .filter(|hash| tip_ancestors.contains(*hash))
                    .filter(vouched)
                    .copied()
                    .collect()
            } else {
                tip_ancestors
                    .iter_unordered()
                    .filter(vouched)
                    .copied()
                    .collect()
            };
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
///
/// It folds each row once, ancestors first (the index's id order), and
/// reads each row's signature verdict from the fold that judged it
/// (`fold_judged_entry_state`): one transition a row, where rounds in hash
/// order took one a row a round (row [ROSTER-KEY-LOG-FLOOD], PR 3). The
/// answer is the rounds' (`fold_readers_door` keeps them): a transition
/// reads only its row, the context and its parents' states, and a genesis
/// claims no parent, so the target folds exactly when every row of its
/// ancestry folds, in any order. A row whose parent has not folded in id
/// order waits on a parent in its own cycle of claims, which never folds.
pub(super) fn entry_folds_on_available_ancestry(
    target_hash: AuthorityEntryHash,
    by_hash: &JudgedRows,
    ancestors: &AncestorIndex,
    context: FoldContext<'_>,
) -> bool {
    let Some(target_ancestors) = ancestors.get(&target_hash) else {
        return false;
    };
    if target_ancestors
        .iter_unordered()
        .any(|ancestor| !by_hash.contains_key(ancestor))
    {
        return false;
    }
    let context = FoldContext {
        entry_ancestors: Some(ancestors),
        ..context
    };
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let rows = target_ancestors
        .iter_unordered()
        .copied()
        .chain(std::iter::once(target_hash));
    for hash in rows {
        match fold_judged_entry_state(by_hash, hash, &states, context) {
            Some(EntryFold::Ready(state)) => {
                states.insert(hash, state);
            }
            Some(EntryFold::Waiting | EntryFold::Invalid(_)) | None => return false,
        }
    }
    true
}
