//! The floor probe equivalence door (row [ROSTER-KEY-LOG-FLOOD], PR 3;
//! Engine RULING 16 Nov 13:44 = A: each PR of the stack exact by
//! construction, with an old-against-new equivalence test). The probe a
//! floored row's voucher folds on
//! (`sequence_ancestry::entry_folds_on_available_ancestry`) folds the
//! voucher's ancestry once, in the index's id order, and reads each row's
//! signature verdict from the fold that judged it. The probe before PR 3,
//! kept here alone as the reference, folded the same rows in rounds in hash
//! order and verified every row's signatures at each transition. A test
//! asks both of every row of a log, under several floor maps, and compares
//! the answers. Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeMap;

use super::ancestor_index::AncestorIndex;
use super::entry_transition::{EntryFold, fold_entry_state};
use super::fold_engine::{FoldContext, JudgedRows};
use super::fold_state::FoldState;
use super::{AuthorityEntryHash, AuthorityLogEntry};

/// The probe asked both ways of every row of one log under each floor map.
#[derive(Debug)]
pub struct ProbeEquivalence {
    /// The probes asked, each of one row under one floor map.
    pub asked: usize,
    /// The probes both ways answer true.
    pub folded: usize,
    /// The floor maps asked under: no floors, the rows' own floors, the
    /// floors the fold applies, and the rows' own floors less each floored
    /// row in turn (the lift of one row).
    pub floor_maps: usize,
    /// Each probe the two ways answer differently: the row, the floor map's
    /// name, and the answer by rounds.
    pub disagreements: Vec<(AuthorityEntryHash, String, bool)>,
}

/// Every row of `entries` the fold judges, asked of both probes under each
/// floor map, in one context: no handoff, no peer, every machine chain
/// counted, no memory floor (`sequence_floor_door::context`).
///
/// # Panics
/// When a row's hash does not compute.
pub fn probe_both_ways(entries: &[AuthorityLogEntry]) -> ProbeEquivalence {
    let (by_hash, _) = super::fold_engine::judged_entries(entries);
    let (ancestors, _) = super::ancestor_index::entry_ancestor_index(&by_hash, u64::MAX)
        .expect("no memory floor refuses");
    let original = super::rows_floor::rows_sequence_floors(&by_hash, &ancestors);
    let applied = super::sequence_ancestry::causal_sequence_floors(
        &by_hash,
        &ancestors,
        &original,
        super::sequence_floor_door::context(Some(&original)),
    );
    let mut floor_maps: Vec<(String, Option<BTreeMap<AuthorityEntryHash, u64>>)> = vec![
        ("no floors".to_owned(), None),
        ("the rows' own floors".to_owned(), Some(original.clone())),
        ("the applied floors".to_owned(), Some(applied)),
    ];
    for lifted in original.keys() {
        let mut trial = original.clone();
        trial.remove(lifted);
        floor_maps.push((
            format!("the rows' own floors less {}", hex(lifted)),
            Some(trial),
        ));
    }
    let mut equivalence = ProbeEquivalence {
        asked: 0,
        folded: 0,
        floor_maps: floor_maps.len(),
        disagreements: Vec::new(),
    };
    for (name, floors) in &floor_maps {
        let context = super::sequence_floor_door::context(floors.as_ref());
        for hash in by_hash.keys() {
            let once = super::sequence_ancestry::entry_folds_on_available_ancestry(
                *hash, &by_hash, &ancestors, context,
            );
            let rounds = folds_in_rounds(*hash, &by_hash, &ancestors, context);
            equivalence.asked += 1;
            equivalence.folded += usize::from(once && rounds);
            if once != rounds {
                equivalence
                    .disagreements
                    .push((*hash, name.clone(), rounds));
            }
        }
    }
    equivalence
}

/// The probe before PR 3, line for line: `target_hash` re-folded over its
/// own complete ancestry in rounds, each round a pass over the rows left in
/// hash order, every transition verifying its row's signatures.
fn folds_in_rounds(
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
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending = target_ancestors.to_set();
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

fn hex(hash: &AuthorityEntryHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
