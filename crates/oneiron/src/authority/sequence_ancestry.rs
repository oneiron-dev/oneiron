//! Causally vouched history may arrive after its already-observed descendant.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn causal_sequence_floors(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, u64>> {
    let original = context.sequence_floors?;
    let mut floors = original.clone();
    loop {
        let before = floors.len();
        for (tip_hash, tip) in by_hash {
            let tip_floor = original.get(tip_hash).copied();
            if tip_floor.is_some_and(|floor| tip.seq < floor) {
                continue;
            }
            let covered: Vec<_> = ancestors[tip_hash]
                .iter()
                .filter(|hash| {
                    by_hash.get(*hash).is_some_and(|entry| {
                        entry.signer_key() == tip.signer_key()
                            && entry.seq < tip.seq
                            && tip_floor.is_none_or(|floor| entry.seq > floor)
                            && floors.get(*hash).is_some_and(|floor| entry.seq < *floor)
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
            // other signer's floor. A newly received rollback tip cannot vouch.
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
            return Some(floors);
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
fn entry_folds_on_available_ancestry(
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
