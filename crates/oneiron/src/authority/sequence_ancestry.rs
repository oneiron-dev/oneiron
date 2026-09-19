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
            if tip_floor.is_some_and(|floor| tip.seq <= floor) {
                continue;
            }
            let covered: Vec<_> = ancestors[tip_hash]
                .iter()
                .filter(|hash| {
                    by_hash.get(*hash).is_some_and(|entry| {
                        entry.signer_key() == tip.signer_key()
                            && entry.seq < tip.seq
                            && tip_floor.is_none_or(|floor| entry.seq > floor)
                            && floors.get(*hash).is_some_and(|floor| entry.seq <= *floor)
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
