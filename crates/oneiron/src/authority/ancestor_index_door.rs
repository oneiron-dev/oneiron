//! The ancestor index equivalence door (row [ROSTER-KEY-LOG-FLOOD], PR 1;
//! Engine RULING 16 Nov 13:44 = A: each PR of the stack exact by
//! construction, with an old-against-new equivalence test). One synthetic
//! log, each row's hash with its claimed parents, built two ways: by the
//! fold's [`AncestorIndex`] (sorted id runs) and by the per-row set index it
//! replaced, kept here alone as the reference. Each way reports every
//! answer a fold reader takes from the index, so a test compares them
//! field for field. Compiled only under `--cfg oneiron_test_support`; never
//! API.

use std::collections::{BTreeMap, BTreeSet};

use super::AuthorityEntryHash;
use super::ancestor_index::AncestorIndex;

/// Every answer a fold reader takes from one ancestor index of a log.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexedAncestry {
    /// The hashes the index holds an ancestry for, among every row, every
    /// claimed parent and every probe hash, in hash order.
    pub indexed: Vec<AuthorityEntryHash>,
    /// Each row's ancestors, as a set (hash order).
    pub members: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    /// Each row's ancestors as the index walks them, then sorted: equal to
    /// `members` only when the walk yields each ancestor once.
    pub walked: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    /// Each row's ancestors found by a membership test of every row, every
    /// claimed parent and every probe hash.
    pub contained: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    /// Each row's ancestor count.
    pub lens: BTreeMap<AuthorityEntryHash, usize>,
    /// Whether each row has an ancestor among the probe hashes.
    pub meets_probe: BTreeMap<AuthorityEntryHash, bool>,
    /// The sum of every row's ancestor count.
    pub pairs: u64,
    /// The pairs whose descendant and ancestor are both counted.
    pub counted_pairs: u64,
}

/// `rows` indexed by the fold's run index: None once the pairs pass
/// `pair_limit`, as the fold's memory floor refuses a log.
pub fn by_runs(
    rows: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    uncounted: &BTreeSet<AuthorityEntryHash>,
    pair_limit: u64,
    probe: &BTreeSet<AuthorityEntryHash>,
) -> Option<IndexedAncestry> {
    let listed: Vec<_> = rows
        .iter()
        .map(|(hash, parents)| (*hash, parents.as_slice()))
        .collect();
    let (index, counted_pairs) =
        AncestorIndex::build(&listed, uncounted, |pairs| pairs > pair_limit)?;
    let candidates = candidates(rows, probe);
    let mut ancestry = IndexedAncestry {
        indexed: candidates
            .iter()
            .filter(|hash| index.get(hash).is_some())
            .copied()
            .collect(),
        members: BTreeMap::new(),
        walked: BTreeMap::new(),
        contained: BTreeMap::new(),
        lens: BTreeMap::new(),
        meets_probe: BTreeMap::new(),
        pairs: index.pairs(),
        counted_pairs,
    };
    for hash in rows.keys() {
        let past = index.get(hash).expect("the index holds every row");
        ancestry
            .members
            .insert(*hash, past.to_set().into_iter().collect());
        let mut walked: Vec<_> = past.iter_unordered().copied().collect();
        walked.sort_unstable();
        ancestry.walked.insert(*hash, walked);
        ancestry.contained.insert(
            *hash,
            candidates
                .iter()
                .filter(|candidate| past.contains(candidate))
                .copied()
                .collect(),
        );
        ancestry.lens.insert(*hash, past.len());
        ancestry.meets_probe.insert(*hash, past.intersects(probe));
    }
    Some(ancestry)
}

/// `rows` indexed by the per-row set index the fold used before PR 1 (a walk
/// of each row's claims into its own set, the limit checked at each pair):
/// the reference [`by_runs`] must equal.
pub fn by_sets(
    rows: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    uncounted: &BTreeSet<AuthorityEntryHash>,
    pair_limit: u64,
    probe: &BTreeSet<AuthorityEntryHash>,
) -> Option<IndexedAncestry> {
    let mut index = BTreeMap::new();
    let (mut pairs, mut counted_pairs) = (0_u64, 0_u64);
    for (hash, parents) in rows {
        let counted = !uncounted.contains(hash);
        let mut ancestors = BTreeSet::new();
        let mut stack = parents.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            pairs += 1;
            if pairs > pair_limit {
                return None;
            }
            counted_pairs += u64::from(counted && !uncounted.contains(&parent));
            if let Some(grandparents) = rows.get(&parent) {
                stack.extend(grandparents.iter().copied());
            }
        }
        index.insert(*hash, ancestors);
    }
    let candidates = candidates(rows, probe);
    let mut ancestry = IndexedAncestry {
        indexed: candidates
            .iter()
            .filter(|hash| index.contains_key(*hash))
            .copied()
            .collect(),
        members: BTreeMap::new(),
        walked: BTreeMap::new(),
        contained: BTreeMap::new(),
        lens: BTreeMap::new(),
        meets_probe: BTreeMap::new(),
        pairs: index.values().map(|past| past.len() as u64).sum(),
        counted_pairs,
    };
    for (hash, past) in &index {
        ancestry
            .members
            .insert(*hash, past.iter().copied().collect());
        ancestry
            .walked
            .insert(*hash, past.iter().copied().collect());
        ancestry.contained.insert(
            *hash,
            candidates
                .iter()
                .filter(|candidate| past.contains(*candidate))
                .copied()
                .collect(),
        );
        ancestry.lens.insert(*hash, past.len());
        ancestry.meets_probe.insert(*hash, !past.is_disjoint(probe));
    }
    Some(ancestry)
}

/// Every row, every claimed parent and every probe hash.
fn candidates(
    rows: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    probe: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    rows.iter()
        .flat_map(|(hash, parents)| std::iter::once(hash).chain(parents))
        .chain(probe)
        .copied()
        .collect()
}
