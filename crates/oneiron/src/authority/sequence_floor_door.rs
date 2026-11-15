//! The sequence floor equivalence door (Engine RULING SEQ-FLOOR-SHAPE = A,
//! 15 Nov 16:37; FIX [SEQUENCE-FLOOR-DELIVERY-ORDER]): one log folded both
//! ways, by the rows' own floors (`rows_floor`, every fold since the ruling)
//! and by one install's arrival order as before it: each row floored at the
//! highest sequence of its signer's same-scope rows that install had seen
//! before it (the receipts `sequence_observation` keeps), less what the old
//! arrival-order lift vouched for. A test shows the two agree on every row
//! of a log whose signers each sign one chain. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::{FoldContext, OnceFloors};
use super::{AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityVaultId};

static NO_PEERS: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>> = BTreeMap::new();
static NO_HANDOFFS: BTreeSet<AuthorityEntryHash> = BTreeSet::new();

/// One log folded both ways.
#[derive(Debug)]
pub struct FloorEquivalence {
    /// The fold by the rows' own floors.
    pub by_rows: AuthorityFold,
    /// The fold by the arrival order's floors and the old lift.
    pub by_arrival: AuthorityFold,
    /// Rows the rows' own floors put past a floor.
    pub rows_floored: usize,
    /// Rows the arrival order put past a floor, before any lift.
    pub arrival_floored: usize,
    /// Rows still past their arrival floor after the old lift.
    pub arrival_floored_after_lift: usize,
    /// Whether each signer's rows in each scope form one chain: sequences
    /// strictly rise, and each row has the one below it among its ancestors.
    pub single_chain: bool,
    /// Whether the arrival order delivers every row after its parents.
    pub topological: bool,
}

/// `entries` folded by their own floors and by an install that observed
/// them in the order `arrival` gives (indices into `entries`, each once).
/// Both folds run the vault fold's once pass (`fold_authority_log_once_with`)
/// under one context: no handoff, no peer, every machine chain counted, no
/// memory floor.
///
/// # Panics
/// When `arrival` is not a permutation of `entries`' indices, or a row's hash
/// does not compute.
pub fn fold_both_ways(entries: &[AuthorityLogEntry], arrival: &[usize]) -> FloorEquivalence {
    let mut seen = vec![false; entries.len()];
    for &index in arrival {
        assert!(
            !std::mem::replace(&mut seen[index], true),
            "row {index} arrives twice"
        );
    }
    assert!(seen.iter().all(|seen| *seen), "every row arrives");
    let hashes: Vec<AuthorityEntryHash> = entries
        .iter()
        .map(|entry| super::authority_entry_hash(entry).expect("row hash"))
        .collect();
    let floors = arrival_floors(entries, &hashes, arrival);
    let by_hash: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = hashes
        .iter()
        .copied()
        .zip(entries.iter().cloned())
        .collect();
    let (ancestors, _) = super::ancestor_index::entry_ancestor_index(&by_hash, u64::MAX)
        .expect("no memory floor refuses");
    let rows_floored = effective(
        &by_hash,
        &super::rows_floor::rows_sequence_floors(&by_hash, &ancestors),
    );
    let arrival_floored = effective(&by_hash, &floors);
    let lifted = arrival_lifted_floors(&by_hash, &ancestors, context(Some(&floors)));
    let arrival_floored_after_lift = effective(&by_hash, &lifted.applied);
    let by_rows = super::fold_engine::fold_authority_log_once(
        entries,
        context(Some(&super::fold_engine::SEQUENCE_FLOORS_FROM_ROWS)),
        None,
        None,
    );
    let by_arrival = super::fold_engine::fold_authority_log_once_with(
        entries,
        context(Some(&floors)),
        None,
        None,
        arrival_lifted_floors,
    );
    let mut delivered = BTreeSet::new();
    let mut topological = true;
    for &index in arrival {
        topological &= entries[index]
            .parent_hashes
            .iter()
            .all(|parent| delivered.contains(parent) || !by_hash.contains_key(parent));
        delivered.insert(hashes[index]);
    }
    FloorEquivalence {
        by_rows,
        by_arrival,
        rows_floored,
        arrival_floored,
        arrival_floored_after_lift,
        single_chain: single_chain(&by_hash, &ancestors),
        topological,
    }
}

fn context(floors: Option<&BTreeMap<AuthorityEntryHash, u64>>) -> FoldContext<'_> {
    FoldContext {
        sequence_floors: floors,
        floor_vouched: None,
        install_held: None,
        entry_ancestors: None,
        causal_past: None,
        peer_consent_roots: &NO_PEERS,
        consent_arm: super::folded_device_can_authority_consent,
        hosted: false,
        machine_standing: &super::machine_standing::every_chain,
        pre_handoff_entries: Some(&NO_HANDOFFS),
        memory_floor_bytes: u64::MAX,
        pin: None,
    }
}

/// Each row's floor on an install that observed `entries` in `arrival`
/// order: the highest sequence of its signer's rows in its scope observed
/// before it, as its receipt keeps it (`sequence_observation`), whether or
/// not that sequence is above its own.
fn arrival_floors(
    entries: &[AuthorityLogEntry],
    hashes: &[AuthorityEntryHash],
    arrival: &[usize],
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut marks: BTreeMap<(AuthorityKey, Option<crate::EntityId>), u64> = BTreeMap::new();
    let mut floors = BTreeMap::new();
    for &index in arrival {
        let entry = &entries[index];
        let scope = (
            entry.signer_key().clone(),
            super::world_privacy::side_world(&entry.op),
        );
        if let Some(mark) = marks.get(&scope) {
            floors.insert(hashes[index], *mark);
        }
        let mark = marks.entry(scope).or_insert(entry.seq);
        *mark = (*mark).max(entry.seq);
    }
    floors
}

/// The rows of `floors` whose own sequence is below their floor.
fn effective(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    floors: &BTreeMap<AuthorityEntryHash, u64>,
) -> usize {
    floors
        .iter()
        .filter(|(hash, floor)| by_hash.get(*hash).is_some_and(|entry| entry.seq < **floor))
        .count()
}

fn single_chain(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> bool {
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, entry) in by_hash {
        scopes
            .entry((
                entry.signer_key(),
                super::world_privacy::side_world(&entry.op),
            ))
            .or_default()
            .push((entry.seq, *hash));
    }
    scopes.values_mut().all(|rows| {
        rows.sort_unstable();
        rows.windows(2).all(|pair| {
            pair[0].0 < pair[1].0
                && ancestors
                    .get(&pair[1].1)
                    .is_some_and(|above| above.contains(&pair[0].1))
        })
    })
}

/// The floors before RULING SEQ-FLOOR-SHAPE: `context`'s floors are the
/// arrival order's, and a later row of the signer vouches for a row below
/// it in its ancestry that arrived after it was observed (in flight), or a
/// roster row vouches for a refused row of its signer below it, when the
/// voucher folds on its own complete ancestry. This is the lift
/// `sequence_ancestry` ran on arrival floors, kept here alone.
fn arrival_lifted_floors(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> OnceFloors {
    let original = context.sequence_floors.cloned().unwrap_or_default();
    let mut floors = original.clone();
    loop {
        let before = floors.len();
        for (tip_hash, tip) in by_hash {
            let tip_floor = original.get(tip_hash).copied();
            let rollback_tip = tip_floor.is_some_and(|floor| tip.seq < floor);
            let roster_tip = super::entry_transition::changes_roster(&tip.op);
            if rollback_tip && !roster_tip {
                continue;
            }
            let covered: Vec<_> = ancestors[tip_hash]
                .iter()
                .filter(|hash| {
                    by_hash.get(*hash).is_some_and(|entry| {
                        let in_flight =
                            !rollback_tip && tip_floor.is_none_or(|floor| entry.seq > floor);
                        let refused_below_roster_row =
                            roster_tip && super::entry_transition::floor_refuses(&entry.op);
                        entry.signer_key() == tip.signer_key()
                            && entry.seq < tip.seq
                            && (in_flight || refused_below_roster_row)
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
            if super::sequence_ancestry::entry_folds_on_available_ancestry(
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
            return OnceFloors {
                original,
                applied: floors,
            };
        }
    }
}
