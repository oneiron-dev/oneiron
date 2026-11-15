//! The authority-internal half of the fold memory measurement door
//! ([ROSTER-KEY-LOG-FLOOD] PLAN v2, step one; root FIX-LIST 25305): the
//! fold's phases one at a time, so an integration test under a counting
//! allocator can weigh what each phase holds. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::{FoldContext, FoldLocalInputs};
use super::fold_state::FoldState;
use super::{AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityVaultId};

static NO_PEERS: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>> = BTreeMap::new();
static NO_HANDOFFS: BTreeSet<AuthorityEntryHash> = BTreeSet::new();

/// A log's rows by hash, as the fold holds a log whose rows are all well
/// signed and none of which hangs off a side branch (`judged_entries`).
pub struct Rows(BTreeMap<AuthorityEntryHash, AuthorityLogEntry>);

/// The fold's ancestor index of [`Rows`] (`entry_ancestor_index`), with its
/// pair counts.
pub struct Index {
    ancestors: BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    pairs: u64,
    counted_pairs: u64,
}

/// Every row's folded state (`fold_schedule::fold_entry_states`).
pub struct States(BTreeMap<AuthorityEntryHash, FoldState>);

/// One folded state.
pub struct State(FoldState);

/// What the whole vault fold of a log keeps: its valid rows and its counted
/// ancestor pairs.
pub struct Folded {
    pub valid: usize,
    pub counted_pairs: u64,
}

/// The rows of `entries`, by hash.
pub fn rows(entries: &[AuthorityLogEntry]) -> Rows {
    Rows(
        entries
            .iter()
            .map(|entry| {
                (
                    super::authority_entry_hash(entry).expect("row hash"),
                    entry.clone(),
                )
            })
            .collect(),
    )
}

/// The ancestor index of `rows` under no memory floor.
pub fn index(rows: &Rows) -> Index {
    let (ancestors, counted_pairs) =
        super::ancestor_index::entry_ancestor_index(&rows.0, u64::MAX).expect("no floor refuses");
    let pairs = ancestors.values().map(|set| set.len() as u64).sum();
    Index {
        ancestors,
        pairs,
        counted_pairs,
    }
}

impl Index {
    /// Every ancestor pair the index holds.
    pub fn pairs(&self) -> u64 {
        self.pairs
    }

    /// The pairs the headroom check counts.
    pub fn counted_pairs(&self) -> u64 {
        self.counted_pairs
    }
}

/// The fold's context on a log with no handoff, under no memory floor:
/// `floors`, when given, are this install's sequence floors.
fn context<'a>(
    ancestors: Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
    floors: Option<&'a BTreeMap<AuthorityEntryHash, u64>>,
) -> FoldContext<'a> {
    FoldContext {
        sequence_floors: floors,
        floor_vouched: None,
        install_held: None,
        entry_ancestors: ancestors,
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

/// Every row's state, as the fold's per-row pass folds them.
pub fn states(rows: &Rows, index: &Index) -> States {
    let mut issues = Vec::new();
    States(super::fold_schedule::fold_entry_states(
        &rows.0,
        context(Some(&index.ancestors), None),
        &mut issues,
    ))
}

impl States {
    /// How many rows folded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no row folded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The grown entries ([`grown_entries`]) of every row's state, summed.
    pub fn grown_entries(&self) -> usize {
        self.0.values().map(grown_entries).sum()
    }

    /// A copy of the state of the row with the most ancestors (the first by
    /// hash among equals).
    pub fn deepest(&self, index: &Index) -> State {
        let mut deepest: Option<(usize, &AuthorityEntryHash)> = None;
        for hash in self.0.keys() {
            let depth = index.ancestors.get(hash).map_or(0, BTreeSet::len);
            if deepest.is_none_or(|(most, _)| depth > most) {
                deepest = Some((depth, hash));
            }
        }
        let (_, hash) = deepest.expect("a folded row");
        State(self.0[hash].clone())
    }

    /// The states merged in hash order, as the once-fold merges them.
    pub fn merged(&self) -> State {
        let mut merged: Option<FoldState> = None;
        for state in self.0.values() {
            merged = Some(match merged {
                Some(current) => super::fold_state::merge_states(&current, state),
                None => state.clone(),
            });
        }
        State(merged.expect("a folded row"))
    }
}

impl State {
    /// The entries this state holds in the maps that one roster key's rows
    /// grow by one a row ([`grown_entries`]).
    pub fn grown_entries(&self) -> usize {
        grown_entries(&self.0)
    }
}

/// The entries `state` holds in the maps that one roster key's rows grow by
/// one a row: roster, federation confirms, critical write confirms, actor
/// bindings and residence directives.
fn grown_entries(state: &FoldState) -> usize {
    state.roster.len()
        + state.federation_confirms.len()
        + state.critical_write_confirms.len()
        + state.actor_bindings.len()
        + state.residence_directives.len()
}

/// The causal floors pass (`sequence_ancestry::causal_sequence_floors`)
/// over this install's `floors`: how many rows it leaves below their floor.
pub fn causal_floors(
    rows: &Rows,
    index: &Index,
    floors: &BTreeMap<AuthorityEntryHash, u64>,
) -> usize {
    super::sequence_ancestry::causal_sequence_floors(
        &rows.0,
        &index.ancestors,
        context(None, Some(floors)),
    )
    .map_or(0, |left| {
        left.iter()
            .filter(|(hash, floor)| rows.0.get(*hash).is_some_and(|entry| entry.seq < **floor))
            .count()
    })
}

/// The whole vault fold of `entries` (the posture-aware vault door, handoff
/// probes and install view included), every row first seen at second 1,
/// under no sequence floor and no memory floor.
pub fn fold(entries: &[AuthorityLogEntry]) -> Folded {
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (super::authority_entry_hash(entry).expect("row hash"), 1))
        .collect();
    let observations = super::sequence_observation::AuthorityLocalObservations {
        sequence_floors: BTreeMap::new(),
        vouched: BTreeSet::new(),
        unvouched: false,
        policy: super::AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(u64::MAX),
            ..super::AuthorityObservationPolicy::default()
        },
    };
    let (consent, local) =
        super::fold_engine::own_log_inputs(crate::HostingPrivacyPosture::default(), None);
    let fold = super::fold_engine::fold_authority_log_inner(
        entries,
        &first_seen,
        Some(2),
        &NO_PEERS,
        consent,
        FoldLocalInputs {
            observations: Some(&observations),
            ..local
        },
    );
    Folded {
        valid: fold.valid_entries.len(),
        counted_pairs: fold.counted_ancestor_pairs,
    }
}

/// The bytes the memory floor projects a fold of `rows` rows and `pairs`
/// ancestor pairs to hold (`log_budget::fold_projected_bytes`).
pub fn projected_bytes(rows: usize, pairs: u64) -> u64 {
    super::log_budget::fold_projected_bytes(rows, pairs)
}
