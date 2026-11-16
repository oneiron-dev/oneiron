//! The authority-internal half of the fold memory measurement door
//! ([ROSTER-KEY-LOG-FLOOD] PLAN v2, step one; root FIX-LIST 25305): the
//! fold's phases one at a time, so an integration test under a counting
//! allocator can weigh what each phase holds. Re-run for PR 4 (the floor,
//! from a re-measurement) at PR 3's head: the door also reports the index
//! ids and runs, the merge gain, and the entries of the run's own family.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use super::ancestor_index::AncestorIndex;
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
    ancestors: AncestorIndex,
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
    let pairs = ancestors.pairs();
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

    /// Every id of the index: each row and each claimed parent the log
    /// lacks.
    pub fn ids(&self) -> u64 {
        self.ancestors.node_count() as u64
    }

    /// The runs of every node's ancestry summed.
    pub fn runs(&self) -> u64 {
        self.ancestors.run_count()
    }
}

/// The merge gain of `rows` under `index`: over every row with 2 or more
/// parent claims, its ancestor count less 1 and less its first parent's
/// ancestor count (the entries `merge_states` adds to its clone of the
/// first parent's state).
pub fn merge_gain(rows: &Rows, index: &Index) -> u64 {
    rows.0
        .iter()
        .map(|(hash, entry)| {
            if entry.parent_hashes.len() < 2 {
                return 0;
            }
            let len = |hash: &AuthorityEntryHash| {
                index
                    .ancestors
                    .get(hash)
                    .map_or(0, |past| past.len() as u64)
            };
            len(hash).saturating_sub(1 + len(&entry.parent_hashes[0]))
        })
        .sum()
}

/// The fold's context on a log with no handoff, no sequence floor and no
/// memory floor.
fn context(ancestors: &AncestorIndex) -> FoldContext<'_> {
    FoldContext {
        sequence_floors: None,
        floor_vouched: None,
        install_held: None,
        entry_ancestors: Some(ancestors),
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
        context(&index.ancestors),
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

    /// The `family` entries ([`family_entries`]) of every row's state,
    /// summed.
    pub fn family_entries(&self, family: &str) -> usize {
        self.0
            .values()
            .map(|state| family_entries_inner(state, family))
            .sum()
    }

    /// A copy of the state of the row with the most ancestors (the first by
    /// hash among equals).
    pub fn deepest(&self, index: &Index) -> State {
        let mut deepest: Option<(usize, &AuthorityEntryHash)> = None;
        for hash in self.0.keys() {
            let depth = index
                .ancestors
                .get(hash)
                .map_or(0, |ancestors| ancestors.len());
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

/// The entries `state` holds in the field(s) that `family`'s rows grow:
/// the one field below for the five first families (as [`grown_entries`]),
/// the family's own for the rest.
pub fn family_entries(state: &State, family: &str) -> usize {
    family_entries_inner(&state.0, family)
}

fn family_entries_inner(state: &FoldState, family: &str) -> usize {
    match family {
        "confirm" => state.federation_confirms.len(),
        "critical" => state.critical_write_confirms.len(),
        "enroll" | "enroll-p256" | "enroll-p256-owner" => state.roster.len(),
        "residence" => state.residence_directives.len(),
        "agents" => state.actor_bindings.len(),
        "slip-mint" => state.slips.mints.len(),
        "slip-revoke" => state.slips.revoked.len() + state.slips.explicit_revoked.len(),
        "world-edit" => state
            .worlds
            .iter()
            .map(|(_, frontier)| frontier.live.len() + frontier.superseded.len())
            .sum(),
        "machine-revision" => state
            .machines
            .iter()
            .map(|(_, chains)| {
                chains
                    .values()
                    .map(|chain| chain.revisions.len())
                    .sum::<usize>()
            })
            .sum(),
        "owner-work" => state.owner_work.request_count() + state.owner_work.result_count(),
        "rescope" => state
            .federation_pacts
            .iter()
            .map(|(_, pact)| pact.narrowings.len() + pact.superseded_narrowings.len())
            .sum(),
        "refused-world-edit" => state.refused_world_edits.len(),
        "refused-grant-travel" => state.refused_grant_travel.len(),
        "refused-export" => state.refused_export_acts.len(),
        "actor-revoke" => {
            state.actor_binding_revocations.len()
                + state
                    .actor_revocation_hashes
                    .iter()
                    .map(|(_, hashes)| hashes.len())
                    .sum::<usize>()
        }
        other => panic!("unknown family {other}"),
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

/// The whole vault fold of `entries` (the posture-aware vault door, handoff
/// probes and install view included), every row first seen at second 1,
/// under no sequence floor and no memory floor.
pub fn fold(entries: &[AuthorityLogEntry]) -> Folded {
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (super::authority_entry_hash(entry).expect("row hash"), 1))
        .collect();
    let observations = super::sequence_observation::AuthorityLocalObservations {
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
