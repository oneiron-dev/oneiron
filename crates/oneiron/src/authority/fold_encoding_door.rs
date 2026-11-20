//! The fold state encoding door (row [ROSTER-KEY-LOG-FLOOD], PR 2: fold
//! states share structure between rows; Stored change: keep). Every row's
//! folded state of one log, and the merge of them all, as the named
//! MessagePack a checkpoint image stores them in. A test compares the bytes
//! one build writes with the bytes another build writes for the same log,
//! and checks that each state's bytes decode and re-encode to the same
//! bytes. Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::FoldContext;
use super::fold_state::FoldState;
use super::{AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityVaultId};

static NO_PEERS: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>> = BTreeMap::new();
static NO_HANDOFFS: BTreeSet<AuthorityEntryHash> = BTreeSet::new();

/// One log's folded states as named MessagePack.
pub struct StateEncodings {
    /// Each folded row's hash and the bytes of its state, in hash order.
    pub rows: Vec<(AuthorityEntryHash, Vec<u8>)>,
    /// The bytes of the merge of every row's state, merged in hash order
    /// as the once fold merges them.
    pub merged: Vec<u8>,
    /// The merged state's entries in the maps that one row grows by one:
    /// roster, federation confirms, critical write confirms, actor bindings
    /// and residence directives. Past 64 a persistent map holds its large
    /// form.
    pub merged_entries: usize,
}

/// Every row's folded state of `entries`, and their merge, encoded: the
/// fold's per-row pass over the whole log, with no handoff, no sequence
/// floor and no memory floor.
pub fn state_encodings(entries: &[AuthorityLogEntry]) -> StateEncodings {
    let by_hash: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = entries
        .iter()
        .map(|entry| {
            (
                super::authority_entry_hash(entry).expect("row hash"),
                entry.clone(),
            )
        })
        .collect();
    let (ancestors, _) = super::ancestor_index::entry_ancestor_index(&by_hash, u64::MAX)
        .expect("no memory floor refuses");
    let mut issues = Vec::new();
    let context = FoldContext {
        sequence_floors: None,
        floor_vouched: None,
        install_held: None,
        entry_ancestors: Some(&ancestors),
        causal_past: None,
        peer_consent_roots: &NO_PEERS,
        consent_arm: super::folded_device_can_authority_consent,
        hosted: false,
        machine_standing: &super::machine_standing::every_chain,
        pre_handoff_entries: Some(&NO_HANDOFFS),
        memory_floor_bytes: u64::MAX,
        pin: None,
        // The fold's first pass: no owner-key enrolment's line is known yet.
        owner_key_lines: None,
        appointments: None,
    };
    let states = super::fold_schedule::fold_entry_states(&by_hash, context, &mut issues);
    let mut merged: Option<FoldState> = None;
    for state in states.values() {
        merged = Some(match merged {
            Some(current) => super::fold_state::merge_states(&current, state),
            None => state.clone(),
        });
    }
    let merged = merged.expect("a folded row");
    StateEncodings {
        rows: states
            .iter()
            .map(|(hash, state)| (*hash, encoded(state)))
            .collect(),
        merged: encoded(&merged),
        merged_entries: merged.roster.len()
            + merged.federation_confirms.len()
            + merged.critical_write_confirms.len()
            + merged.actor_bindings.len()
            + merged.residence_directives.len(),
    }
}

/// A state's bytes decoded, then encoded again.
pub fn reencoded(bytes: &[u8]) -> Vec<u8> {
    let state: FoldState = rmp_serde::from_slice(bytes).expect("a state's bytes decode");
    encoded(&state)
}

/// The named MessagePack of `state`, as a checkpoint image writes it.
fn encoded(state: &FoldState) -> Vec<u8> {
    rmp_serde::to_vec_named(state).expect("a fold state encodes")
}
