//! The single MACRO home-node election (ARCH-0026; DOOR-101 PR2a; FIX
//! 4898): which node of the vault runs its MACRO consolidation.
//!
//! Every election ranks one source of candidates
//! ([`authorized_home_candidates_in_txn`]): each live owner machine that
//! declares itself able to run MACRO now, by its signed home candidacy
//! (`authority::home_candidacy`) judged on the fold the election reads, and
//! beside them the candidacy this node's host kept for itself. The owner's
//! picked node wins outright when it is a live eligible candidate; without
//! one, an attached cloud, then an always-on node, then a primary device;
//! the lowest node id breaks a tie in a tier. A pick that is absent,
//! cleared, in conflict, unknown here or not eligible now leaves the default
//! order, and stays recorded until a matching declaration lands. Picks and
//! declarations are signed rows of the vault's main authority log, so every
//! linked machine folds the same ones; each elects on its own fold, and the
//! designation it writes is its own.
//!
//! This node keeps the host's own candidacy as the host last supplied it,
//! never inferred from the winner or the pick, and reads the declarations
//! again on every election, so a pick, a declaration or a machine's removal
//! that lands from the owner's surface or from a peer's log re-elects here
//! in the transaction that lands it. While the host has supplied no
//! candidacy, nothing is elected. Two machines that declare one node id
//! refuse the election, and the last elected home stands. The designation's
//! time moves only when its node or class does. Re-election moves no
//! admitted call, lease or budget: the old home only stops admitting new
//! MACRO work.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::HostingPrivacyPosture;
use crate::authority::JudgedHomeCandidacy;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

use super::codec::invalid_dreamer_runner;
use super::store::DreamerRunnerStore;
use super::types::{DreamerHomeNodeCandidate, DreamerHomeNodeDesignation};

/// The single elected MACRO home-node designation.
const HOME_NODE: SideTable<(), DreamerHomeNodeDesignation, Raw> =
    SideTable::new(&side_table::DREAMER_HOME_NODE);
/// The host's own candidacy, exactly as it last supplied it: its claim of
/// itself, or a topology owner's set. Every election ranks it beside the
/// vault's authorized declarations.
const HOME_CANDIDATES: SideTable<(), Vec<DreamerHomeNodeCandidate>, Named> =
    SideTable::new(&side_table::DREAMER_HOME_CANDIDATES);

/// The candidates one election ranks, and a node id two standing machines
/// declare, which refuses the election.
pub(super) struct HomeCandidates {
    pub(super) candidates: Vec<DreamerHomeNodeCandidate>,
    ambiguous: Option<u64>,
}

impl HomeCandidates {
    /// The host's own candidacy alone: what an election ranks while it
    /// cannot read the vault's declarations.
    fn local(local: &[DreamerHomeNodeCandidate]) -> Self {
        Self {
            candidates: local.to_vec(),
            ambiguous: None,
        }
    }

    /// The one candidate source (Engine 10-19, FIX 4898 rulings 1-2): each
    /// machine's newest declaration whose machine stands as one of the
    /// owner's machines under this install's pin and that says it can run
    /// MACRO now, with its declared facts, attached while its declaration
    /// is live; then each of the host's own `local` candidates whose node no
    /// such declaration names, unless only machines that no longer stand
    /// declare that node: a removed, held or key-conflicted machine never
    /// stands for itself again. A host candidate whose own machine declares
    /// it cannot run MACRO now stands only while no other eligible candidate
    /// does: a vault no node has claimed is claimed there, as a host with its
    /// Dreamer off claims it for its standing questions.
    pub(super) fn of(declared: &[JudgedHomeCandidacy], local: &[DreamerHomeNodeCandidate]) -> Self {
        // Each declared node: how many standing machines declare it, and
        // whether one of them can run MACRO now.
        let mut bound = BTreeMap::<u64, (usize, bool)>::new();
        let mut fallen = BTreeSet::new();
        for declaration in declared {
            if declaration.stands {
                let (machines, ready) = bound.entry(declaration.node_id).or_default();
                *machines += 1;
                *ready |= declaration.macro_ready;
            } else {
                fallen.insert(declaration.node_id);
            }
        }
        let ambiguous = bound
            .iter()
            .find(|(_, (machines, _))| *machines > 1)
            .map(|(node_id, _)| *node_id);
        let mut candidates: Vec<_> = declared
            .iter()
            .filter(|declaration| declaration.owner_machine && declaration.macro_ready)
            .map(|declaration| DreamerHomeNodeCandidate {
                node_id: declaration.node_id,
                cloud: declaration.cloud,
                attached: true,
                always_on_local: declaration.always_on,
                primary_device: declaration.primary,
            })
            .collect();
        let named: BTreeSet<u64> = candidates
            .iter()
            .map(|candidate| candidate.node_id)
            .collect();
        let (unready, ready): (Vec<_>, Vec<_>) = local
            .iter()
            .copied()
            .filter(|candidate| {
                !named.contains(&candidate.node_id)
                    && (bound.contains_key(&candidate.node_id)
                        || !fallen.contains(&candidate.node_id))
            })
            .partition(|candidate| {
                bound
                    .get(&candidate.node_id)
                    .is_some_and(|(_, ready)| !*ready)
            });
        candidates.extend(ready);
        if candidates
            .iter()
            .all(|candidate| candidate.designation_class().is_none())
        {
            candidates.extend(unready);
        }
        Self {
            candidates,
            ambiguous,
        }
    }
}

/// The candidates an election in `txn` ranks: the vault's authorized home
/// candidacies beside the host's own `local` candidacy
/// ([`HomeCandidates::of`]); `None` when this snapshot cannot read the
/// declarations (history the vault lacks, conflicting vault roots).
pub(super) fn authorized_home_candidates_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    local: &[DreamerHomeNodeCandidate],
) -> Result<Option<HomeCandidates>> {
    Ok(
        crate::authority::election_home_candidacies_in_txn(store, posture, txn)?
            .map(|declared| HomeCandidates::of(&declared, local)),
    )
}

impl DreamerRunnerStore<'_> {
    /// Builds a local candidate from the vault's stable sync device identity.
    pub fn local_home_node_candidate(
        &self,
        attached: bool,
        always_on_local: bool,
        primary_device: bool,
    ) -> Result<DreamerHomeNodeCandidate> {
        let node_id = crate::identity::load_or_mint_client_id(self.vault)?;
        Ok(DreamerHomeNodeCandidate {
            node_id,
            cloud: false,
            attached,
            always_on_local,
            primary_device,
        })
    }

    /// Keeps `candidates` as the host's own candidacy, and elects and
    /// persists the single MACRO home-node designation over it and the
    /// vault's authorized declarations (`authorized_home_candidates_in_txn`).
    ///
    /// Election is deterministic over that source and the owner's home pick
    /// as this snapshot folds it: picked node > attached cloud > always-on
    /// local > primary device, with node id as a stable tie-breaker inside a
    /// tier. A pick or declarations this snapshot cannot read leave the
    /// host's own candidacy in the default order. The candidacy is kept, in
    /// the same write, so a later pick or declaration re-elects over it.
    pub fn elect_home_node(
        &self,
        candidates: &[DreamerHomeNodeCandidate],
        now: u64,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        let store = &self.vault.store;
        let posture = self.vault.privacy_posture();
        let mut wtxn = store.env.write_txn()?;
        // A fold this snapshot cannot read elects over the host's own
        // candidacy in the default order, as the election did before picks
        // and declarations: it never fails the topology write.
        let (pick, source) = match election_inputs(store, posture, &wtxn, candidates) {
            Ok(inputs) => inputs,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "MACRO home election read no owner pick or candidacy; it elects over the \
                     host's own candidacy in the default order"
                );
                (None, None)
            }
        };
        let source = source.unwrap_or_else(|| HomeCandidates::local(candidates));
        let (designation, moved) = elect_in_txn(store, &mut wtxn, &source, pick, now)?;
        HOME_CANDIDATES.put(store, &mut wtxn, &(), &candidates.to_vec())?;
        wtxn.commit()?;
        // The deadline lane re-reads at once: a node that gained the home
        // arms its queued Macro work, and one that lost it stops arming.
        if moved {
            store.notify_proactivity_changes();
        }
        Ok(designation)
    }

    /// Re-elects when the topology owner supplies a changed candidate set,
    /// kept as the host's own candidacy beside the vault's authorized
    /// declarations.
    ///
    /// This is an explicit topology update, not a socket liveness signal:
    /// each cloud candidate's `attached` bit comes from the host-authorized
    /// topology. A transport outage never revokes the current MACRO home.
    /// An empty set clears the host's own candidacy after an explicit
    /// detach; the declarations still elect.
    pub fn sync_topology_changed(
        &self,
        candidates: &[DreamerHomeNodeCandidate],
        now: u64,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        self.elect_home_node(candidates, now)
    }

    /// Reads the persisted MACRO home-node designation, if one exists.
    pub(crate) fn home_node_designation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        HOME_NODE.get(&self.vault.store, txn, &())
    }

    /// Reads the host's own candidacy as it last supplied it; `None` while
    /// no election has kept one.
    pub(crate) fn home_candidates_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<Vec<DreamerHomeNodeCandidate>>> {
        HOME_CANDIDATES.get(&self.vault.store, txn, &())
    }

    pub fn home_node_designation(&self) -> Result<Option<DreamerHomeNodeDesignation>> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.home_node_designation_in_txn(&rtxn)
    }
}

/// Re-elects this node's MACRO home in `txn` over the vault's authorized
/// declarations and the host's kept candidacy, and the owner's pick, as
/// `txn` folds them: where a pick, a declaration or a machine's removal may
/// have landed (the end of a batch that moved the authority log, an adopted
/// checkpoint) and before a MACRO admission. Nothing is elected while the
/// host keeps no candidacy, or while this snapshot cannot read the fold
/// (history the vault lacks, conflicting vault roots): the designation
/// stands. Returns whether the designation moved; the caller's commit owes
/// the wake.
///
/// Never fails the write that carries it (Engine 10-19 10:0x): an error
/// reading the fold or electing is logged, the last elected home stands,
/// and the next landing or admission elects again.
pub(crate) fn reelect_home_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: HostingPrivacyPosture,
) -> bool {
    match reelect(store, txn, posture) {
        Ok(moved) => moved,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "MACRO home re-election skipped; the last elected home stands"
            );
            false
        }
    }
}

fn reelect(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: HostingPrivacyPosture,
) -> Result<bool> {
    let Some(local) = HOME_CANDIDATES.get(store, txn, &())? else {
        return Ok(false);
    };
    let Some(picks) = crate::authority::election_home_pick_in_txn(store, posture, txn)? else {
        return Ok(false);
    };
    let Some(source) = authorized_home_candidates_in_txn(store, posture, txn, &local)? else {
        return Ok(false);
    };
    let now = crate::unix_seconds_now();
    let (_, moved) = elect_in_txn(store, txn, &source, picks.election_pick(), now)?;
    Ok(moved)
}

/// The owner's pick and the candidates as `txn` folds them, beside the
/// host's own `local` candidacy; each `None` when this snapshot cannot read
/// it.
fn election_inputs(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    local: &[DreamerHomeNodeCandidate],
) -> Result<(Option<u64>, Option<HomeCandidates>)> {
    let pick = crate::authority::election_home_pick_in_txn(store, posture, txn)?
        .and_then(|picks| picks.election_pick());
    Ok((
        pick,
        authorized_home_candidates_in_txn(store, posture, txn, local)?,
    ))
}

/// Elects over `source` and `pick`, and writes the designation when its
/// node or class moved; the same winner keeps its first time.
fn elect_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &HomeCandidates,
    pick: Option<u64>,
    now: u64,
) -> Result<(Option<DreamerHomeNodeDesignation>, bool)> {
    let previous = HOME_NODE.get(store, txn, &())?;
    // A node id two standing machines declare is ambiguous: the election
    // refuses it, as a zero or duplicate candidate is refused, and the last
    // elected home stands.
    if let Some(node_id) = source.ambiguous {
        tracing::warn!(
            node_id,
            "two machines declare one MACRO home node id; the election is refused and the last \
             elected home stands"
        );
        return Ok((previous, false));
    }
    let designation = elect_home_node_designation(&source.candidates, pick, now)?;
    if previous.as_ref().map(|home| (home.node_id, home.class))
        == designation.as_ref().map(|home| (home.node_id, home.class))
    {
        #[cfg(feature = "sync")]
        retry_home_move_in_txn(store, txn, previous.map(|home| home.node_id));
        return Ok((previous, false));
    }
    if let Some(designation) = designation {
        HOME_NODE.put(store, txn, &(), &designation)?;
    } else {
        HOME_NODE.delete(store, txn, &())?;
    }
    #[cfg(feature = "sync")]
    request_home_move_in_txn(
        store,
        txn,
        previous.map(|home| home.node_id),
        designation.map(|home| home.node_id),
    );
    Ok((designation, true))
}

/// FIX 5661: records with the home-state carrier (`sync::home_handoff`) that
/// this election moved the home from sync node `from` to `to`, so the old
/// home drains its free-time state and hands it to the new one. Only the
/// request rides the election's writer, in a savepoint: no export or signing
/// runs here, and a request that fails is logged and never refuses the
/// election. The next election of this node records it again
/// ([`retry_home_move_in_txn`]).
#[cfg(feature = "sync")]
fn request_home_move_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    from: Option<u64>,
    to: Option<u64>,
) {
    if let Err(error) = record_home_move_in_txn(store, txn, from, to) {
        tracing::warn!(
            kind = ?error.kind(),
            ?from,
            ?to,
            "the MACRO home moved with no drain request recorded; the next election records it"
        );
    }
}

#[cfg(feature = "sync")]
fn record_home_move_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<()> {
    let mut savepoint = store.env.nested_write_txn(txn)?;
    crate::sync::home_handoff::request_move_in_txn(store, &mut savepoint, from, to)?;
    savepoint.commit()?;
    Ok(())
}

/// FIX 5661: an election that moved nothing records a move the carrier has
/// not heard of. The last request the carrier holds names the node the home
/// moved to then; when this election's home is another, a later move went
/// unrecorded, and it moved from that node to this home.
#[cfg(feature = "sync")]
fn retry_home_move_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, home: Option<u64>) {
    match crate::sync::home_handoff::pending_move_in_txn(store, txn) {
        Ok(Some((_, to))) if to != home => request_home_move_in_txn(store, txn, to, home),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the MACRO home's drain request did not read; the next election reads it again"
            );
        }
    }
}

fn elect_home_node_designation(
    candidates: &[DreamerHomeNodeCandidate],
    pick: Option<u64>,
    now: u64,
) -> Result<Option<DreamerHomeNodeDesignation>> {
    let mut seen = HashSet::with_capacity(candidates.len());
    let mut best: Option<(u8, u64, DreamerHomeNodeDesignation)> = None;

    for candidate in candidates {
        if candidate.node_id == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer home node_id must be nonzero",
            ));
        }
        if !seen.insert(candidate.node_id) {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer home node candidate",
            ));
        }

        let Some(class) = candidate.designation_class() else {
            continue;
        };
        let rank = class.rank(pick == Some(candidate.node_id));
        let designation = DreamerHomeNodeDesignation {
            node_id: candidate.node_id,
            class,
            elected_at: now,
        };
        match best.as_ref() {
            Some((best_rank, best_node_id, _))
                if rank > *best_rank
                    || (rank == *best_rank && candidate.node_id > *best_node_id) => {}
            _ => best = Some((rank, candidate.node_id, designation)),
        }
    }

    Ok(best.map(|(_, _, designation)| designation))
}
