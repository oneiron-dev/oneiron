//! The single MACRO home-node election (ARCH-0026; DOOR-101 PR2a): which
//! node of the vault runs its MACRO consolidation.
//!
//! The election ranks the host's current candidates: an attached cloud,
//! then the owner's picked node when it is a live eligible candidate, then an
//! always-on node, then a primary device; the lowest node id breaks a tie in
//! a tier. A pick that is absent, cleared, in conflict, unknown here or not
//! eligible now leaves the default order. The pick is the owner's signed act
//! on the vault's main authority log (`authority::home_pick`), so every
//! linked machine folds the same pick; each elects from its own host's
//! candidates, and the designation it writes is its own.
//!
//! This node keeps the host's last candidate set as the host supplied it,
//! never inferred from the winner or the pick, so a pick that lands from the
//! owner's surface or from a peer's log re-elects here in the transaction
//! that lands it. With no candidate set kept, nothing is elected. The
//! designation's time moves only when its node or class does. Re-election
//! moves no admitted call, lease or budget: the old home only stops
//! admitting new MACRO work.

use std::collections::HashSet;

use crate::HostingPrivacyPosture;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

use super::codec::invalid_dreamer_runner;
use super::store::DreamerRunnerStore;
use super::types::{DreamerHomeNodeCandidate, DreamerHomeNodeDesignation};

/// The single elected MACRO home-node designation.
const HOME_NODE: SideTable<(), DreamerHomeNodeDesignation, Raw> =
    SideTable::new(&side_table::DREAMER_HOME_NODE);
/// The host's last validated candidate set, exactly as supplied.
const HOME_CANDIDATES: SideTable<(), Vec<DreamerHomeNodeCandidate>, Named> =
    SideTable::new(&side_table::DREAMER_HOME_CANDIDATES);

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

    /// Elects and persists the single MACRO home-node designation.
    ///
    /// Election is deterministic over the supplied current candidate set and
    /// the owner's home pick as this snapshot folds it: attached cloud >
    /// picked node > always-on local > primary device, with node id as a
    /// stable tie-breaker inside a tier. A pick this snapshot cannot read
    /// leaves the default order. The candidates are kept, in the same write,
    /// so a later pick re-elects over them.
    pub fn elect_home_node(
        &self,
        candidates: &[DreamerHomeNodeCandidate],
        now: u64,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        let store = &self.vault.store;
        let mut wtxn = store.env.write_txn()?;
        // A fold this snapshot cannot read elects in the default order, as
        // the election did before picks: it never fails the topology write.
        let pick = match crate::authority::election_home_pick_in_txn(
            store,
            self.vault.privacy_posture(),
            &wtxn,
        ) {
            Ok(picks) => picks.and_then(|picks| picks.election_pick()),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "MACRO home election read no owner pick; it elects in the default order"
                );
                None
            }
        };
        let (designation, moved) = elect_in_txn(store, &mut wtxn, candidates, pick, now)?;
        HOME_CANDIDATES.put(store, &mut wtxn, &(), &candidates.to_vec())?;
        wtxn.commit()?;
        // The deadline lane re-reads at once: a node that gained the home
        // arms its queued Macro work, and one that lost it stops arming.
        if moved {
            store.notify_proactivity_changes();
        }
        Ok(designation)
    }

    /// Re-elects when the topology owner supplies a changed candidate set.
    ///
    /// This is an explicit topology update, not a socket liveness signal:
    /// each cloud candidate's `attached` bit comes from the host-authorized
    /// topology. A transport outage never revokes the current MACRO home.
    /// An empty set clears the old designation after an explicit detach.
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

    pub fn home_node_designation(&self) -> Result<Option<DreamerHomeNodeDesignation>> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.home_node_designation_in_txn(&rtxn)
    }
}

/// Re-elects this node's MACRO home in `txn` over the host's kept candidates
/// and the owner's pick as `txn` folds it: where a pick may have landed (the
/// end of a batch that moved the authority log, an adopted checkpoint) and
/// before a MACRO admission. Nothing is elected while no candidate set is
/// kept, or while this snapshot cannot read the pick (history the vault
/// lacks, conflicting vault roots): the designation stands. Returns whether
/// the designation moved; the caller's commit owes the wake.
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
    let Some(candidates) = HOME_CANDIDATES.get(store, txn, &())? else {
        return Ok(false);
    };
    let Some(picks) = crate::authority::election_home_pick_in_txn(store, posture, txn)? else {
        return Ok(false);
    };
    let now = crate::unix_seconds_now();
    let (_, moved) = elect_in_txn(store, txn, &candidates, picks.election_pick(), now)?;
    Ok(moved)
}

/// Elects over `candidates` and `pick`, and writes the designation when its
/// node or class moved; the same winner keeps its first time.
fn elect_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    candidates: &[DreamerHomeNodeCandidate],
    pick: Option<u64>,
    now: u64,
) -> Result<(Option<DreamerHomeNodeDesignation>, bool)> {
    let designation = elect_home_node_designation(candidates, pick, now)?;
    let previous = HOME_NODE.get(store, txn, &())?;
    if previous.as_ref().map(|home| (home.node_id, home.class))
        == designation.as_ref().map(|home| (home.node_id, home.class))
    {
        return Ok((previous, false));
    }
    if let Some(designation) = designation {
        HOME_NODE.put(store, txn, &(), &designation)?;
    } else {
        HOME_NODE.delete(store, txn, &())?;
    }
    Ok((designation, true))
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
