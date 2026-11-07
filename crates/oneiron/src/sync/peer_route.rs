//! FIX 4748 (owner RULING B, 2026-10-19): while the home node is off, linked
//! devices sync device to device over the mesh, and they converge when the
//! home returns (ARCH-0023b `#home-down`, `#peer-fetch`: "Only machines
//! marked mine serve. ... The asker tries the standby home first.").
//!
//! This module holds the engine calls of the asking side: when a device
//! counts its home down ([`HOME_DOWN_AFTER_SECS`]), how often it probes the
//! home while it syncs with a peer ([`HOME_PROBE_SECS`],
//! [`HOME_PROBE_TIMEOUT_SECS`]), which machines it asks and in which order
//! ([`choose_sync_peer`]), and which of a peer's frames it leaves alone
//! ([`peer_ignores_frame`]). The connection's peer sessions live in
//! `sync::connection::peer_session`: a peer session exchanges updates both
//! ways as a home session does, and confirms nothing, so the queue stays
//! whole for the home.
//!
//! None of it runs without a mesh: a link with no peer dialer
//! (`SyncClientConfig::peer_dialer`, set only while a mesh listener runs
//! here) never counts its home down.
//!
//! The serving side reads [`authority_fold_settled`]: a machine serves a
//! peer only while its own authority fold is settled. A peer gets state,
//! never operations: every window export to it is the window's state-only
//! copy, whatever vector its asker sends, or nothing when the asker already
//! holds all of it ([`peer_state_copy_owed`]). The asking side installs a
//! peer's copy only when the copy holds everything its own replica holds
//! ([`installs_peer_state_copy`]), so it never loses its own writes to one.
//! Both ends leave a [`PeerSyncReceipt`] naming the other machine and the
//! session.

use loro::{LoroDoc, VersionVector};

use crate::error::Result;
use crate::sync::mesh_path::{MeshPathDirection, MeshPathOutcome, MeshPathReceipt, SYNC_ALPN};
use crate::sync::transport;
use crate::{EntityId, Vault};

/// FIX 4748 engine call (CALLS "FIX 4748 home down after"): how long the
/// dials to the home must fail in a row, none of them answered, before the
/// device counts its home down and syncs with its other machines.
pub const HOME_DOWN_AFTER_SECS: u64 = 60;

/// FIX 4748 engine call (CALLS "FIX 4748 home probe"): how often a peer
/// session probes the home; the session ends once the home answers.
pub const HOME_PROBE_SECS: u64 = 30;

/// FIX 4748 engine call (CALLS "FIX 4748 home probe timeout"): how long one
/// probe waits for the home's carrier to open before it counts the home
/// still down.
pub const HOME_PROBE_TIMEOUT_SECS: u64 = 10;

/// FIX 4748 engine call (CALLS "FIX 4748 peer order"): the machines a device
/// whose home `down_home` is down asks for sync, best first, or none.
///
/// The candidates are the machines this vault's mesh grants admit on `alpn`
/// ([`Vault::mesh_machines_granted`], the sync ALPN), less this machine
/// (`local`) and the down home, kept only when marked mine: a trusted
/// identity under this install's pin, the mark the world privacy judge reads.
/// The standby home leads: the machine the MACRO election would pick next
/// with the down home out, by the election's own rank over each machine's
/// signed candidacy (the owner's pick, then an attached cloud, an always-on
/// node, a primary device, the lowest node id breaking a tie). Every other
/// candidate follows in that same rank, machines with no eligible candidacy
/// last, by machine id. No signed row says a machine holds a full copy yet,
/// so none ranks first for it (My network item 04 waits on one).
///
/// Fails closed: a grant list, fold or pick this snapshot cannot read asks
/// no peer, and the reason is logged.
#[must_use]
pub fn choose_sync_peer(
    vault: &Vault,
    alpn: &[u8],
    local: EntityId,
    down_home: EntityId,
) -> Vec<EntityId> {
    let ranked = vault
        .mesh_machines_granted(alpn)
        .and_then(|granted| rank_sync_peers(vault, &granted, local, down_home));
    match ranked {
        Ok(peers) => peers,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "device sync asks no peer: the grants or the fold did not read"
            );
            Vec::new()
        }
    }
}

/// [`choose_sync_peer`]'s order over `granted`, in one snapshot.
fn rank_sync_peers(
    vault: &Vault,
    granted: &[EntityId],
    local: EntityId,
    down_home: EntityId,
) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let fold = match vault.authority_view_readonly_in_txn(&txn) {
        Ok(fold) if !fold.vault_root_is_conflicted() => fold,
        Ok(_) => return Ok(Vec::new()),
        Err(error) if crate::authority::is_history_incomplete(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let pick =
        crate::authority::election_home_pick_in_txn(&vault.store, vault.privacy_posture(), &txn)?
            .and_then(|picks| picks.election_pick());
    let mut ranked: Vec<(u8, u64, EntityId)> = granted
        .iter()
        .copied()
        .filter(|machine| *machine != local && *machine != down_home)
        .filter(|machine| fold.trusted_machine(*machine).is_some())
        .map(|machine| {
            let (rank, node_id) = fold
                .judged_home_candidacy(machine)
                .as_ref()
                .and_then(crate::dreamer_runner::declared_home_candidate)
                .and_then(|candidate| {
                    crate::dreamer_runner::home_candidate_rank(&candidate, pick)
                        .map(|rank| (rank, candidate.node_id))
                })
                .unwrap_or((u8::MAX, u64::MAX));
            (rank, node_id, machine)
        })
        .collect();
    ranked.sort_unstable();
    ranked.dedup();
    Ok(ranked.into_iter().map(|(_, _, machine)| machine).collect())
}

/// FIX 4748 engine call (CALLS "FIX 4748 peer relays"): whether a frame of
/// `tag` from a peer is left alone. The sealed world-update relay, the
/// custody leaf-key relay and the lease registrar are the home's; a peer
/// serves none of them, and a frame of one from it changes nothing here.
#[must_use]
pub const fn peer_ignores_frame(tag: u8) -> bool {
    matches!(
        tag,
        transport::TAG_SEALED_UPDATE | transport::TAG_LEAF_KEY_REQUEST
            ..=transport::TAG_LEAF_KEY_FAILURE | transport::TAG_LEASE_GRANTED
    )
}

/// FIX 4748 engine call (CALLS "FIX 4748 peer serve settled fold"): whether
/// this machine's authority fold is settled enough to serve a peer; it fails
/// closed otherwise ("It fails closed while the authority fold is
/// unsettled"). Settled is all of: the fold reads (no history it lacks
/// refuses it), its vault root is not in conflict, every row its own rows
/// and checkpoint name is held ([`Vault::authority_missing_history`]), and
/// this machine's own chains do not rest on an unsettled roster root (no
/// chain `admitter_unsettled`, the retired-signer conflict mark).
///
/// # Errors
///
/// Storage errors, and a fold fault other than missing history.
pub fn authority_fold_settled(vault: &Vault) -> Result<bool> {
    {
        let txn = vault.store.env.read_txn()?;
        let fold = match vault.authority_view_readonly_in_txn(&txn) {
            Ok(fold) => fold,
            Err(error) if crate::authority::is_history_incomplete(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if fold.vault_root_is_conflicted() {
            return Ok(false);
        }
        let Some(local) = crate::identity::read_machine_id_in_txn(vault, &txn)? else {
            return Ok(false);
        };
        let settled = fold
            .machine(local)
            .is_some_and(|machine| !machine.chains().any(|(_, chain)| chain.admitter_unsettled));
        if !settled {
            return Ok(false);
        }
    }
    Ok(vault.authority_missing_history()?.is_complete())
}

/// FIX 4748 engine call (CALLS "FIX 4748 peer state-only export"): whether a
/// machine served as a peer while the home is down owes its asker a copy of
/// window `doc`, `remote` being the asker's version vector of it.
///
/// A peer gets state, never operations ("It serves state-only copies, never
/// history"): every window export to it is the state-only copy of the
/// window's current state (`window::export_window_state_for`), whatever
/// `remote` holds, and no update since `remote` goes, so a vector that names
/// part of the window's history earns none of it. The vector decides only
/// whether a copy goes at all: one is owed when `remote` does not cover every
/// operation `doc` holds, and none when the asker already holds them all, so
/// an asker that installed the current copy and asks again is sent nothing.
#[must_use]
pub fn peer_state_copy_owed(doc: &LoroDoc, remote: &VersionVector) -> bool {
    !remote.includes_vv(&doc.oplog_vv())
}

/// FIX 4748 engine call (CALLS "FIX 4748 peer copy install"): whether a
/// device in a peer session installs a peer's state-only copy of a window in
/// place of its own replica, `copy` the copy's version vector and `local` the
/// replica's.
///
/// It does only when `copy` covers `local`: the peer holds everything this
/// device holds of the window, so the install loses none of this device's
/// writes. Otherwise the device keeps its replica, sends the peer its own
/// writes first, and asks for the window again. Either way its queue stays
/// whole: a peer session retires no queued send, so the home session replays
/// every one.
#[must_use]
pub fn installs_peer_state_copy(copy: &VersionVector, local: &VersionVector) -> bool {
    copy.includes_vv(local)
}

/// The part one end of a peer sync session plays (FIX 4748).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSyncPart {
    /// This machine dialed the peer while its home was down.
    Asked,
    /// This machine served the peer that dialed it.
    Served,
}

impl PeerSyncPart {
    const fn label(self) -> &'static str {
        match self {
            Self::Asked => "asked",
            Self::Served => "served",
        }
    }
}

/// One end's receipt of a peer sync session (FIX 4748: "both ends write a
/// receipt"), so the owner can see which peer served whom. It is a mesh path
/// receipt row ([`MeshPathReceipt`], local only, never synced) on the sync
/// ALPN: `machine` names the other machine, `direction` this end's part, and
/// `detail` the session, by the upgrade proof's nonce both ends read, with
/// this end's part or why it refused. It is written when the session opens
/// or is refused, and again with its close time when it ends.
#[derive(Debug, Clone)]
pub struct PeerSyncReceipt {
    receipt: MeshPathReceipt,
}

impl PeerSyncReceipt {
    /// Leaves the receipt of session `session` with `peer`, which this end
    /// played as `part`; `refused` names why this end refused it, and the
    /// receipt is then `Refused`. A receipt that does not land is logged.
    #[must_use]
    pub fn leave(
        vault: &Vault,
        part: PeerSyncPart,
        peer: EntityId,
        session: &str,
        refused: Option<&str>,
    ) -> Self {
        let direction = match part {
            PeerSyncPart::Asked => MeshPathDirection::Outbound,
            PeerSyncPart::Served => MeshPathDirection::Inbound,
        };
        let outcome = match refused {
            Some(_) => MeshPathOutcome::Refused,
            None => MeshPathOutcome::Admitted,
        };
        let mut receipt = MeshPathReceipt::new(direction, outcome, SYNC_ALPN);
        receipt.machine = Some(peer.to_hex());
        let part = part.label();
        receipt.detail = Some(match refused {
            Some(reason) => format!("peer sync session {session}: {part}, refused: {reason}"),
            None => format!("peer sync session {session}: {part}"),
        });
        if let Some(id) = vault.leave_mesh_path_receipt(&receipt) {
            receipt.id = id;
        }
        Self { receipt }
    }

    /// Writes the session's end on its receipt; one that never landed stays
    /// unwritten.
    pub fn close(mut self, vault: &Vault) {
        if self.receipt.id.is_empty() {
            return;
        }
        self.receipt.closed_at_ms = Some(crate::unix_millis_now());
        let _ = vault.leave_mesh_path_receipt(&self.receipt);
    }
}
