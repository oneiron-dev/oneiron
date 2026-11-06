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

use crate::error::Result;
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
