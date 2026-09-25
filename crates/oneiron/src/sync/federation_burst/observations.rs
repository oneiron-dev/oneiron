//! Transactional per-principal/grant observations, independent of connections.

use super::{FederationPeer, corrupt};
use crate::llm::{NormalizedBurstInputs, normalized_burst_inputs};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct Observation {
    first: u64,
    tick: u64,
    completed: u64,
    recent: u64,
    streak: u32,
}

fn key(peer: &FederationPeer) -> Vec<u8> {
    let mut key = b"m:federation-observation:v1:".to_vec();
    key.extend_from_slice(&peer.digest());
    key
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>, key: &[u8]) -> Result<Observation> {
    vault.store.sync_queue.get(txn, key)?.map_or_else(
        || Ok(Observation::default()),
        |value| postcard::from_bytes(&value).map_err(|_| corrupt()),
    )
}

fn save(vault: &Vault, txn: &mut heed::RwTxn<'_>, key: &[u8], row: &Observation) -> Result<()> {
    let value = postcard::to_allocvec(row).map_err(|_| corrupt())?;
    vault.store.sync_queue.put(txn, key, &value)?;
    Ok(())
}

pub(super) fn observe_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    peer: &FederationPeer,
    writes: u64,
    now: u64,
) -> Result<NormalizedBurstInputs> {
    let key = key(peer);
    let mut row = load(vault, txn, &key)?;
    if row.recent == 0 && row.completed == 0 {
        row.first = now;
        row.tick = now;
    }
    // Clock rollback cannot discard observations or reset a peer's baseline.
    let now = now.max(row.tick);
    if now > row.tick {
        row.completed = row.completed.saturating_add(row.recent);
        row.recent = 0;
        row.tick = now;
    }
    row.recent = row.recent.saturating_add(writes.max(1));
    // Only completed clock ticks train the baseline. A current burst cannot
    // teach away its own signal. Cold start is the normalizer's clock seed.
    let baseline = row.completed as f64 / now.saturating_sub(row.first).max(1) as f64;
    let size = vault.store.entities.len(&*txn)?;
    let inputs = normalized_burst_inputs(row.recent, 1, baseline, size, row.streak);
    save(vault, txn, &key, &row)?;
    Ok(inputs)
}

pub(super) fn outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    peer: &FederationPeer,
    structural_failure: bool,
) -> Result<()> {
    let key = key(peer);
    let mut row = load(vault, txn, &key)?;
    row.streak = if structural_failure {
        row.streak.saturating_add(1)
    } else {
        0
    };
    save(vault, txn, &key, &row)
}

pub(super) fn record_outcome(
    vault: &Vault,
    peer: &FederationPeer,
    structural_failure: bool,
) -> Result<()> {
    peer.revalidate(vault)?;
    vault.with_write_txn(|txn| outcome_in_txn(vault, txn, peer, structural_failure))
}
