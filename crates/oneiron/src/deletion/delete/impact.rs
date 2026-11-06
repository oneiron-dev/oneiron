//! Core half of `deletion::delete::impact`: its store-layer items live in `oneiron_store::deletion::delete::impact` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::delete::impact::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Both impact lists for the stored record `raw` at `id`, read in `txn`.
pub(super) fn bytes_impact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<(Vec<HeldBytes>, Vec<LfsChunkImpact>)> {
    let mut held = Vec::new();
    for content_hash in
        crate::blob_artifact::held_content_hashes_in_txn(&vault.store, txn, id, raw)?
    {
        let mut other_holders =
            crate::blob_artifact::content_holders_in_txn(&vault.store, txn, &content_hash)?;
        other_holders.retain(|holder| holder != id);
        held.push(HeldBytes {
            content_hash,
            other_holders,
        });
    }
    let chunks = crate::origin::lfs::lfs_chunk_owners_in_txn(&vault.store, txn, id, raw)?
        .into_iter()
        .map(|(chunk_hash, other_owners)| LfsChunkImpact {
            chunk_hash,
            other_owners,
        })
        .collect();
    Ok((held, chunks))
}
