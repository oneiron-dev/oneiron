//! Doors for `tests/media_vector_replica.rs` (census L7-43): the receiver's install of a media
//! vector replica its home served, in one write of its own, and a row as the vault stores it.

use crate::embed::MediaVectorReplica;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Installs `replica` as `id`'s vector, as the receiver's backfill installs one a home served
/// (`reuse_home_media_vectors`): whether it landed.
pub fn install_media_vector_replica(
    vault: &Vault,
    id: &EntityId,
    replica: &MediaVectorReplica,
) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    let installed =
        crate::embed::install_media_vector_replica_in_txn(vault, &mut txn, id, replica)?;
    txn.commit()?;
    Ok(installed)
}

/// `id`'s row as the vault stores it: a file-plane ASSET's row keeps the manifest that names its
/// body file, where the public `Vault::get_raw` hands the whole body in its place.
pub fn stored_row(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
    vault.get_raw_in(&vault.store.env.read_txn()?, id)
}
