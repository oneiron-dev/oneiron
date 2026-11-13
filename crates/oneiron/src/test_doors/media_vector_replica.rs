//! Doors for `tests/media_vector_replica.rs` (census L7-43): the receiver's install of a media
//! vector replica its home served, in one write of its own.

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
