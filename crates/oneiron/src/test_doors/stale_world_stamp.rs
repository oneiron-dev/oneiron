//! Door for `tests/bounded_channel_narrowing_scope.rs`
//! (BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE): a stale
//! stamp for one foreign world, stored with no pact or registration behind
//! it, so a test reads how a run under `WorldScope::All` treats the claims
//! of a world whose federation went terminal.

use crate::Vault;
use crate::entity_id::ForeignWorldId;
use crate::error::Result;
use crate::federation::{
    FEDERATION_STALE_KEY_PREFIX, FederationStaleReason, WorldStaleStamp, encode_world_stale_stamp,
};

/// Stores a `Disconnected` stale stamp for `world`, the row a pact that goes
/// terminal leaves for each world it delivered.
///
/// # Errors
///
/// The store refuses the write.
pub fn stamp_world_stale(vault: &Vault, world: ForeignWorldId) -> Result<()> {
    let key = format!(
        "{FEDERATION_STALE_KEY_PREFIX}{}",
        world.entity_id().to_hex()
    );
    let stamp = encode_world_stale_stamp(WorldStaleStamp {
        reason: FederationStaleReason::Disconnected,
        disconnect_epoch: 1,
        stamped_at_secs: 1,
    });
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(txn, &key, &stamp)?;
        Ok(())
    })
}
