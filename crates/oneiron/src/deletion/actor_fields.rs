//! An erased actor's name, out of the rows that record it outside its own
//! record (FIX 3520).
//!
//! A side table that records an actor names its scrub in its declaration
//! (`side_table::decls`, an entry ending `=> scrub`), and this sweep walks
//! them, so a new table reaches the erase by declaring its scrub there.
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::ActorScrub;

/// Identity ops are an entity family, not a side table: their decisions stay
/// and the actor's author carriers go.
const IDENTITY_OPS: ActorScrub = Vault::scrub_identity_op_actor_in_txn;

/// Runs in the purge's transaction: the identity ops first, then every
/// declared table's scrub in catalog order.
pub(super) fn erase_actor_fields_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    IDENTITY_OPS(vault, wtxn, actor)?;
    for scrub in crate::side_table::actor_scrubs() {
        scrub(vault, wtxn, actor)?;
    }
    Ok(())
}
