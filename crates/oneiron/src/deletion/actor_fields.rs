//! An erased actor's name, out of the rows that record it outside its own
//! record (FIX 3520).
//!
//! A side table that records an actor names its scrub in its declaration
//! (`side_table::decls`, an entry ending `=> scrub`), and this sweep walks
//! them, so a new table reaches the erase by declaring its scrub there.
use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::ActorScrub;

use super::tombstone::HARD_DELETE_MARKER;

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

/// Every id `vault`'s hard-delete markers name: each hard-erased id, actor or
/// not, a marker-only one a replay left included. Read while a restore's
/// live source still stands, so its erasures since the checkpoint carry over.
pub(crate) fn hard_erased_ids_in(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    hard_erased_ids_in_txn(vault, &rtxn)
}

fn hard_erased_ids_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<BTreeSet<EntityId>> {
    let mut ids = BTreeSet::new();
    for row in HARD_DELETE_MARKER.iter_raw_from(&vault.store, rtxn, &[])? {
        let (key, _) = row?;
        // A key that spells no id names no actor.
        if let Some(id) = std::str::from_utf8(&key)
            .ok()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// A checkpoint restore's actor sweep, in its image-write transaction once
/// the type index is back (FIX 3655): every id a restored hard-delete marker
/// names, and each of `live`, gets the erase's actor sweep again, so a
/// restored row does not bring back an erased actor's name. Only the name
/// goes; the restored content stays.
pub(crate) fn rerun_actor_scrubs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    live: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut erased = hard_erased_ids_in_txn(vault, wtxn)?;
    erased.extend(live);
    for actor in &erased {
        erase_actor_fields_in_txn(vault, wtxn, actor)?;
    }
    Ok(())
}
