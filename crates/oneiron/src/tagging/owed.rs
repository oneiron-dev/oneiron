//! The tag passes a physical tear owes (FIX 6262).
//!
//! A tear that empties a kept TURN's missing-MESSAGE entry
//! ([`crate::store::turn_missing`]) has the store and no vault in hand, so it
//! cannot read the tagger the vault arms. It owes the turn its sieve read
//! there, and records the turn here for its tag pass, in the same
//! transaction. The reconciler's upkeep pays each row with the vault's
//! tagging configuration: a stored turn is marked at the bulk class, as the
//! erase doors mark one with the vault in hand, and its row goes in the same
//! write. A row goes with its turn when the turn is erased or torn. It is
//! derived and local: it lives in `vault_meta`, which sync never reads.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::extraction::ExtractionWork;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

use super::history::PRUNE_BUDGET;

/// A TURN owed a tag pass that a tear could not mark. Key: the turn id.
const OWED: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::TURN_TAG_OWED);

/// Owes `turn` a tag pass in the tear's transaction.
pub(crate) fn owe_tag_pass_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    OWED.put(store, txn, turn, &())
}

/// Drops the tag pass `id` is owed, as a turn that goes; whether it was owed
/// one.
pub(crate) fn forget_tag_pass_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    OWED.delete(store, txn, id)
}

/// Whether `id` is a turn owed a tag pass.
pub(crate) fn tag_pass_owed_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    OWED.contains(store, txn, id)
}

/// Pays the owed tag passes, at most [`PRUNE_BUDGET`] to a write, reading
/// `paused` before each write (FIX 6902): each stored turn is marked at the
/// bulk class under the tagger `vault` arms, and its row goes. A row whose
/// turn is not stored goes unmarked. One read finds whether any is owed, so
/// an upkeep with none opens no write. `Ok(true)` when `paused` cut it
/// short: the rows it did not reach wait for the next upkeep.
pub(super) fn pay_owed_tag_passes(vault: &Vault, paused: &dyn Fn() -> bool) -> Result<bool> {
    loop {
        if paused() {
            return Ok(true);
        }
        let owed = {
            let txn = vault.store.env.read_txn()?;
            let owed: Vec<EntityId> = OWED
                .iter_from(&vault.store, &txn, &[])?
                .take(PRUNE_BUDGET)
                .map(|row| row.map(|(turn, ())| turn))
                .collect::<Result<_>>()?;
            owed
        };
        if owed.is_empty() {
            return Ok(false);
        }
        vault.with_write_txn_grouped(|txn| {
            for turn in &owed {
                // A row another write paid or dropped meanwhile is gone.
                if OWED.delete(&vault.store, txn, turn)?
                    && vault.store.port_entity_present(txn, turn)?
                {
                    super::mark_turn_in_txn(vault, txn, *turn, ExtractionWork::Bulk)?;
                }
            }
            Ok(())
        })?;
    }
}
