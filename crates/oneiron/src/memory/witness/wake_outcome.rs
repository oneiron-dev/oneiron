//! What a landed turn's program wake came to (DOOR-141, FIX 9970): the
//! accepted turn's receipt says it, and a wake the turn could not record
//! labels the turn, so a later read of it shows the failure too. The turn is
//! accepted either way; a wake that fails rolls back alone.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The label of each TURN whose landing could not record its program wake,
/// and why. Key: the TURN.
const UNPERSISTED: SideTable<EntityId, UnpersistedWakeReason, Named> =
    SideTable::new(&side_table::MEMORY_TURN_WAKE_UNPERSISTED);

#[doc(hidden)]
pub use oneiron_verb_wire::memory::witness::wake_outcome::{
    TurnProgramWakeOutcome, UnpersistedWakeReason,
};

/// Keeps `turn`'s label as `outcome` leaves it, in the landing's own writer:
/// an unpersisted wake labels the turn, and a landing that evaluates its wake
/// clears an earlier label. The label is written in a savepoint of its own;
/// one that cannot be kept is logged, and the turn commits as it would have.
pub(super) fn keep_wake_label_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    turn: EntityId,
    outcome: TurnProgramWakeOutcome,
) {
    if let Err(error) = write_wake_label_in_txn(vault, wtxn, turn, outcome) {
        tracing::warn!(
            kind = ?error.kind(),
            turn = %turn.to_hex(),
            "a turn's unpersisted-wake label was not kept; the turn commits"
        );
    }
}

fn write_wake_label_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    turn: EntityId,
    outcome: TurnProgramWakeOutcome,
) -> Result<()> {
    let reason = match outcome {
        TurnProgramWakeOutcome::Unpersisted { reason } => Some(reason),
        TurnProgramWakeOutcome::NotArmed | TurnProgramWakeOutcome::Evaluated { .. } => None,
    };
    if reason.is_none() && !UNPERSISTED.contains(vault, &*wtxn, &turn)? {
        return Ok(());
    }
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match reason {
        Some(reason) => UNPERSISTED.put(vault, &mut savepoint, &turn, &reason)?,
        None => {
            UNPERSISTED.delete(vault, &mut savepoint, &turn)?;
        }
    }
    savepoint.commit()?;
    Ok(())
}

/// The wake outcome a read of `turn` shows: its unpersisted label, when one
/// stands; `None` otherwise.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn turn_wake_outcome_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnProgramWakeOutcome>> {
    Ok(UNPERSISTED
        .get_lenient(vault, txn, turn)?
        .map(|reason| TurnProgramWakeOutcome::Unpersisted { reason }))
}

/// Drops the label an erase of `id` covers. Registered in
/// `deletion/derived_rows.rs`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_turn_wake_label_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    UNPERSISTED.delete(store, txn, id)?;
    Ok(())
}
