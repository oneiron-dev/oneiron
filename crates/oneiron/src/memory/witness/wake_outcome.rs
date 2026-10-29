//! What a landed turn's program wake came to (DOOR-141, FIX 9970): the
//! accepted turn's receipt says it, and a wake the turn could not record
//! labels the turn, so a later read of it shows the failure too. The turn is
//! accepted either way; a wake that fails rolls back alone.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The label of each TURN whose landing could not record its program wake,
/// and why. Key: the TURN.
const UNPERSISTED: SideTable<EntityId, UnpersistedWakeReason, Named> =
    SideTable::new(&side_table::MEMORY_TURN_WAKE_UNPERSISTED);

/// The outcome of the wake a landed turn owes its actor's armed programs.
/// A turn that owes none (off record, an import, a host door's turn, or one
/// that lands no new words) carries no outcome at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TurnProgramWakeOutcome {
    /// The actor has no program armed: no wake is owed.
    NotArmed,
    /// The armed programs were judged and their wakes recorded in the turn's
    /// commit. `newly_recorded` counts the wakes this landing added; zero
    /// means none matched or each was already recorded, not that one failed.
    Evaluated {
        /// Wakes this landing recorded.
        newly_recorded: u32,
    },
    /// The turn's wake was not recorded, and no program wakes for it.
    Unpersisted {
        /// Why the wake was not recorded.
        reason: UnpersistedWakeReason,
    },
}

impl TurnProgramWakeOutcome {
    /// The outcome's wire name, as its `outcome` tag spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotArmed => "not_armed",
            Self::Evaluated { .. } => "evaluated",
            Self::Unpersisted { .. } => "unpersisted",
        }
    }
}

/// Why a turn's program wake was not recorded. It names the class of cause
/// only; the storage error and the caller's authority stay out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnpersistedWakeReason {
    /// The turn's caller seals no authority a program could run under (an
    /// operator root acting as nobody, a code run's call, a machine-signed
    /// write).
    NoAuthority,
    /// Reading the armed programs or writing the wake failed in storage.
    StorageFailure,
}

impl UnpersistedWakeReason {
    /// The reason's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAuthority => "no_authority",
            Self::StorageFailure => "storage_failure",
        }
    }
}

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
