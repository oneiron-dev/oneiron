//! Keyed indexes over the program tables (FIX 5735): an actor's erase and a
//! restore's rerun of it for each erased id read the actor's attempt stamps
//! and admissions by key, never every stamp and every admission. Each index
//! row is written in the writer that writes the row it names, and neither
//! row is ever deleted, so the index holds exactly the rows its table holds.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Each program attempt stamped as an actor, keyed by the actor, then the
/// attempt.
const ACTOR_ATTEMPT: SideTable<(EntityId, AttemptId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_ATTEMPT);
/// Each admission of a wake an actor's turn owed, keyed by the actor, then
/// the admission.
const ACTOR_ADMISSION: SideTable<(EntityId, [u8; 32]), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_ADMISSION);

/// Indexes `attempt` under the actor its stamp names, in the stamp's writer.
pub(super) fn index_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
) -> Result<()> {
    ACTOR_ATTEMPT.put(vault, txn, &(actor, attempt), &())
}

/// The program attempts stamped as `actor`, in key order.
pub(super) fn actor_attempts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<AttemptId>> {
    Ok(ACTOR_ATTEMPT
        .scan_keys(vault, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, attempt)| attempt)
        .collect())
}

/// Indexes `admission` under its waking actor, in the writer that first
/// writes it. A later rewrite keeps its actor, so it needs none.
pub(super) fn index_admission_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    admission: &[u8; 32],
) -> Result<()> {
    ACTOR_ADMISSION.put(vault, txn, &(actor, *admission), &())
}

/// The admissions of wakes `actor`'s turns owed, in key order.
pub(super) fn actor_admissions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<[u8; 32]>> {
    Ok(ACTOR_ADMISSION
        .scan_keys(vault, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, admission)| admission)
        .collect())
}
