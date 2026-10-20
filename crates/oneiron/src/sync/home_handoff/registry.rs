//! FIX 5661 seam (Engine-approved 10-20 11:5x): the tables this build
//! registers with the carrier, and the narrow reads its adapters and the
//! election ask of it. Additive beside the carrier: no trait or body of the
//! carrier changes.
//!
//! One list for both ends, so a source and a target of one build register
//! the same tables at the same versions in one order: the free-time policy,
//! clock, cycles and receipts, then the spend trees those cycles hold, then
//! the items to resume, which need their cycles and their spend scopes
//! landed before them in the one adopting transaction.

use heed::RoTxn;

use super::{HomeTableRegistration, HomeWrite, guard_in_txn, store};
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// Every table a home move carries in this build, in the order the carrier
/// exports and adopts them (CALLS: home tables). C2's drain, its adoption
/// and restore's live keys all walk this one list.
pub(crate) fn home_tables() -> [HomeTableRegistration; 6] {
    [
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimePolicyRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeClockRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeCycleRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeReceiptRows>(),
        HomeTableRegistration::of::<crate::agent_dispatch::spend_handoff::FreeTimeSpendRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeItemRows>(),
    ]
}

/// Whether this node froze its home state for a move and adopted none
/// since: its rows of every registered table are history, and a move that
/// chains back here carries their successors.
pub(crate) fn froze_home_state_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(!store::head_in_txn(dbs, txn)?.holds_state())
}

/// The home move this node's election last recorded that no export or
/// adoption has answered yet, as its (from, to) sync node ids.
pub(crate) fn pending_move_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<(Option<u64>, Option<u64>)>> {
    Ok(store::head_in_txn(dbs, txn)?
        .request
        .map(|request| (request.from, request.to)))
}

/// [`guard_in_txn`]'s answer as a bool: `false` where the guard refuses a
/// write of `mode` on this node, an error only where a read failed.
pub(crate) fn takes_home_write_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mode: HomeWrite,
) -> Result<bool> {
    match guard_in_txn(vault, txn, mode) {
        Ok(()) => Ok(true),
        // The guard refuses with the carrier's one refusal (`super::refused`).
        Err(Error::InvalidConfig(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
