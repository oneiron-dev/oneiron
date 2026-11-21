//! FIX 5661 seam (Engine-approved 10-20 11:5x): the tables this build
//! registers with the carrier, and the narrow reads its adapters and the
//! election ask of it. Additive beside the carrier: no trait or body of the
//! carrier changes.
//!
//! One list for both ends, so a source and a target of one build register
//! the same tables at the same versions in one order: the free-time policy,
//! clock, cycles and receipts, then the spend trees those cycles hold, then
//! the items to resume, which need their cycles and their spend scopes
//! landed before them in the one adopting transaction, and last the
//! leave-notice delegations the home answers removed people with (FIX 7932),
//! the Coach's topology-audit section (FIX 7817), the owner's narrowing
//! history of the base agents' grants (STEWARD-NARROWING-RECEIPT-LOCAL), the
//! booking lifecycle's tokens, deposits, holds and receipts (FIX
//! [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]), which stand on no other
//! table, and the emergency reschedule's instructions, plans and checkpoints
//! (FIX [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE]), whose picks the token
//! section carries.

use heed::RoTxn;

use super::{HandoffStatus, HomeTableRegistration, HomeWrite, guard_in_txn, store};
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// Every table a home move carries in this build, in the order the carrier
/// exports and adopts them (CALLS: home tables). C2's drain, its adoption
/// and restore's live keys all walk this one list.
pub(crate) fn home_tables() -> [HomeTableRegistration; 15] {
    [
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimePolicyRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeClockRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeCycleRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeReceiptRows>(),
        HomeTableRegistration::of::<crate::agent_dispatch::spend_handoff::FreeTimeSpendRows>(),
        HomeTableRegistration::of::<crate::dreamer_runner::FreeTimeItemRows>(),
        HomeTableRegistration::of::<crate::authority::LeaveNoticeDelegationRows>(),
        // FIX 7817: the Coach's topology-audit candidates, selections and
        // results, one section; independent of the free-time sections.
        HomeTableRegistration::of::<crate::identity_topology::CoachTopologyAuditRows>(),
        // Engine RULING ROW4-NARROWING-HISTORY = A: the record of each
        // narrowing the owner applied, with its agent and owner as actor
        // parts; independent of every other section.
        HomeTableRegistration::of::<crate::federation::SystemAgentNarrowingRows>(),
        // Lead ruling BK-HOME-MOVE-CARRIES-BOOKINGS = A (21 Nov 06:2x, "Money
        // follows the home"): the booking lifecycle's rows, its deposits with
        // them; each section stands alone, and the new home queues a settle
        // row for each carried deposit that still owes a move.
        HomeTableRegistration::of::<crate::booking::lifecycle::home_rows::BookingTokenRows>(),
        HomeTableRegistration::of::<crate::booking::lifecycle::home_rows::BookingHoldRows>(),
        HomeTableRegistration::of::<crate::booking::lifecycle::home_rows::BookingReceiptRows>(),
        // Engine ANSWER BK-EMERGENCY-ROWS-CARRY-SCOPE = B: the emergency
        // reschedule's rows, each section standing alone; the adopting writer
        // rebuilds their lookups.
        HomeTableRegistration::of::<
            crate::booking::emergency_reschedule::home_rows::EmergencyInstructionRows,
        >(),
        HomeTableRegistration::of::<
            crate::booking::emergency_reschedule::home_rows::EmergencyPlanRows,
        >(),
        HomeTableRegistration::of::<
            crate::booking::emergency_reschedule::home_rows::EmergencyItemRows,
        >(),
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

/// FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]: whether this node's election named it the
/// target of a move from another node that no adoption here has answered, while that node can
/// still hand its state over: its machine still stands as one of the owner's
/// ([`super::delivery::candidate_machine`]), so a handoff from it can still open and land here.
/// A recorded outcome does not end the wait (review round 2 of #10058): `NotArrived` and every
/// other reason leave the move able to land later ([`super::adopt`] admits it), so a row this node
/// opened meanwhile under a key the move also carries would make the whole adoption conflict.
/// The rows that move carries are not here yet: a domain that keeps its rows on the home alone
/// (booking) admits none of them, and answers no unknown provider id, until they are. The guard
/// ([`guard_in_txn`]) lets such a node write.
pub(crate) fn awaits_incoming_move_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    let head = store::head_in_txn(vault, txn)?;
    let node = crate::identity::read_client_id_from(vault, txn)?;
    let (
        Some(store::MoveRequest {
            from: Some(from),
            to: Some(to),
        }),
        Some(node),
    ) = (head.request, node)
    else {
        return Ok(false);
    };
    if to != node || from == node {
        return Ok(false);
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    Ok(super::delivery::candidate_machine(&fold, from).is_some())
}

/// Whether this node froze its home state for a move whose target has not acknowledged it
/// (review round 2 of #10058): `Some(false)` while the frozen handoff stands unacknowledged, so
/// its source can still cancel it and take the state back ([`super::cancel_frozen`]);
/// `Some(true)` once its target's ack landed, when the state is the new home's for good; `None`
/// while this node holds its state.
pub(crate) fn frozen_move_acknowledged_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<bool>> {
    let head = store::head_in_txn(dbs, txn)?;
    if head.holds_state() {
        return Ok(None);
    }
    let Some(floor) = head.floor else {
        return Ok(None);
    };
    Ok(Some(
        store::transfer_in_txn(dbs, txn, &floor.handoff)?
            .is_some_and(|transfer| transfer.status != HandoffStatus::Frozen),
    ))
}

/// Whether this node's own election names another node the vault's MACRO home, read in the
/// caller's writer (review round 2 of #10058): a domain whose rows only the home writes refuses
/// a write the door let through before the election moved. No designation, or no sync node id
/// here, answers `false`: the door refuses a node with no designation before any writer.
pub(crate) fn elected_home_elsewhere_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    let node = crate::identity::read_client_id_from(vault, txn)?;
    let home = crate::dreamer_runner::DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .map(|home| home.node_id);
    Ok(matches!((node, home), (Some(node), Some(home)) if node != home))
}
