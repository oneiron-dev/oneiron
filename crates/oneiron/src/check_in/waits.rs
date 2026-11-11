//! The waits and canon's table "When nobody answers" (ARCH-0082 #waits and
//! #no-answer; ruling R2; Engine ruling P22-SHAPE Q5-Q7).
//!
//! Every transition takes an explicit `now`; a durable caller reads the
//! vault's store clock once per transaction. One call moves the ask at most
//! one rung, and a rung's wait starts when its entry is recorded, so a late
//! tick delays a rung and never skips its holders. A rung with no verified
//! holder skips no holder, so it is passed at once, with a receipt. At the
//! due instant the climb wins over an answer; at `until`, let-go wins over
//! everything.

use super::act_class::{ActClass, UndoClass};
use super::mode::CheckInMode;
use super::pending::{
    CapturedWait, HolderKind, PENDING, PendingCheckIn, PendingState, Rung, RungEntry, RungMembers,
    RungResolver,
};
use super::policy::{CheckInScope, ClassWait, class_wait};
use super::receipt::{CheckInOutcome, ReceiptFields, write_check_in_receipt_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// A refusal of a check-in door, with the rule it broke.
pub(super) fn refuse(rule: &str) -> Error {
    Error::InvalidConfig(format!("check_in: {rule}"))
}

/// Whether an exhausted chain may let the act proceed with an undo: an
/// undo restores it, or a revoke undoes it.
pub(super) fn is_undoable(act: ActClass) -> bool {
    matches!(
        act.row().undo,
        UndoClass::Undoable | UndoClass::UndoableByRevoke
    )
}

/// The class's effective wait per person rung for `act` in `scope`, from the
/// vault's resolved policy in `txn`.
pub(super) fn class_wait_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    act: ActClass,
    scope: &CheckInScope,
) -> Result<ClassWait> {
    let resolution = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    Ok(class_wait(resolution.check_in_policy(), act, scope))
}

/// One transition the host's tick made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckInTransition {
    /// The asker's `until` passed: let go.
    LetGo,
    /// The delay window ended in silence.
    WindowPassed,
    /// The delay window ended with an objection standing.
    ObjectionHeld,
    /// The rung's wait ended; the ask entered this rung.
    Climbed(Rung),
    /// The last rung's wait ended while the delay window still runs: the
    /// window's end decides.
    AwaitsWindow,
    /// The chain is exhausted: the act holds.
    Held,
    /// The chain is exhausted: the undoable act may proceed with its undo.
    ProceedWithUndo,
}

/// Makes the one transition due at `now` for the pending check-in `id`, in
/// `txn`: let-go at `until`, then the delay window's end, then the current
/// rung's end (a climb, or the chain's end). `None` when nothing is due.
///
/// # Errors
///
/// No such row; storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2e's host ticks it; until then only the test door does"
    )
)]
pub(crate) fn advance_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<Option<CheckInTransition>> {
    let mut row = PENDING
        .get(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    if row.state != PendingState::Open {
        return Ok(None);
    }
    let transition = if row.until.is_some_and(|until| now >= until) {
        settle(vault, txn, &mut row, PendingState::LetGo { at: now }, now)?;
        CheckInTransition::LetGo
    } else if let Some(objected) = row
        .delay_window
        .as_ref()
        .filter(|window| now >= window.ends_at)
        .map(|window| !window.objections.is_empty())
    {
        if objected {
            settle(
                vault,
                txn,
                &mut row,
                PendingState::ObjectionHeld { at: now },
                now,
            )?;
            CheckInTransition::ObjectionHeld
        } else {
            settle(
                vault,
                txn,
                &mut row,
                PendingState::WindowPassed { at: now },
                now,
            )?;
            CheckInTransition::WindowPassed
        }
    } else if row.chain_exhausted_at.is_some()
        || row.current_rung().is_none_or(|entry| now < entry.due_at())
    {
        return Ok(None);
    } else {
        enter_next_rung(vault, txn, &mut row, chain, now)?
    };
    PENDING.put(&vault.store, txn, &row.id, &row)?;
    Ok(Some(transition))
}

/// Moves the ask from its current rung (rung 1 at open) to the next rung
/// with a verified holder, passing each rung with none with a `skipped`
/// receipt, and pins the holders there with a `climbed` receipt. Past the
/// Owner rung, the chain is exhausted: canon's table decides.
pub(super) fn enter_next_rung(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &mut PendingCheckIn,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<CheckInTransition> {
    let mut next = match row.current_rung() {
        None => Some(Rung::Grantor),
        Some(entry) => entry.rung.next(),
    };
    while let Some(rung) = next {
        match chain.members(&vault.store, txn, row, rung)? {
            RungMembers::Holders(holders) if !holders.is_empty() => {
                let wait = if holders
                    .iter()
                    .any(|holder| holder.kind == HolderKind::Person)
                {
                    let floor = class_wait_in_txn(vault, txn, row.act, &row.scope)?;
                    let secs = floor.secs.max(row.asker_wait_secs.unwrap_or(0));
                    Some(CapturedWait {
                        floor,
                        secs,
                        due_at: now.saturating_add(secs),
                    })
                } else {
                    None
                };
                let entry = RungEntry {
                    rung,
                    entered_at: now,
                    holders,
                    skipped: None,
                    wait,
                    extension: None,
                };
                let fields = climbed_fields(row, &entry);
                row.rungs.push(entry);
                write_check_in_receipt_in_txn(
                    &vault.store,
                    txn,
                    row,
                    CheckInOutcome::Climbed,
                    None,
                    fields,
                    now,
                )?;
                return Ok(CheckInTransition::Climbed(rung));
            }
            members => {
                let link = match members {
                    RungMembers::Missing(link) => link,
                    RungMembers::Holders(_) => "no live holder".to_owned(),
                };
                let fields = ReceiptFields::new(row)
                    .with("rung", rung.as_str().to_owned())
                    .with("missing_link", link.clone());
                row.rungs.push(RungEntry {
                    rung,
                    entered_at: now,
                    holders: Vec::new(),
                    skipped: Some(link),
                    wait: None,
                    extension: None,
                });
                write_check_in_receipt_in_txn(
                    &vault.store,
                    txn,
                    row,
                    CheckInOutcome::Skipped,
                    None,
                    fields,
                    now,
                )?;
                next = rung.next();
            }
        }
    }
    exhaust(vault, txn, row, now)
}

fn climbed_fields(row: &PendingCheckIn, entry: &RungEntry) -> ReceiptFields {
    let holders = entry
        .holders
        .iter()
        .map(|holder| holder.principal.to_hex())
        .collect::<Vec<_>>()
        .join(",");
    let mut fields = ReceiptFields::new(row)
        .with("rung", entry.rung.as_str().to_owned())
        .with("holders", holders)
        .with("due_at", entry.due_at().to_string());
    if let Some(wait) = &entry.wait {
        fields = fields
            .with("wait_secs", wait.secs.to_string())
            .with("floor_secs", wait.floor.secs.to_string())
            .with("floor_source", wait.floor.source.receipt_token());
    }
    fields
}

/// Canon's table at the chain's end: a running delay window decides at its
/// end; an undoable `AskWhenUnsure` act with an undo plan proceeds with it;
/// any other act holds.
fn exhaust(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &mut PendingCheckIn,
    now: u64,
) -> Result<CheckInTransition> {
    if row.delay_window.is_some() {
        row.chain_exhausted_at = Some(now);
        return Ok(CheckInTransition::AwaitsWindow);
    }
    let proceeds = row.mode == CheckInMode::AskWhenUnsure && is_undoable(row.act);
    match row.undo_plan.clone().filter(|_| proceeds) {
        Some(undo_plan) => {
            settle(
                vault,
                txn,
                row,
                PendingState::ProceedWithUndo { at: now, undo_plan },
                now,
            )?;
            Ok(CheckInTransition::ProceedWithUndo)
        }
        None => {
            settle(vault, txn, row, PendingState::Held { at: now }, now)?;
            Ok(CheckInTransition::Held)
        }
    }
}

/// Puts `row` in the final `state`, with its receipt.
fn settle(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &mut PendingCheckIn,
    state: PendingState,
    now: u64,
) -> Result<()> {
    let (outcome, fields) = match &state {
        PendingState::LetGo { .. } => (CheckInOutcome::LetGo, ReceiptFields::new(row)),
        PendingState::Held { .. } => (CheckInOutcome::Held, ReceiptFields::new(row)),
        PendingState::ProceedWithUndo { undo_plan, .. } => (
            CheckInOutcome::ProceedWithUndo,
            ReceiptFields::new(row).with("undo_plan", undo_plan.clone()),
        ),
        PendingState::WindowPassed { .. } => {
            (CheckInOutcome::WindowPassed, ReceiptFields::new(row))
        }
        PendingState::ObjectionHeld { .. } => {
            (CheckInOutcome::ObjectionHeld, ReceiptFields::new(row))
        }
        PendingState::Open | PendingState::Answered { .. } => {
            return Err(Error::InvariantViolation(
                "a check-in settles by time only into a final state",
            ));
        }
    };
    row.state = state;
    write_check_in_receipt_in_txn(&vault.store, txn, row, outcome, None, fields, now)
}
