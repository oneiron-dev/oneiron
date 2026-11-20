//! One deposit's provider moves: capture, void, refund (BK-DEPOSITS PR 2).
//!
//! [`run_booking_deposit_settlement`] drains the deposit's queued settle rows;
//! [`settle_booking_deposit`] runs one booking's due move at once. Each move
//! is decided in a writer, asked of the [`DepositSettlementPort`] with no
//! writer held, and recorded in a second writer only while the deposit still
//! owes exactly that move.

use super::super::door::attempt_failure_reason;
use super::super::storage::{booking_writer, engine_failure, read_txn, refused};
use super::super::token::hex_lower;
use super::{
    DEPOSIT, DEPOSIT_BOOKING, DepositSettlePayload, DepositState, MAX_FAILURE_BYTES, booking_key,
    bounded, enqueue_settle, put_deposit,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt,
    RequeueAttempt,
};
use crate::booking::BookingError;
use crate::{EntityId, Vault};

/// The attempt kind whose rows owe one deposit's next provider move.
pub const BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND: &str = "booking.deposit.settle";

/// The claim of one settle row at which a failed provider call stops running
/// again promptly: every claim before it retries
/// [`DEPOSIT_SETTLE_RETRY_SECONDS`] later, and from it on the row asks again
/// every [`DEPOSIT_SETTLE_OWED_RECHECK_SECONDS`]. A retry is safe: every
/// provider call carries an idempotency key per deposit, move and amount.
const DEPOSIT_SETTLE_PROMPT_ATTEMPTS: u32 = 8;

/// How long a settle row whose provider call failed waits before its next
/// prompt try.
const DEPOSIT_SETTLE_RETRY_SECONDS: u64 = 300;

/// How long a settle row waits before it asks again once the provider
/// refused its move, or its prompt tries are spent. The deposit still owes
/// the move, and what blocks it can end with no deposit transition to queue
/// a new row: an outage ends, or the owner repairs the provider key. So the
/// row never ends while the move is owed
/// (FIX [BK-DEPOSIT-SETTLE-OUTAGE-STRANDS-MOVE]).
const DEPOSIT_SETTLE_OWED_RECHECK_SECONDS: u64 = 3_600;

/// How long a settle row whose move the provider holds pending waits before
/// it asks again.
const DEPOSIT_SETTLE_PENDING_RECHECK_SECONDS: u64 = 3_600;

/// FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE] (BK-HOME-MOVE-CARRIES-BOOKINGS = A,
/// lead 21 Nov 06:2x: "Money follows the home"): whether this node still settles its
/// deposits, by the home-move fence (`sync::home_handoff::guard_in_txn`). A node that froze
/// its booking rows for a move does not: its deposit rows are history, the new home holds
/// them and owes their moves, so the old home moves no money. A node draining toward a move
/// still settles the deposits it admitted, so its settle rows can end before it freezes.
#[cfg(feature = "sync")]
pub(super) fn settles_deposits_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Settle,
    )
    .map_err(|error| engine_failure("home move fence read", error))
}

/// Without the home handoff no move ever freezes a deposit.
#[cfg(not(feature = "sync"))]
pub(super) fn settles_deposits_here(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(true)
}

/// Whether this node admits a new deposit checkout, by the home-move fence: not while it
/// drains its booking rows toward a move, nor once it froze them, nor while it waits for the
/// move that carries them here. The visitor starts the checkout on the new home once it holds
/// them: a destination that opened one first would store the payment the old home opened under
/// the same provider key as a second row, and that row would refuse the carried one.
#[cfg(feature = "sync")]
pub(super) fn admits_deposits_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Admit,
    )
    .map_err(|error| engine_failure("home move fence read", error))?
        && !awaits_carried_deposits(vault, txn)?)
}

/// Without the home handoff no move ever drains a node.
#[cfg(not(feature = "sync"))]
pub(super) fn admits_deposits_here(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(true)
}

/// Whether this node waits for a home move that carries its deposits here
/// (`sync::home_handoff::awaits_incoming_move_in_txn`): a payment it does not know may be one
/// that move carries.
#[cfg(feature = "sync")]
pub(super) fn awaits_carried_deposits(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    crate::sync::home_handoff::awaits_incoming_move_in_txn(vault, txn)
        .map_err(|error| engine_failure("home move state read", error))
}

/// Without the home handoff no move ever carries a deposit.
#[cfg(not(feature = "sync"))]
pub(super) fn awaits_carried_deposits(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(false)
}

/// Whether this node opens a deposit checkout now, asked before the server
/// creates the provider's payment: a node that drains its booking rows
/// toward a home move, froze them, or waits for the move that carries them
/// here opens none (FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]), and
/// [`begin_deposit_checkout`](super::begin_deposit_checkout) asks the same
/// again in its writer.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] where this node opens no checkout
/// now; [`BookingError::SlotOracle`] on a store failure.
pub fn check_deposit_checkout_admitted(vault: &Vault) -> Result<(), BookingError> {
    if !admits_deposits_here(vault, &read_txn(vault)?)? {
        return Err(refused(CHECKOUT_MOVING));
    }
    Ok(())
}

/// The refusal of a checkout on a node a home move is leaving or reaching.
pub(super) const CHECKOUT_MOVING: &str =
    "this node is moving its booking rows to a new home: the checkout starts there";

/// One provider move a deposit owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositSettleMove {
    /// Capture this much of the authorization (the rest is released).
    Capture { amount_minor: u64 },
    /// Cancel the payment; nothing is captured.
    Void,
    /// Refund this much of the capture.
    Refund { amount_minor: u64 },
}

impl DepositSettleMove {
    const fn tag(self) -> &'static str {
        match self {
            Self::Capture { .. } => "capture",
            Self::Void => "void",
            Self::Refund { .. } => "refund",
        }
    }

    const fn amount_minor(self) -> u64 {
        match self {
            Self::Capture { amount_minor } | Self::Refund { amount_minor } => amount_minor,
            Self::Void => 0,
        }
    }
}

/// One provider call: the payment, the move, and the idempotency key the
/// provider must dedupe it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSettleRequest<'a> {
    pub payment_id: &'a str,
    pub movement: DepositSettleMove,
    pub idempotency_key: &'a str,
}

/// Why a provider call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositProviderFailure {
    /// Worth another try: the network, a timeout, the provider's 5xx or 429.
    Transient(String),
    /// The provider took the move and has not finished it (a refund it
    /// holds pending), or the server could not ask the provider yet (its key
    /// is withheld, missing or not a test key). The deposit still owes the
    /// move; it is asked again later and never fails for good on this
    /// answer, since the provider ends the move one way or the other, and
    /// the owner can fix the key.
    Pending(String),
    /// The provider refused the move itself; another try answers the same
    /// until something changes at the provider (the owner repairs a key that
    /// lacks the permission, say). The deposit still owes the move, so its
    /// row asks again later and does not end on this answer.
    Permanent(String),
}

impl DepositProviderFailure {
    fn reason(&self) -> &str {
        match self {
            Self::Transient(reason) | Self::Pending(reason) | Self::Permanent(reason) => reason,
        }
    }
}

/// The provider seam the server implements. A call that succeeded and is
/// asked again with the same idempotency key must answer success.
pub trait DepositSettlementPort {
    /// Asks the provider for one move, and answers the amount it moved, in
    /// the currency's smallest unit: the amount the payment now has
    /// captured for a capture (also when an earlier capture already stood),
    /// or 0 when the payment stands cancelled at the provider, so nothing can
    /// be captured;
    /// the amount refunded for a refund, once the provider has finished it;
    /// for a void, 0, or the amount the payment had already captured when a
    /// capture stood before the void (a capture whose reply was lost), which
    /// the void cannot release and the deposit then owes back.
    ///
    /// # Errors
    ///
    /// [`DepositProviderFailure`] when the provider did not do it, or
    /// [`DepositProviderFailure::Pending`] while it has not finished it.
    fn settle(&mut self, request: &DepositSettleRequest<'_>)
    -> Result<u64, DepositProviderFailure>;
}

/// What one deposit's settle step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositSettleStep {
    /// Nothing is owed here: no such deposit, it stands settled, or this
    /// node froze it for a home move and the new home owes its moves.
    Nothing,
    /// Still in its checkout window; due again at this instant.
    Wait { due_at: u64 },
    /// The provider did this move, and the deposit recorded it.
    Moved(DepositSettleMove),
    /// The provider did not.
    Failed(DepositProviderFailure),
}

enum SettlePlan {
    Nothing,
    Wait {
        due_at: u64,
    },
    Move {
        payment_id: String,
        movement: DepositSettleMove,
        /// What the provider refunded before this refund; 0 for any other
        /// move.
        refunded_before: u64,
    },
}

/// One provider answer to record: the move asked, what the provider moved,
/// and what was refunded before it when the move was planned.
#[derive(Clone, Copy)]
struct SettledMove {
    movement: DepositSettleMove,
    moved: u64,
    refunded_before: u64,
}

/// Decides one deposit's next move in a writer. An open deposit whose
/// checkout window has ended turns void-due here, so no confirm can take it
/// after the decision.
///
/// A node that froze its booking rows for a home move plans nothing: the new
/// home holds the deposit and its owed move (FIX
/// [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]), so the old home's settle row
/// ends with no provider call.
fn plan_settle(vault: &Vault, key: &[u8; 32], now_utc: u64) -> Result<SettlePlan, BookingError> {
    booking_writer(vault, |wtxn| {
        if !settles_deposits_here(vault, &*wtxn)? {
            return Ok(SettlePlan::Nothing);
        }
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(SettlePlan::Nothing);
        };
        let mut refunded_before = 0;
        let movement = match row.state {
            DepositState::CaptureDue { amount_minor } => {
                DepositSettleMove::Capture { amount_minor }
            }
            DepositState::VoidDue => DepositSettleMove::Void,
            DepositState::RefundDue { amount_minor } => {
                refunded_before = row.refunded_minor;
                DepositSettleMove::Refund { amount_minor }
            }
            state if state.is_open() => {
                if now_utc < row.lease_expires_at {
                    return Ok(SettlePlan::Wait {
                        due_at: row.lease_expires_at,
                    });
                }
                row.state = DepositState::VoidDue;
                row.updated_at = now_utc;
                put_deposit(vault, wtxn, key, &row)?;
                DepositSettleMove::Void
            }
            _ => return Ok(SettlePlan::Nothing),
        };
        Ok(SettlePlan::Move {
            payment_id: row.payment_id,
            movement,
            refunded_before,
        })
    })
}

/// Records the provider's done move against what the deposit owes now.
///
/// A capture is recorded by what the provider captured, `moved`, against
/// what the deposit owes now: a cancel may have shrunk the capture, or
/// released it all, while the call ran (the writer is not held across it).
/// Then the provider holds more than the deposit keeps, and the difference
/// is owed back at once, as a refund queued in this same commit. A void that
/// found the payment already captured (a capture whose reply was lost, then
/// a cancel that released the deposit) owes that capture back the same way.
/// Either records what the provider captured. A refund adds to what was
/// refunded before it; when the owner's return came while it was owed, the
/// balance of the capture is owed next, queued in the same commit.
///
/// A capture that captured nothing found the payment cancelled at the provider
/// (a cancellation whose event this node never applied): the deposit stands
/// voided.
///
/// A refund records only against the refund it was planned for: what was
/// refunded before it, `refunded_before`, must still be what the deposit
/// says. A home move that went away and came back while the call ran can
/// leave the deposit owing a later refund, after more was refunded; the old
/// call's answer is not that refund's, and the queued row asks that one.
///
/// A node that froze its booking rows for a home move while the call ran
/// records nothing: the new home holds the deposit as it stood at the freeze,
/// owes this same move, and asks it under the same idempotency key, which the
/// provider answers as the move already done.
fn record_settled(
    vault: &Vault,
    key: &[u8; 32],
    planned: SettledMove,
    now_utc: u64,
) -> Result<(), BookingError> {
    let SettledMove {
        movement,
        moved,
        refunded_before,
    } = planned;
    booking_writer(vault, |wtxn| {
        if !settles_deposits_here(vault, &*wtxn)? {
            return Ok(());
        }
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(());
        };
        let next = match (row.state, movement) {
            (DepositState::CaptureDue { .. }, DepositSettleMove::Capture { .. }) if moved == 0 => {
                row.captured_minor = Some(0);
                DepositState::Voided
            }
            (
                DepositState::CaptureDue { amount_minor: owed },
                DepositSettleMove::Capture { .. },
            ) => {
                row.captured_minor = Some(moved);
                if moved > owed {
                    DepositState::RefundDue {
                        amount_minor: moved - owed,
                    }
                } else {
                    DepositState::Captured {
                        amount_minor: moved,
                    }
                }
            }
            (
                DepositState::VoidDue,
                DepositSettleMove::Capture { .. } | DepositSettleMove::Void,
            ) if moved > 0 => {
                row.captured_minor = Some(moved);
                DepositState::RefundDue {
                    amount_minor: moved,
                }
            }
            (DepositState::VoidDue, DepositSettleMove::Void) => DepositState::Voided,
            (DepositState::RefundDue { .. }, DepositSettleMove::Refund { .. })
                if row.refunded_minor == refunded_before =>
            {
                let refunded = row.refunded_minor.saturating_add(moved);
                let balance_owed = std::mem::take(&mut row.balance_owed_after_refund);
                match row.captured_minor {
                    Some(captured) if balance_owed && captured > refunded => {
                        row.refunded_minor = refunded;
                        DepositState::RefundDue {
                            amount_minor: captured - refunded,
                        }
                    }
                    _ => DepositState::Refunded {
                        amount_minor: refunded,
                    },
                }
            }
            // The deposit moved on while the call ran (a provider
            // cancellation, a refund recorded on another home); its own row
            // settles what is left.
            _ => return Ok(()),
        };
        let refund_owed = matches!(next, DepositState::RefundDue { .. });
        row.state = next;
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, key, &row)?;
        if refund_owed {
            let cause = match movement {
                DepositSettleMove::Void => "void-found-captured",
                DepositSettleMove::Capture { .. } => "capture-overtaken",
                DepositSettleMove::Refund { .. } => "owner-balance",
            };
            enqueue_settle(vault, wtxn, key, cause, now_utc)?;
        }
        Ok(())
    })
}

/// Runs one deposit's due move: decides it, asks the provider with no
/// writer held, and records the answer.
fn settle_deposit_key<P: DepositSettlementPort>(
    vault: &Vault,
    key: &[u8; 32],
    port: &mut P,
    now_utc: u64,
) -> Result<DepositSettleStep, BookingError> {
    let (payment_id, movement, refunded_before) = match plan_settle(vault, key, now_utc)? {
        SettlePlan::Nothing => return Ok(DepositSettleStep::Nothing),
        SettlePlan::Wait { due_at } => return Ok(DepositSettleStep::Wait { due_at }),
        SettlePlan::Move {
            payment_id,
            movement,
            refunded_before,
        } => (payment_id, movement, refunded_before),
    };
    // One key per deposit, move and amount: a retry of the same move is
    // deduped by the provider, and a smaller capture after a cancel is a
    // new request rather than a mismatched replay. A refund after an
    // earlier one also names what was refunded before it, so a balance
    // equal to the earlier refund is not taken for its replay.
    let key_hex = hex_lower(key);
    let digest = &key_hex[..32];
    let idempotency_key = if refunded_before > 0 {
        format!(
            "oneiron-deposit-{}-{}-after-{refunded_before}-{digest}",
            movement.tag(),
            movement.amount_minor(),
        )
    } else {
        format!(
            "oneiron-deposit-{}-{}-{digest}",
            movement.tag(),
            movement.amount_minor(),
        )
    };
    match port.settle(&DepositSettleRequest {
        payment_id: &payment_id,
        movement,
        idempotency_key: &idempotency_key,
    }) {
        Ok(moved) => {
            record_settled(
                vault,
                key,
                SettledMove {
                    movement,
                    moved,
                    refunded_before,
                },
                now_utc,
            )?;
            Ok(DepositSettleStep::Moved(movement))
        }
        Err(failure) => Ok(DepositSettleStep::Failed(failure)),
    }
}

/// Runs the due move of the booking `event_ref`'s deposit at once: the
/// server's capture right after a confirm. The booking's queued settle row
/// stays the backstop and finds nothing owed once this succeeds.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub fn settle_booking_deposit<P: DepositSettlementPort>(
    vault: &Vault,
    event_ref: &EntityId,
    port: &mut P,
    now_utc: u64,
) -> Result<DepositSettleStep, BookingError> {
    let link = {
        let rtxn = read_txn(vault)?;
        DEPOSIT_BOOKING
            .get(&vault.store, &rtxn, &booking_key(event_ref))
            .map_err(|error| engine_failure("meta read", error))?
    };
    match link {
        Some(link) => settle_deposit_key(vault, &link.deposit_key, port, now_utc),
        None => Ok(DepositSettleStep::Nothing),
    }
}

/// What one [`run_booking_deposit_settlement`] pass settled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BookingDepositSettlementDrain {
    pub captured: u32,
    pub voided: u32,
    pub refunded: u32,
    /// Rows of a deposit still in its checkout window, queued again for its
    /// end.
    pub waiting: u32,
    /// Rows that owed nothing any more.
    pub settled_nothing: u32,
    /// Rows whose provider call, or whose store write, failed and runs again
    /// promptly.
    pub retrying: u32,
    /// Rows whose move the provider holds pending, asked again later.
    pub pending: u32,
    /// Rows whose move the provider refused, or whose prompt tries are spent
    /// on a failing provider call or store write: the deposit still owes the
    /// move, and the row asks again later.
    pub still_owed: u32,
    /// Rows that failed for good: a row whose payload names no deposit, so
    /// no move is owed through it.
    pub failed: u32,
}

/// Claims and runs up to `limit` queued [`BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND`]
/// rows: each deposit's due move through `port`. A deposit still in its
/// checkout window is queued again for the window's end, where an
/// unconfirmed one is voided. A provider failure runs again five minutes
/// later, until the row's eighth claim. A move the provider refused, or one
/// still failing at that claim, is asked again an hour later, and so is a
/// move the provider holds pending, however many claims it took: a row ends
/// only once its deposit owes nothing, so an outage or a broken provider key
/// strands no capture, void or refund. A store failure while a move is
/// decided or recorded runs the row again the same way. Only a row whose
/// payload names no deposit fails for good.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a queue failure. A row whose move fails
/// is queued again and does not fail the pass.
pub fn run_booking_deposit_settlement<P: DepositSettlementPort>(
    vault: &Vault,
    lease_owner: &str,
    port: &mut P,
    limit: usize,
    now_utc: u64,
) -> Result<BookingDepositSettlementDrain, BookingError> {
    let queue = AttemptQueue::new(vault);
    let mut drain = BookingDepositSettlementDrain::default();
    for _ in 0..limit {
        let claimed = queue
            .claim_kind(
                BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now: now_utc,
                },
            )
            .map_err(|error| engine_failure("deposit settle claim", error))?;
        let ClaimOutcome::Claimed(record) = claimed else {
            break;
        };
        let settle = SettleRow {
            queue: &queue,
            record: &record,
            lease_owner,
            now_utc,
        };
        let key = match settle_payload_key(&record) {
            Ok(key) => key,
            Err(error) => {
                tracing::warn!(%error, "booking deposit settle row names no deposit");
                settle.fail(&error)?;
                drain.failed += 1;
                continue;
            }
        };
        let prompt = record.attempt_count < DEPOSIT_SETTLE_PROMPT_ATTEMPTS;
        match settle_deposit_key(vault, &key, port, now_utc) {
            Ok(DepositSettleStep::Nothing) => {
                settle.complete()?;
                drain.settled_nothing += 1;
            }
            Ok(DepositSettleStep::Wait { due_at }) => {
                settle.requeue("deposit checkout window still open", due_at)?;
                drain.waiting += 1;
            }
            Ok(DepositSettleStep::Moved(movement)) => {
                settle.complete()?;
                match movement {
                    DepositSettleMove::Capture { .. } => drain.captured += 1,
                    DepositSettleMove::Void => drain.voided += 1,
                    DepositSettleMove::Refund { .. } => drain.refunded += 1,
                }
            }
            Ok(DepositSettleStep::Failed(DepositProviderFailure::Pending(reason))) => {
                tracing::debug!(%reason, "booking deposit move is pending at the provider");
                settle.requeue(
                    &requeue_reason(&reason),
                    now_utc.saturating_add(DEPOSIT_SETTLE_PENDING_RECHECK_SECONDS),
                )?;
                drain.pending += 1;
            }
            Ok(DepositSettleStep::Failed(DepositProviderFailure::Transient(reason))) if prompt => {
                tracing::debug!(%reason, "booking deposit move runs again later");
                settle.requeue(
                    &requeue_reason(&reason),
                    now_utc.saturating_add(DEPOSIT_SETTLE_RETRY_SECONDS),
                )?;
                drain.retrying += 1;
            }
            Ok(DepositSettleStep::Failed(failure)) => {
                tracing::warn!(
                    reason = failure.reason(),
                    "booking deposit move is still owed and is asked again later"
                );
                settle.requeue(
                    &requeue_reason(failure.reason()),
                    now_utc.saturating_add(DEPOSIT_SETTLE_OWED_RECHECK_SECONDS),
                )?;
                drain.still_owed += 1;
            }
            // A store failure while the move was decided or recorded. The
            // deposit may still owe the move, and a move the provider did is
            // answered again under the same idempotency key.
            Err(error) => {
                tracing::warn!(%error, "booking deposit settle row met a store failure");
                let wait = if prompt {
                    drain.retrying += 1;
                    DEPOSIT_SETTLE_RETRY_SECONDS
                } else {
                    drain.still_owed += 1;
                    DEPOSIT_SETTLE_OWED_RECHECK_SECONDS
                };
                settle.requeue(
                    &attempt_failure_reason(&error),
                    now_utc.saturating_add(wait),
                )?;
            }
        }
    }
    Ok(drain)
}

/// The reason a settle row is queued again under: the provider's own,
/// bounded, and never empty, since the queue refuses an empty reason and the
/// row would then stay leased.
fn requeue_reason(reason: &str) -> String {
    let reason = bounded(reason, MAX_FAILURE_BYTES);
    if reason.is_empty() {
        "the provider gave no reason".to_owned()
    } else {
        reason
    }
}

fn settle_payload_key(record: &AttemptRecord) -> Result<[u8; 32], BookingError> {
    let payload: DepositSettlePayload = serde_json::from_slice(&record.payload)
        .map_err(|_| refused("booking deposit settle payload did not decode"))?;
    oneiron_hex::decode::<32>(&payload.deposit_key)
        .ok_or_else(|| refused("booking deposit settle payload names no deposit"))
}

/// One claimed settle row and the three ways its claim ends.
struct SettleRow<'a> {
    queue: &'a AttemptQueue<'a>,
    record: &'a AttemptRecord,
    lease_owner: &'a str,
    now_utc: u64,
}

impl SettleRow<'_> {
    fn complete(&self) -> Result<(), BookingError> {
        self.queue
            .complete(CompleteAttempt {
                id: self.record.id,
                lease_owner: self.lease_owner.to_owned(),
                attempt_count: self.record.attempt_count,
                now: self.now_utc,
            })
            .map(|_| ())
            .map_err(|error| engine_failure("deposit settle complete", error))
    }

    fn requeue(&self, reason: &str, due_at: u64) -> Result<(), BookingError> {
        self.queue
            .requeue_coalescing(RequeueAttempt {
                id: self.record.id,
                lease_owner: self.lease_owner.to_owned(),
                attempt_count: self.record.attempt_count,
                reason: reason.to_owned(),
                due_at,
            })
            .map(|_| ())
            .map_err(|error| engine_failure("deposit settle requeue", error))
    }

    fn fail(&self, failure: &BookingError) -> Result<(), BookingError> {
        self.queue
            .fail(FailAttempt {
                id: self.record.id,
                lease_owner: self.lease_owner.to_owned(),
                attempt_count: self.record.attempt_count,
                reason: attempt_failure_reason(failure),
                now: self.now_utc,
            })
            .map(|_| ())
            .map_err(|error| engine_failure("deposit settle fail", error))
    }
}
