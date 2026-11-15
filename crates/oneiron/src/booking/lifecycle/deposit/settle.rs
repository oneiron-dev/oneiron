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

/// How many claims one settle row gets before it fails for good. A retry is
/// safe: every provider call carries an idempotency key per deposit, move
/// and amount.
const DEPOSIT_SETTLE_ATTEMPTS: u32 = 8;

/// How long a settle row whose provider call failed waits before its next
/// try.
const DEPOSIT_SETTLE_RETRY_SECONDS: u64 = 300;

/// How long a settle row whose move the provider holds pending waits before
/// it asks again.
const DEPOSIT_SETTLE_PENDING_RECHECK_SECONDS: u64 = 3_600;

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
    /// The provider refused the move itself; another try answers the same.
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
    /// captured for a capture (also when an earlier capture already stood);
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
    /// Nothing is owed: no such deposit, or it stands settled.
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
    },
}

/// Decides one deposit's next move in a writer. An open deposit whose
/// checkout window has ended turns void-due here, so no confirm can take it
/// after the decision.
fn plan_settle(vault: &Vault, key: &[u8; 32], now_utc: u64) -> Result<SettlePlan, BookingError> {
    booking_writer(vault, |wtxn| {
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(SettlePlan::Nothing);
        };
        let movement = match row.state {
            DepositState::CaptureDue { amount_minor } => {
                DepositSettleMove::Capture { amount_minor }
            }
            DepositState::VoidDue => DepositSettleMove::Void,
            DepositState::RefundDue { amount_minor } => DepositSettleMove::Refund { amount_minor },
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
fn record_settled(
    vault: &Vault,
    key: &[u8; 32],
    movement: DepositSettleMove,
    moved: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| {
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(());
        };
        let next = match (row.state, movement) {
            (
                DepositState::CaptureDue { amount_minor: owed },
                DepositSettleMove::Capture { .. },
            ) => {
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
            ) if moved > 0 => DepositState::RefundDue {
                amount_minor: moved,
            },
            (DepositState::VoidDue, DepositSettleMove::Void) => DepositState::Voided,
            (DepositState::RefundDue { .. }, DepositSettleMove::Refund { .. }) => {
                DepositState::Refunded {
                    amount_minor: moved,
                }
            }
            // The deposit moved on while the call ran (a provider
            // cancellation); its own row settles what is left.
            _ => return Ok(()),
        };
        let refund_owed = matches!(next, DepositState::RefundDue { .. });
        row.state = next;
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, key, &row)?;
        if refund_owed {
            let cause = if movement == DepositSettleMove::Void {
                "void-found-captured"
            } else {
                "capture-overtaken"
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
    let (payment_id, movement) = match plan_settle(vault, key, now_utc)? {
        SettlePlan::Nothing => return Ok(DepositSettleStep::Nothing),
        SettlePlan::Wait { due_at } => return Ok(DepositSettleStep::Wait { due_at }),
        SettlePlan::Move {
            payment_id,
            movement,
        } => (payment_id, movement),
    };
    // One key per deposit, move and amount: a retry of the same move is
    // deduped by the provider, and a smaller capture after a cancel is a
    // new request rather than a mismatched replay.
    let idempotency_key = format!(
        "oneiron-deposit-{}-{}-{}",
        movement.tag(),
        movement.amount_minor(),
        &hex_lower(key)[..32]
    );
    match port.settle(&DepositSettleRequest {
        payment_id: &payment_id,
        movement,
        idempotency_key: &idempotency_key,
    }) {
        Ok(moved) => {
            record_settled(vault, key, movement, moved, now_utc)?;
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
    /// Rows whose provider call failed and runs again later.
    pub retrying: u32,
    /// Rows whose move the provider holds pending, asked again later.
    pub pending: u32,
    /// Rows that failed for good.
    pub failed: u32,
}

/// Claims and runs up to `limit` queued [`BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND`]
/// rows: each deposit's due move through `port`. A deposit still in its
/// checkout window is queued again for the window's end, where an
/// unconfirmed one is voided. A provider failure runs again five minutes
/// later, and fails for good on a permanent refusal or the eighth claim. A
/// move the provider holds pending is asked again an hour later, however
/// many claims it took.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a queue failure. A row whose move fails
/// settles its row and does not fail the pass.
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
        let step = settle_payload_key(&record)
            .and_then(|key| settle_deposit_key(vault, &key, port, now_utc));
        let settle = SettleRow {
            queue: &queue,
            record: &record,
            lease_owner,
            now_utc,
        };
        match step {
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
                    &bounded(&reason, MAX_FAILURE_BYTES),
                    now_utc.saturating_add(DEPOSIT_SETTLE_PENDING_RECHECK_SECONDS),
                )?;
                drain.pending += 1;
            }
            Ok(DepositSettleStep::Failed(DepositProviderFailure::Transient(reason)))
                if record.attempt_count < DEPOSIT_SETTLE_ATTEMPTS =>
            {
                tracing::debug!(%reason, "booking deposit move runs again later");
                settle.requeue(
                    &bounded(&reason, MAX_FAILURE_BYTES),
                    now_utc.saturating_add(DEPOSIT_SETTLE_RETRY_SECONDS),
                )?;
                drain.retrying += 1;
            }
            Ok(DepositSettleStep::Failed(failure)) => {
                tracing::warn!(
                    reason = failure.reason(),
                    "booking deposit move failed for good"
                );
                settle.fail(&refused(bounded(failure.reason(), MAX_FAILURE_BYTES)))?;
                drain.failed += 1;
            }
            Err(error) => {
                tracing::warn!(%error, "booking deposit settle row failed for good");
                settle.fail(&error)?;
                drain.failed += 1;
            }
        }
    }
    Ok(drain)
}

fn settle_payload_key(record: &AttemptRecord) -> Result<[u8; 32], BookingError> {
    let payload: DepositSettlePayload = serde_json::from_slice(&record.payload)
        .map_err(|_| refused("booking deposit settle payload did not decode"))?;
    super::super::digest_from_hex(&payload.deposit_key)
        .ok_or_else(|| refused("booking deposit settle payload names no deposit"))
}

/// One claimed settle row and the three ways it ends.
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
