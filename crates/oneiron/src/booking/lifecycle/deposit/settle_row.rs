//! One deposit settle row on the attempt queue: its payload (the deposit,
//! and what the deposit stood at when it was queued), its enqueue, and the
//! three ways a claim of it ends.

use serde::{Deserialize, Serialize};

use super::super::door::attempt_failure_reason;
use super::super::storage::{engine_failure, refused};
use super::super::token::hex_lower;
use super::refund_ended_unpaid::is_zero;
use super::settle::BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND;
use super::{DEPOSIT, MAX_FAILURE_BYTES, bounded};
use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, CompleteAttempt, EnqueueAttempt, FailAttempt, RequeueAttempt,
};
use crate::booking::BookingError;

/// The payload of one [`BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND`] row: the
/// deposit whose next move is owed. The move itself is read from committed
/// state when the row runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositSettlePayload {
    /// The deposit's key, lowercase hex.
    deposit_key: String,
    /// The deposit's retry count when the row was queued: the owner's ask
    /// again of a refund the provider ended unpaid queues a row of its own,
    /// so a row queued before it ends once it runs, and only one row per
    /// deposit keeps asking (review round 2 of #10149). Unset, a row queued
    /// before any retry, or before the count existed, reads as 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    refund_retry: u32,
    /// The refund owed when the row was queued stood marked refunded outside
    /// the provider ([`super::DepositRow::marks_owed_refund`]): a row queued
    /// before the mark ends once it runs, so only the mark's row finds the
    /// refund (FIX [BK-DEPOSIT-FAILED-REFUND-MARK-PAID]). Unset, and left
    /// out, on every other row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    marked_outside: bool,
}

/// What a deposit stood at when a settle row of it was queued: its retry
/// count, and whether the refund it owed stood marked refunded outside the
/// provider.
#[derive(Debug, Clone, Copy)]
pub(super) struct QueuedStamp {
    pub(super) refund_retry: u32,
    pub(super) marked_outside: bool,
}

/// Queues `key`'s next owed move as one settle row, deduplicated by the
/// deposit and `cause`, stamped with the deposit as `wtxn` reads it
/// ([`QueuedStamp`]).
pub(super) fn enqueue_settle(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    cause: &str,
    now_utc: u64,
) -> Result<(), BookingError> {
    let hex = hex_lower(key);
    let (refund_retry, marked_outside) = DEPOSIT
        .get(&vault.store, &*wtxn, key)
        .map_err(|error| engine_failure("meta read", error))?
        .map_or((0, false), |row| {
            (row.refund_retry, row.marks_owed_refund())
        });
    let payload = serde_json::to_vec(&DepositSettlePayload {
        deposit_key: hex.clone(),
        refund_retry,
        marked_outside,
    })
    .map_err(|_| refused("booking deposit settle payload did not encode"))?;
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        wtxn,
        EnqueueAttempt {
            kind: BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(format!(
                "{BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND}:{hex}:{cause}"
            )),
            run_id: None,
            now: now_utc,
        },
    )
    .map_err(|error| engine_failure("booking deposit settle enqueue", error))?;
    Ok(())
}

/// The reason a settle row is queued again under: the provider's own,
/// bounded, and never empty, since the queue refuses an empty reason and the
/// row would then stay leased.
pub(super) fn requeue_reason(reason: &str) -> String {
    let reason = bounded(reason, MAX_FAILURE_BYTES);
    if reason.is_empty() {
        "the provider gave no reason".to_owned()
    } else {
        reason
    }
}

/// The deposit a settle row names, and what it stood at when the row was
/// queued.
pub(super) fn settle_payload_key(
    record: &AttemptRecord,
) -> Result<([u8; 32], QueuedStamp), BookingError> {
    let payload: DepositSettlePayload = serde_json::from_slice(&record.payload)
        .map_err(|_| refused("booking deposit settle payload did not decode"))?;
    let stamp = QueuedStamp {
        refund_retry: payload.refund_retry,
        marked_outside: payload.marked_outside,
    };
    oneiron_hex::decode::<32>(&payload.deposit_key)
        .map(|key| (key, stamp))
        .ok_or_else(|| refused("booking deposit settle payload names no deposit"))
}

/// One claimed settle row and the three ways its claim ends.
pub(super) struct SettleRow<'a> {
    pub(super) queue: &'a AttemptQueue<'a>,
    pub(super) record: &'a AttemptRecord,
    pub(super) lease_owner: &'a str,
    pub(super) now_utc: u64,
}

impl SettleRow<'_> {
    pub(super) fn complete(&self) -> Result<(), BookingError> {
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

    pub(super) fn requeue(&self, reason: &str, due_at: u64) -> Result<(), BookingError> {
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

    pub(super) fn fail(&self, failure: &BookingError) -> Result<(), BookingError> {
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
