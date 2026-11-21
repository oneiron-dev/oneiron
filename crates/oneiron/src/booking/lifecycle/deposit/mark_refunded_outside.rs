//! A refund owed to the visitor that the owner marks refunded outside the
//! provider (FIX [BK-DEPOSIT-FAILED-REFUND-MARK-PAID];
//! BK-DEPOSIT-FAILED-REFUND-MARK-PAID = B, the lead, Engine 21 Nov 10:55).
//!
//! The owner may pay the visitor back outside Stripe (a bank transfer, say),
//! whether Stripe ended the refund unpaid or never failed it. The owner's
//! `vault.booking.deposit.mark_refunded_outside` records the owner's word,
//! dated, for exactly the refund owed now, and queues the deposit's settle
//! row. From then on that row asks the provider only to find the refund
//! (BK-DEPOSIT-MARK-PAID-STRIPE-HOLDS-REFUND = A, Engine 21 Nov 12:13): no
//! refund is made after a mark. A refund the provider paid under the
//! deposit's keys, or by hand for what is owed, settles the deposit as the
//! provider's, and the owner's card then says Stripe refunded it as well,
//! since the visitor may be paid twice; one it still holds keeps the row
//! asking, with the mark on the card; with none, the deposit settles
//! refunded outside the provider, for the amount marked. A mark covers the
//! one refund it was made for: a balance owed after it is the provider's to
//! refund, as before. A settle row that planned a refund before the mark asks
//! the deposit's [`RefundPermission`] right before the provider makes it, so
//! no refund starts after a mark (review round 2 of #10267).

use serde::{Deserialize, Serialize};

use super::super::claim::read_booking_facts_to_cancel;
use super::super::storage::{booking_writer, engine_failure, read_txn, refused};
use super::{
    DEPOSIT, DEPOSIT_BOOKING, DepositProviderFailure, DepositRow, DepositState, booking_key,
    enqueue_settle, put_deposit,
};
use crate::booking::BookingError;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::verbs::BookingDepositMarkRefundedOutsideReceipt;
use crate::{EntityId, Vault};

/// The longest idempotency key a mark takes, in bytes.
const MARK_IDEMPOTENCY_KEY_MAX_BYTES: usize = 200;

/// The most idempotency keys one mark answers: a call under a new key for
/// a refund that stands marked joins that mark.
const MARK_IDEMPOTENCY_KEYS_MAX: usize = 16;

/// The owner's word that the refund a deposit owed was paid back outside
/// the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefundMarkedOutside {
    /// When the owner marked it.
    marked_at: u64,
    /// The refund owed then, which the owner says was paid back.
    amount_minor: u64,
    /// How the marked refund settled; unset while its settle row runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settled: Option<MarkedRefundSettled>,
    /// The idempotency keys of the calls this mark answered, the first the
    /// one that recorded it: a repeat of a call under one answers this mark,
    /// whatever the deposit owes since (review rounds 1 and 2 of #10267).
    /// Empty on a mark stored before the keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    idempotency_keys: Vec<String>,
    /// The deposit's marks before this one, oldest first: a repeat of a call
    /// one answered answers it still, and what each settled outside the
    /// provider still counts (review round 2 of #10267).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    earlier: Vec<EarlierMark>,
}

/// A mark that a mark of a later refund followed, as it stood then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EarlierMark {
    marked_at: u64,
    amount_minor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settled: Option<MarkedRefundSettled>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    idempotency_keys: Vec<String>,
}

impl RefundMarkedOutside {
    /// When the mark that answered a call under `idempotency_key` was made,
    /// and what it marked: this one, or an earlier one.
    fn answered(&self, idempotency_key: &str) -> Option<(u64, u64)> {
        let answers = |keys: &[String]| keys.iter().any(|key| key == idempotency_key);
        if answers(&self.idempotency_keys) {
            return Some((self.marked_at, self.amount_minor));
        }
        self.earlier
            .iter()
            .find(|mark| answers(&mark.idempotency_keys))
            .map(|mark| (mark.marked_at, mark.amount_minor))
    }

    /// What this mark and the earlier ones settled outside the provider.
    fn settled_outside(&self) -> u64 {
        let outside = |settled: Option<MarkedRefundSettled>, amount_minor: u64| match settled {
            Some(MarkedRefundSettled::Outside) => amount_minor,
            _ => 0,
        };
        self.earlier
            .iter()
            .fold(outside(self.settled, self.amount_minor), |sum, mark| {
                sum.saturating_add(outside(mark.settled, mark.amount_minor))
            })
    }

    /// The earlier marks of the mark that follows this one: this one's,
    /// then this one.
    fn into_earlier(self) -> Vec<EarlierMark> {
        let mut earlier = self.earlier;
        earlier.push(EarlierMark {
            marked_at: self.marked_at,
            amount_minor: self.amount_minor,
            settled: self.settled,
            idempotency_keys: self.idempotency_keys,
        });
        earlier
    }
}

/// How a refund the owner marked refunded outside the provider settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MarkedRefundSettled {
    /// The provider held no refund of it that paid or might still pay.
    Outside,
    /// The provider paid a refund of it after all: one asked before the
    /// mark, or one made by hand in its dashboard.
    ByProvider,
}

impl DepositRow {
    /// What the deposit recorded refunded outside the provider: every refund
    /// a mark settled as the mark's, the latest mark's and the earlier ones'
    /// (review round 2 of #10267). A mark of the refund owed now has not
    /// settled, so it counts only refunds before that one.
    pub(super) fn refunded_outside(&self) -> u64 {
        self.refund_marked_outside
            .as_ref()
            .map_or(0, RefundMarkedOutside::settled_outside)
    }

    /// Whether the refund the deposit owes now stands marked refunded
    /// outside the provider: its settle row then only finds it.
    pub(super) fn marks_owed_refund(&self) -> bool {
        matches!(self.state, DepositState::RefundDue { .. })
            && self
                .refund_marked_outside
                .as_ref()
                .is_some_and(|mark| mark.settled.is_none())
    }
}

/// What the provider's answer `moved` to the refund `row` owes, `owed`,
/// records as refunded. A refund marked refunded outside the provider
/// settles as the provider's when the answer names one paid, and else as
/// the mark's, for what was owed; the mark keeps which. An unmarked refund
/// records the answer as it came.
pub(super) fn record_marked_refund(row: &mut DepositRow, moved: u64, owed: u64) -> u64 {
    if !row.marks_owed_refund() {
        return moved;
    }
    let Some(mark) = row.refund_marked_outside.as_mut() else {
        return moved;
    };
    let (settled, refunded) = match moved {
        0 => (MarkedRefundSettled::Outside, owed),
        paid => (MarkedRefundSettled::ByProvider, paid),
    };
    mark.settled = Some(settled);
    refunded
}

/// The deposit's word on whether the provider may make the refund a settle
/// row asks, asked right before it makes one, once it found none made
/// (review round 2 of #10267): no once the owner marked the refund owed
/// refunded outside the provider, so no refund starts after a mark, and the
/// provider then answers as for a find. A mark made after a yes meets that
/// refund under way, as one the provider holds: its answer records it as the
/// provider's.
#[derive(Clone, Copy)]
pub struct RefundPermission<'a>(&'a dyn Fn() -> Result<bool, DepositProviderFailure>);

impl<'a> RefundPermission<'a> {
    /// The permission `granted` answers.
    pub const fn new(granted: &'a dyn Fn() -> Result<bool, DepositProviderFailure>) -> Self {
        Self(granted)
    }

    /// Whether the provider may make the refund now.
    ///
    /// # Errors
    ///
    /// [`DepositProviderFailure::Transient`] when the deposit could not be
    /// read.
    pub fn granted(&self) -> Result<bool, DepositProviderFailure> {
        (self.0)()
    }
}

impl std::fmt::Debug for RefundPermission<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefundPermission")
    }
}

/// The [`RefundPermission`] of the deposit `key`, read when asked: granted
/// unless the refund it owes stands marked refunded outside the provider.
pub(super) fn refund_permission_granted(
    vault: &Vault,
    key: &[u8; 32],
) -> Result<bool, DepositProviderFailure> {
    let read = || -> Result<bool, BookingError> {
        let rtxn = read_txn(vault)?;
        let row = DEPOSIT
            .get(&vault.store, &rtxn, key)
            .map_err(|error| engine_failure("meta read", error))?;
        Ok(!row.is_some_and(|row| row.marks_owed_refund()))
    };
    read().map_err(|error| {
        DepositProviderFailure::Transient(format!(
            "the deposit was not read before its refund: {error}"
        ))
    })
}

/// A deposit's mark as its owner's card reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::booking::lifecycle) struct MarkedRefund {
    pub(in crate::booking::lifecycle) marked_at: u64,
    pub(in crate::booking::lifecycle) amount_minor: u64,
    /// The terms' currency, ISO 4217 lowercase.
    pub(in crate::booking::lifecycle) currency: String,
    /// The provider paid a refund of it after the mark after all.
    pub(in crate::booking::lifecycle) provider_refunded: bool,
}

/// The latest mark on the deposit of the booking `event_ref`, read in
/// `rtxn`; `None` for a booking this node holds no deposit for, or one
/// whose refunds no owner marked.
///
/// # Errors
///
/// Storage errors.
pub(in crate::booking::lifecycle) fn refund_marked_outside_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> crate::error::Result<Option<MarkedRefund>> {
    let Some(link) = DEPOSIT_BOOKING.get(&vault.store, rtxn, &booking_key(event_ref))? else {
        return Ok(None);
    };
    Ok(DEPOSIT
        .get(&vault.store, rtxn, &link.deposit_key)?
        .and_then(|row| {
            let mark = row.refund_marked_outside?;
            Some(MarkedRefund {
                marked_at: mark.marked_at,
                amount_minor: mark.amount_minor,
                currency: row.terms.currency,
                provider_refunded: mark.settled == Some(MarkedRefundSettled::ByProvider),
            })
        }))
}

/// `vault.booking.deposit.mark_refunded_outside`
/// (BK-DEPOSIT-FAILED-REFUND-MARK-PAID = B): the owner says the refund the
/// booking's deposit owes the visitor now was paid back outside the
/// provider. The proof and the hosts are Return deposit's
/// ([`super::refund_booking_deposit_as_owner`]): the vault owner's own
/// proof, revalidated in this writer, of a host selected at the booking's
/// confirmation; an agent may ask the owner, and never marks. It takes only
/// `amount_minor` equal to the refund owed now, and the caller's
/// `idempotency_key` for the mark. In one booking writer it
/// records the mark, dated, drops the note that the provider ended the
/// refund unpaid, so the owner's stuck-refund line and its INBOX row go, and
/// queues the deposit's settle row, which from then on only finds the
/// refund. A repeat of a call under an idempotency key a mark answered
/// records nothing and answers that mark, also once it settled and a later
/// refund is owed, or marked: a retried call never marks a refund it was not
/// made for (review rounds 1 and 2 of #10267). A call under a new key for a
/// refund that stands marked records no mark either: the mark keeps the key
/// and answers it. A later mark keeps the earlier ones. The receipt shows
/// the amount marked.
///
/// # Errors
///
/// [`BookingError::Boundary`] for a proof that no longer holds or a caller
/// who was not a selected host; [`BookingError::InvalidConstraint`] for an
/// EVENT that is no booking, for an amount other than the refund owed, for
/// an idempotency key that is empty or longer than
/// [`MARK_IDEMPOTENCY_KEY_MAX_BYTES`], and for a new key once the mark of the
/// refund owed answers [`MARK_IDEMPOTENCY_KEYS_MAX`];
/// [`BookingError::InvalidConfig`] for a deposit that owes the visitor no
/// refund (held, released, or refunded by the provider), or a booking this
/// node holds no deposit for; [`BookingError::SlotOracle`] on a store
/// failure.
pub(crate) fn mark_booking_deposit_refunded_outside(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    event_ref: &EntityId,
    amount_minor: u64,
    idempotency_key: &str,
) -> Result<BookingDepositMarkRefundedOutsideReceipt, BookingError> {
    if idempotency_key.is_empty() || idempotency_key.len() > MARK_IDEMPOTENCY_KEY_MAX_BYTES {
        return Err(refused(format!(
            "idempotency_key names the mark: 1 to {MARK_IDEMPOTENCY_KEY_MAX_BYTES} bytes"
        )));
    }
    booking_writer(vault, |wtxn| {
        let actor = owner
            .owner_authored_write_in_txn(vault, &*wtxn)
            .map_err(|error| BookingError::Boundary(Box::new(MemoryError::from(error))))?
            .actor();
        let booking = read_booking_facts_to_cancel(vault, &*wtxn, event_ref)?;
        if !booking
            .context
            .as_ref()
            .is_some_and(|context| context.owner_refs.contains(&actor.to_hex()))
        {
            return Err(BookingError::Boundary(Box::new(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only a host selected when the booking was confirmed marks its deposit's refund",
                &["Call it as one of the booking's hosts."],
            ))));
        }
        let no_deposit =
            || BookingError::InvalidConfig("this node holds no deposit for the booking".to_owned());
        let link = DEPOSIT_BOOKING
            .get(&vault.store, &*wtxn, &booking_key(event_ref))
            .map_err(|error| engine_failure("meta read", error))?
            .ok_or_else(no_deposit)?;
        let mut row = DEPOSIT
            .get(&vault.store, &*wtxn, &link.deposit_key)
            .map_err(|error| engine_failure("meta read", error))?
            .ok_or_else(no_deposit)?;
        let repeated = row
            .refund_marked_outside
            .as_ref()
            .and_then(|mark| mark.answered(idempotency_key));
        if let Some(answered) = repeated {
            return Ok(receipt(event_ref, &row, answered, false));
        }
        let DepositState::RefundDue { amount_minor: owed } = row.state else {
            return Err(BookingError::InvalidConfig(
                "the booking's deposit owes the visitor no refund to mark".to_owned(),
            ));
        };
        if amount_minor != owed {
            return Err(refused(format!(
                "the refund owed now is {owed} in the currency's smallest unit: mark that amount"
            )));
        }
        if let Some(mark) = row
            .refund_marked_outside
            .as_mut()
            .filter(|mark| mark.settled.is_none())
        {
            if mark.idempotency_keys.len() >= MARK_IDEMPOTENCY_KEYS_MAX {
                return Err(refused(format!(
                    "the refund owed stands marked under {MARK_IDEMPOTENCY_KEYS_MAX} idempotency \
                     keys: repeat one of them"
                )));
            }
            mark.idempotency_keys.push(idempotency_key.to_owned());
            let answered = (mark.marked_at, mark.amount_minor);
            put_deposit(vault, wtxn, &link.deposit_key, &row)?;
            return Ok(receipt(event_ref, &row, answered, false));
        }
        let now_utc = vault.now_recorded_at();
        let earlier = row
            .refund_marked_outside
            .take()
            .map_or_else(Vec::new, RefundMarkedOutside::into_earlier);
        let mark = RefundMarkedOutside {
            marked_at: now_utc,
            amount_minor,
            settled: None,
            idempotency_keys: vec![idempotency_key.to_owned()],
            earlier,
        };
        let marked = receipt(event_ref, &row, (now_utc, amount_minor), true);
        row.refund_marked_outside = Some(mark);
        row.refund_ended_unpaid = None;
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, &link.deposit_key, &row)?;
        // One row per marked refund: a balance marked after an earlier one
        // follows more refunded.
        let cause = format!("owner-marked-outside-{}", row.refunded_minor);
        enqueue_settle(vault, wtxn, &link.deposit_key, &cause, now_utc)?;
        Ok(marked)
    })
}

/// The receipt of the mark made at `marked.0` for `marked.1`: `recorded`
/// when this call recorded it.
fn receipt(
    event_ref: &EntityId,
    row: &DepositRow,
    (marked_at, amount_minor): (u64, u64),
    recorded: bool,
) -> BookingDepositMarkRefundedOutsideReceipt {
    BookingDepositMarkRefundedOutsideReceipt {
        event_ref: event_ref.to_hex(),
        amount_minor,
        currency: row.terms.currency.clone(),
        marked_at,
        recorded,
    }
}
