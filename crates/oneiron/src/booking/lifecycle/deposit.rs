//! BK-DEPOSITS PR 2: one deposit's payment, from checkout to settlement.
//!
//! The Engine ruled the money path on Sun 15 Nov 01:10: the visitor's card is
//! authorized when the hold is extended to the checkout window, captured at
//! confirm, and voided when the hold dies unconfirmed; a refused card keeps
//! the hold live until its own expiry, so the visitor can retry. The money is
//! the visitor's, paid to the owner's own provider account; Oneiron holds no
//! funds and moves none itself. This module keeps the record of what the
//! provider was asked and what it answered, and decides the next move.
//!
//! # Shape
//!
//! - [`begin_deposit_checkout`]: the server created the provider's payment
//!   for an event type's published terms; this records the deposit row and
//!   mints a checkout lease bound to the session AND that payment. The hold
//!   door then extends the hold to the lease, as it always has.
//! - [`record_deposit_provider_event`]: the provider's signed word that the
//!   card was authorized, refused or the payment cancelled. Each provider
//!   event applies once.
//! - The confirm writer refuses a deposit event type's confirm unless the
//!   hold's lease names an authorized deposit of this session, page, event
//!   type and terms; the booked commit marks the capture due in the same
//!   transaction. A visitor's cancel decides the refund by the terms the
//!   visitor paid under, in the cancel's own transaction.
//! - [`run_booking_deposit_settlement`] drains [`BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND`]
//!   rows and asks a [`DepositSettlementPort`] for each due move: capture,
//!   void, refund. [`settle_booking_deposit`] runs one booking's move at once
//!   (the server's capture right after confirm); the queued row stays the
//!   backstop. No writer is held across a provider call.
//!
//! Rows live under `booking.token.v1:` beside the token, lease and emergency
//! pick rows, each under its own digest domain (see [`super::TOKEN`]).

use serde::{Deserialize, Serialize};

use super::storage::{booking_writer, engine_failure, read_txn, refused};
use super::token::{
    OpaqueCheckoutLeaseToken, SessionKey, digest_with, lease_digest, mint_raw_token, session_digest,
};
use super::types::{MAX_CHECKOUT_HOLD_TTL_SECS, SoftHoldRow};
use super::{CHECKOUT_LEASE, CheckoutLeaseRow, digest_serde, entity_ref_serde};
use crate::booking::{BookingError, DepositTerms, EventTypeKey};
use crate::side_table::{self, SideTable, VersionedNamed};
use crate::{EntityId, Vault};

mod held;
mod home_fence;
mod refund;
mod refund_ended_unpaid;
mod settle;

pub(crate) use self::held::note_unattributed_cancel_in_txn;
pub(super) use self::held::{
    EmergencyReturn, HeldDeposit, HeldDepositKind, emergency_return_in_txn, held_deposit_in_txn,
    refund_ended_unpaid_at_in_txn, unattributed_cancel_sequence_in_txn,
};
pub use self::home_fence::check_deposit_checkout_admitted;
use self::home_fence::{
    CHECKOUT_MOVING, SettleStanding, admits_deposits_here, awaits_carried_deposits, put_deposit,
    settle_standing_in_txn,
};
pub(super) use self::refund::{
    cap_refund_on_visitor_reschedule_in_writer, refund_on_host_cancel_in_writer,
    refund_on_visitor_cancel_in_writer,
};
pub(crate) use self::refund::{refund_booking_deposit_as_owner, refund_deposit_on_host_cancel};
use self::refund_ended_unpaid::RefundEndedUnpaid;
use self::settle::enqueue_settle;
#[cfg(feature = "sync")]
pub(super) use self::settle::queue_carried_settle_in_txn;
pub use self::settle::{
    BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND, BookingDepositSettlementDrain, DepositProviderFailure,
    DepositSettleMove, DepositSettleRequest, DepositSettleStep, DepositSettlementPort,
    run_booking_deposit_settlement, settle_booking_deposit,
};

/// The checkout window a deposit's lease opens: the hold lives this long
/// while the visitor pays ("~15min", ARCH-0062:225). A checkout started
/// again for the same payment never reaches past
/// [`MAX_CHECKOUT_HOLD_TTL_SECS`] from its first start.
pub const DEPOSIT_CHECKOUT_WINDOW_SECS: u64 = 15 * 60;

/// The longest provider payment id or provider event id accepted.
const MAX_PROVIDER_ID_BYTES: usize = 255;

/// The longest provider refusal reason kept on a deposit row.
const MAX_FAILURE_BYTES: usize = 512;

const DEPOSIT_KEY_DOMAIN: &[u8] = b"oneiron.booking.deposit.v1\0";
const DEPOSIT_EVENT_DOMAIN: &[u8] = b"oneiron.booking.deposit_provider_event.v1\0";
const DEPOSIT_BOOKING_DOMAIN: &[u8] = b"oneiron.booking.deposit_booking.v1\0";

/// Where one deposit stands. Changes only move forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositState {
    /// Checkout started; the provider has not authorized the card.
    AwaitingAuthorization,
    /// The provider refused the card. The hold stays live until its own
    /// expiry, and the visitor may pay again on the same payment.
    AuthorizationFailed,
    /// The card is authorized for exactly the terms' amount.
    Authorized,
    /// The booking is confirmed; this capture is owed.
    CaptureDue { amount_minor: u64 },
    /// The provider captured this amount.
    Captured { amount_minor: u64 },
    /// The hold died unconfirmed, or a cancel released the whole deposit
    /// before its capture; the authorization is to be voided.
    VoidDue,
    /// The payment is cancelled; nothing was captured.
    Voided,
    /// This refund is owed: a cancel's, a capture's excess, or a return's
    /// (all of it, or the balance after an earlier refund).
    RefundDue { amount_minor: u64 },
    /// The provider refunded this amount in all.
    Refunded { amount_minor: u64 },
}

impl DepositState {
    /// Still in checkout: no booking yet, and nothing settled.
    const fn is_open(self) -> bool {
        matches!(
            self,
            Self::AwaitingAuthorization | Self::AuthorizationFailed | Self::Authorized
        )
    }
}

/// One deposit, keyed by its provider payment's digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DepositRow {
    #[serde(with = "digest_serde")]
    session_hash: [u8; 32],
    #[serde(with = "entity_ref_serde")]
    page_ref: EntityId,
    event_type: EventTypeKey,
    /// The terms the visitor pays under, frozen at checkout.
    terms: DepositTerms,
    /// The provider's payment id.
    payment_id: String,
    opened_at: u64,
    /// The latest expiry of any lease minted for this payment.
    lease_expires_at: u64,
    state: DepositState,
    /// The booking's EVENT, lowercase hex, once confirmed.
    event_ref: Option<String>,
    /// The provider's last refusal of the card.
    failure: Option<String>,
    /// The most a later visitor cancel refunds: what a cancel would have
    /// refunded when the visitor last moved the booking, against the slot
    /// left. Unset until a visitor reschedule.
    #[serde(default)]
    refund_cap_minor: Option<u64>,
    /// What the provider captured: recorded when a capture, or a void that
    /// found one, answers, and when a cancel owes part of a capture back.
    /// Unset on a row refunded before it was recorded; the owner's return
    /// then owes no balance.
    #[serde(default)]
    captured_minor: Option<u64>,
    /// What the provider refunded before the refund owed now: 0 for a first
    /// refund. A later refund names it in its idempotency key, so a balance
    /// equal to the earlier refund is a new request, not its replay.
    #[serde(default)]
    refunded_minor: u64,
    /// The owner asked the whole capture back while a smaller refund was
    /// owed: once that refund settles, the balance is owed as well.
    #[serde(default)]
    balance_owed_after_refund: bool,
    /// The owner's cancelled calendar write whose replay read a stored copy
    /// with no write marker as the owner's own while this deposit was held
    /// (BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C): a host's cancel at its
    /// SEQUENCE would read the same, so the owner's line names it as a
    /// cancel Oneiron cannot attribute. Unset on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unattributed_cancel: Option<UnattributedCancel>,
    /// The SEQUENCE of the owner's BK-09 emergency cancel that gave this
    /// deposit back whole (released a capture still due, or owed a captured
    /// one back), in that cancel's own commit: the booking the visitor picks
    /// again from its proposals carries no deposit, and the owner's card
    /// says where this deposit's return stands (RULING
    /// DEPOSIT-PICK-AFTER-EMERGENCY-CANCEL = A). Unset on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    emergency_return_sequence: Option<u32>,
    /// How many times the owner asked again for the refund owed now after
    /// the provider ended it unpaid (FIX [BK-DEPOSIT-FAILED-REFUND-SURFACE]):
    /// from the first on, the refund's idempotency key names it, so the
    /// provider makes a new refund. 0, and left out, on every other row.
    #[serde(default, skip_serializing_if = "refund_ended_unpaid::is_zero")]
    refund_retry: u32,
    /// The refund owed now, asked under `refund_retry`, that the provider
    /// ended with nothing paid back: the owner's line says so, and Return
    /// deposit asks again. Unset on every other row, and once a refund of
    /// the deposit settles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refund_ended_unpaid: Option<RefundEndedUnpaid>,
    updated_at: u64,
}

/// The first replay that read an unmarked stored copy as the owner's
/// cancelled write while a deposit was held
/// ([`note_unattributed_cancel_in_txn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnattributedCancel {
    /// The write's staged SEQUENCE.
    sequence: u32,
    /// When the replay's proof was written. The owner's held-deposit row
    /// dates the unattributed cancel by it, so a row marked done before
    /// then comes back (review round 1 of #10028).
    noted_at: u64,
}

/// A booking's deposit. Key: hash32 (the booking digest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DepositBookingRow {
    #[serde(with = "digest_serde")]
    deposit_key: [u8; 32],
}

/// A provider event already applied. Key: hash32 (the provider event digest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DepositProviderEventRow {
    #[serde(with = "digest_serde")]
    deposit_key: [u8; 32],
    recorded_at: u64,
}

/// Same `booking.token.v1:` declaration as [`super::TOKEN`]; see its doc
/// comment. Key: hash32 (the payment digest).
pub(super) const DEPOSIT: SideTable<
    [u8; 32],
    DepositRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_TOKEN);

/// Same declaration. Key: hash32 (the booking digest).
pub(super) const DEPOSIT_BOOKING: SideTable<
    [u8; 32],
    DepositBookingRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_TOKEN);

/// Same declaration. Key: hash32 (the provider event digest).
pub(super) const DEPOSIT_PROVIDER_EVENT: SideTable<
    [u8; 32],
    DepositProviderEventRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_TOKEN);

fn deposit_key(payment_id: &str) -> [u8; 32] {
    digest_with(DEPOSIT_KEY_DOMAIN, payment_id.as_bytes())
}

fn booking_key(event_ref: &EntityId) -> [u8; 32] {
    digest_with(DEPOSIT_BOOKING_DOMAIN, event_ref.as_bytes())
}

fn provider_event_key(event_id: &str) -> [u8; 32] {
    digest_with(DEPOSIT_EVENT_DOMAIN, event_id.as_bytes())
}

fn provider_id_defect(id: &str) -> bool {
    id.is_empty() || id.len() > MAX_PROVIDER_ID_BYTES || !id.bytes().all(|b| b.is_ascii_graphic())
}

fn bounded(text: &str, limit: usize) -> String {
    let mut cut = text.len().min(limit);
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

// -------------------------------------------------------------------------
// Checkout
// -------------------------------------------------------------------------

/// The payment a server created for one session's deposit.
#[derive(Debug, Clone, PartialEq)]
pub struct DepositCheckoutStart {
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    pub session_key: SessionKey,
    /// The terms the payment was created for: the published card's, which
    /// must still be the event type's live configuration.
    pub terms: DepositTerms,
    /// The provider's payment id.
    pub payment_id: String,
}

/// What [`begin_deposit_checkout`] returns: the lease the visitor's hold
/// presents, and when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositCheckoutLease {
    pub lease: OpaqueCheckoutLeaseToken,
    pub expires_at: u64,
}

/// Records a deposit checkout and mints its lease, bound to the session and
/// to the provider's payment.
///
/// The terms must equal the event type's live configured deposit, read in
/// this writer. A second start for the same payment (the server's retry,
/// which the provider answers with the same payment) mints a fresh lease for
/// the same deposit, never reaching past [`MAX_CHECKOUT_HOLD_TTL_SECS`] from
/// the first start; a payment of another session, page, event type or
/// terms, or one already settled, is refused. The first start queues the
/// deposit's settle row, which voids the payment once its checkout window
/// ends unconfirmed.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a refused start;
/// [`BookingError::InvalidConfig`] when the event type has no live
/// configuration; [`BookingError::SlotOracle`] on a store failure.
pub fn begin_deposit_checkout(
    vault: &Vault,
    start: &DepositCheckoutStart,
    now_utc: u64,
) -> Result<DepositCheckoutLease, BookingError> {
    if provider_id_defect(&start.payment_id) {
        return Err(refused("deposit payment id is not a provider id"));
    }
    start.terms.validate()?;
    let key = deposit_key(&start.payment_id);
    let session_hash = session_digest(&start.session_key);
    booking_writer(vault, |wtxn| {
        if !admits_deposits_here(vault, &*wtxn)? {
            return Err(refused(CHECKOUT_MOVING));
        }
        let config = crate::booking::config::load_event_type_config_in_txn(
            vault,
            &*wtxn,
            start.page_ref,
            &start.event_type,
        )?;
        if config.deposit.as_ref() != Some(&start.terms) {
            return Err(refused(
                "checkout terms are not this event type's configured deposit",
            ));
        }
        let existing = DEPOSIT
            .get(&vault.store, &*wtxn, &key)
            .map_err(|error| engine_failure("meta read", error))?;
        let mut row = match existing {
            Some(row) => {
                if row.session_hash != session_hash
                    || row.page_ref != start.page_ref
                    || row.event_type != start.event_type
                    || row.terms != start.terms
                {
                    return Err(refused("deposit payment belongs to another checkout"));
                }
                if !row.state.is_open() {
                    return Err(refused("deposit payment is already settled"));
                }
                row
            }
            None => DepositRow {
                session_hash,
                page_ref: start.page_ref,
                event_type: start.event_type.clone(),
                terms: start.terms.clone(),
                payment_id: start.payment_id.clone(),
                opened_at: now_utc,
                lease_expires_at: now_utc,
                state: DepositState::AwaitingAuthorization,
                event_ref: None,
                failure: None,
                refund_cap_minor: None,
                captured_minor: None,
                refunded_minor: 0,
                balance_owed_after_refund: false,
                unattributed_cancel: None,
                emergency_return_sequence: None,
                refund_retry: 0,
                refund_ended_unpaid: None,
                updated_at: now_utc,
            },
        };
        let expires_at = now_utc
            .saturating_add(DEPOSIT_CHECKOUT_WINDOW_SECS)
            .min(row.opened_at.saturating_add(MAX_CHECKOUT_HOLD_TTL_SECS));
        if expires_at <= now_utc {
            return Err(refused("deposit checkout window has ended"));
        }
        let lease = OpaqueCheckoutLeaseToken(mint_raw_token());
        CHECKOUT_LEASE
            .put(
                &vault.store,
                wtxn,
                &lease_digest(&lease),
                &CheckoutLeaseRow {
                    session_hash,
                    expires_at,
                    deposit_key: Some(key),
                },
            )
            .map_err(|error| engine_failure("meta write", error))?;
        row.lease_expires_at = row.lease_expires_at.max(expires_at);
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, &key, &row)?;
        enqueue_settle(vault, wtxn, &key, "expiry", now_utc)?;
        Ok(DepositCheckoutLease { lease, expires_at })
    })
}

// -------------------------------------------------------------------------
// Provider events
// -------------------------------------------------------------------------

/// One verified provider event about a deposit's payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositProviderEvent {
    /// The provider's event id: each one applies once.
    pub event_id: String,
    /// The provider's payment id.
    pub payment_id: String,
    pub kind: DepositProviderEventKind,
}

/// What the provider said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositProviderEventKind {
    /// The card is authorized for this amount, capturable.
    Authorized { amount_minor: u64, currency: String },
    /// The provider refused the card.
    AuthorizationFailed { reason: String },
    /// The payment is cancelled.
    Canceled,
}

/// What [`record_deposit_provider_event`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositProviderEventOutcome {
    /// The deposit moved to this state.
    Applied(DepositState),
    /// The deposit already stood past this event; nothing changed.
    Unchanged(DepositState),
    /// This provider event was already applied.
    Replayed,
    /// No deposit has this payment: another use of the owner's account.
    UnknownPayment,
    /// The authorized amount or currency is not the deposit's terms; the
    /// deposit stays unauthorized, and its window's end voids it.
    TermsMismatch,
    /// Not applied now, and nothing changed: it froze its booking rows for a
    /// home move its target has not acknowledged, or it awaits the move that
    /// carries its deposits here. The provider must deliver it again.
    Deferred,
    /// Not this node's to apply: it froze its booking rows for a move its
    /// target acknowledged. The new home asks the provider before a confirm.
    MovedAway,
}

/// Applies one verified provider event to its deposit, once.
///
/// An authorization counts only for exactly the deposit's amount and
/// currency. A refusal keeps the deposit, and the hold that waits on it,
/// open for a retry on the same payment. A cancellation closes any deposit
/// not yet captured.
///
/// During a home move it writes nothing (FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]):
/// [`DepositProviderEventOutcome::Deferred`] on the old home until its move is
/// acknowledged, and on the new home for a payment it does not know before the
/// move lands, never acknowledged as no deposit's; then
/// [`DepositProviderEventOutcome::MovedAway`] on the old home.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a malformed event;
/// [`BookingError::SlotOracle`] on a store failure.
pub fn record_deposit_provider_event(
    vault: &Vault,
    event: &DepositProviderEvent,
    now_utc: u64,
) -> Result<DepositProviderEventOutcome, BookingError> {
    if provider_id_defect(&event.event_id) || provider_id_defect(&event.payment_id) {
        return Err(refused("deposit provider event names no provider id"));
    }
    let key = deposit_key(&event.payment_id);
    let event_key = provider_event_key(&event.event_id);
    booking_writer(vault, |wtxn| {
        match settle_standing_in_txn(vault, &*wtxn)? {
            SettleStanding::Settles => {}
            SettleStanding::MoveUnacknowledged => return Ok(DepositProviderEventOutcome::Deferred),
            SettleStanding::MovedAway => return Ok(DepositProviderEventOutcome::MovedAway),
        }
        if DEPOSIT_PROVIDER_EVENT
            .get(&vault.store, &*wtxn, &event_key)
            .map_err(|error| engine_failure("meta read", error))?
            .is_some()
        {
            return Ok(DepositProviderEventOutcome::Replayed);
        }
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, &key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(if awaits_carried_deposits(vault, &*wtxn)? {
                DepositProviderEventOutcome::Deferred
            } else {
                DepositProviderEventOutcome::UnknownPayment
            });
        };
        DEPOSIT_PROVIDER_EVENT
            .put(
                &vault.store,
                wtxn,
                &event_key,
                &DepositProviderEventRow {
                    deposit_key: key,
                    recorded_at: now_utc,
                },
            )
            .map_err(|error| engine_failure("meta write", error))?;
        let before = row.state;
        let next = match &event.kind {
            DepositProviderEventKind::Authorized {
                amount_minor,
                currency,
            } => {
                if *amount_minor != row.terms.amount_minor || *currency != row.terms.currency {
                    return Ok(DepositProviderEventOutcome::TermsMismatch);
                }
                matches!(
                    before,
                    DepositState::AwaitingAuthorization | DepositState::AuthorizationFailed
                )
                .then_some(DepositState::Authorized)
            }
            DepositProviderEventKind::AuthorizationFailed { reason } => {
                if matches!(
                    before,
                    DepositState::AwaitingAuthorization | DepositState::AuthorizationFailed
                ) {
                    row.failure = Some(bounded(reason, MAX_FAILURE_BYTES));
                    Some(DepositState::AuthorizationFailed)
                } else {
                    None
                }
            }
            DepositProviderEventKind::Canceled => matches!(
                before,
                DepositState::AwaitingAuthorization
                    | DepositState::AuthorizationFailed
                    | DepositState::Authorized
                    | DepositState::CaptureDue { .. }
                    | DepositState::VoidDue
            )
            .then_some(DepositState::Voided),
        };
        let Some(next) = next else {
            return Ok(DepositProviderEventOutcome::Unchanged(before));
        };
        row.state = next;
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, &key, &row)?;
        Ok(DepositProviderEventOutcome::Applied(next))
    })
}

// -------------------------------------------------------------------------
// The lifecycle writers' deposit steps
// -------------------------------------------------------------------------

/// The hold door's check of a lease that names a deposit: the deposit must
/// be for this page and event type, and still in checkout. A lease minted
/// for one event type's payment never extends a hold on another.
pub(super) fn check_hold_lease_deposit(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lease: &CheckoutLeaseRow,
    page_ref: EntityId,
    event_type: &EventTypeKey,
) -> Result<(), BookingError> {
    let Some(key) = lease.deposit_key else {
        return Ok(());
    };
    let row = DEPOSIT
        .get(&vault.store, txn, &key)
        .map_err(|error| engine_failure("meta read", error))?
        .ok_or_else(|| refused("checkout lease names no deposit"))?;
    if row.page_ref != page_ref || row.event_type != *event_type {
        return Err(refused(
            "checkout lease belongs to another event type's deposit",
        ));
    }
    if !row.state.is_open() {
        return Err(refused("checkout lease's deposit is already settled"));
    }
    Ok(())
}

/// The confirm writer's deposit gate.
///
/// `None` when the hold's event type asks no deposit (or has no live
/// configuration, which the confirm's own re-solve refuses). Otherwise the
/// hold must carry a lease whose deposit is authorized for this session,
/// page, event type and the configuration's current terms; its key is
/// returned for [`mark_capture_due_in_writer`].
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the deposit is not authorized;
/// [`BookingError::SlotOracle`] on a store failure.
pub(super) fn authorized_deposit_in_writer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hold: &SoftHoldRow,
    session_hash: &[u8; 32],
) -> Result<Option<[u8; 32]>, BookingError> {
    let terms = match crate::booking::config::load_event_type_config_in_txn(
        vault,
        txn,
        hold.page_ref,
        &hold.event_type,
    ) {
        Ok(config) => config.deposit,
        Err(BookingError::InvalidConfig(_)) => None,
        Err(error) => return Err(error),
    };
    let Some(terms) = terms else {
        return Ok(None);
    };
    let not_authorized = || refused("booking deposit is not authorized");
    let lease_hash = hold.checkout_lease_hash.ok_or_else(not_authorized)?;
    let lease = CHECKOUT_LEASE
        .get(&vault.store, txn, &lease_hash)
        .map_err(|error| engine_failure("meta read", error))?
        .ok_or_else(not_authorized)?;
    let key = lease.deposit_key.ok_or_else(not_authorized)?;
    let row = DEPOSIT
        .get(&vault.store, txn, &key)
        .map_err(|error| engine_failure("meta read", error))?
        .ok_or_else(not_authorized)?;
    if row.state != DepositState::Authorized
        || row.session_hash != *session_hash
        || lease.session_hash != *session_hash
        || row.page_ref != hold.page_ref
        || row.event_type != hold.event_type
        || row.terms != terms
    {
        return Err(not_authorized());
    }
    Ok(Some(key))
}

/// The booked confirm's deposit step, in its own commit: the capture of the
/// whole deposit is due, the booking names its deposit, and the settle row
/// is queued.
pub(super) fn mark_capture_due_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    event_ref: &EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
    let mut row = DEPOSIT
        .get(&vault.store, &*wtxn, key)
        .map_err(|error| engine_failure("meta read", error))?
        .ok_or_else(|| refused("booking deposit vanished inside its confirm"))?;
    row.state = DepositState::CaptureDue {
        amount_minor: row.terms.amount_minor,
    };
    row.event_ref = Some(event_ref.to_hex());
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, key, &row)?;
    DEPOSIT_BOOKING
        .put(
            &vault.store,
            wtxn,
            &booking_key(event_ref),
            &DepositBookingRow { deposit_key: *key },
        )
        .map_err(|error| engine_failure("meta write", error))?;
    enqueue_settle(vault, wtxn, key, "capture", now_utc)
}

// -------------------------------------------------------------------------
// Reads
// -------------------------------------------------------------------------

/// One deposit as the server and the owner read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookingDepositStatus {
    pub payment_id: String,
    pub state: DepositState,
    pub terms: DepositTerms,
    pub lease_expires_at: u64,
    /// The booking's EVENT once confirmed.
    pub event_ref: Option<EntityId>,
    /// The provider's last refusal of the card.
    pub failure: Option<String>,
}

fn status_of(row: DepositRow) -> BookingDepositStatus {
    BookingDepositStatus {
        payment_id: row.payment_id,
        state: row.state,
        terms: row.terms,
        lease_expires_at: row.lease_expires_at,
        event_ref: row
            .event_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok()),
        failure: row.failure,
    }
}

/// The deposit of the provider payment `payment_id`.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub fn booking_deposit_for_payment(
    vault: &Vault,
    payment_id: &str,
) -> Result<Option<BookingDepositStatus>, BookingError> {
    let rtxn = read_txn(vault)?;
    Ok(DEPOSIT
        .get(&vault.store, &rtxn, &deposit_key(payment_id))
        .map_err(|error| engine_failure("meta read", error))?
        .map(status_of))
}

/// The deposit of the booking `event_ref`.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub fn booking_deposit_for_event(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<Option<BookingDepositStatus>, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &rtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(None);
    };
    Ok(DEPOSIT
        .get(&vault.store, &rtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
        .map(status_of))
}

/// The deposit the session's live hold waits on: its lease's. `None` when
/// the session holds nothing live, or holds without a deposit lease.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub fn booking_deposit_for_session_hold(
    vault: &Vault,
    session_key: &SessionKey,
    now_utc: u64,
) -> Result<Option<BookingDepositStatus>, BookingError> {
    let rtxn = read_txn(vault)?;
    let hold: Option<SoftHoldRow> = super::storage::HOLD
        .get(&vault.store, &rtxn, &super::token::hold_digest(session_key))
        .map_err(|error| engine_failure("meta read", error))?;
    let Some(lease_hash) = hold
        .filter(|hold| hold.is_live_at(now_utc))
        .and_then(|hold| hold.checkout_lease_hash)
    else {
        return Ok(None);
    };
    let Some(key) = CHECKOUT_LEASE
        .get(&vault.store, &rtxn, &lease_hash)
        .map_err(|error| engine_failure("meta read", error))?
        .and_then(|lease| lease.deposit_key)
    else {
        return Ok(None);
    };
    Ok(DEPOSIT
        .get(&vault.store, &rtxn, &key)
        .map_err(|error| engine_failure("meta read", error))?
        .map(status_of))
}
