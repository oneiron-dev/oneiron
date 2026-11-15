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
    OpaqueCheckoutLeaseToken, SessionKey, digest_with, hex_lower, lease_digest, mint_raw_token,
    session_digest,
};
use super::types::{MAX_CHECKOUT_HOLD_TTL_SECS, SoftHoldRow};
use super::{CHECKOUT_LEASE, CheckoutLeaseRow, digest_serde, entity_ref_serde};
use crate::attempt_queue::EnqueueAttempt;
use crate::booking::{BookingError, DepositTerms, EventTypeKey};
use crate::side_table::{self, SideTable, VersionedNamed};
use crate::{EntityId, Vault};

mod settle;

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
    /// A visitor's cancel owes this refund.
    RefundDue { amount_minor: u64 },
    /// The provider refunded this amount.
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
struct DepositRow {
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
    updated_at: u64,
}

/// A booking's deposit. Key: hash32 (the booking digest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositBookingRow {
    #[serde(with = "digest_serde")]
    deposit_key: [u8; 32],
}

/// A provider event already applied. Key: hash32 (the provider event digest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositProviderEventRow {
    #[serde(with = "digest_serde")]
    deposit_key: [u8; 32],
    recorded_at: u64,
}

/// Same `booking.token.v1:` declaration as [`super::TOKEN`]; see its doc
/// comment. Key: hash32 (the payment digest).
const DEPOSIT: SideTable<
    [u8; 32],
    DepositRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_TOKEN);

/// Same declaration. Key: hash32 (the booking digest).
const DEPOSIT_BOOKING: SideTable<
    [u8; 32],
    DepositBookingRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_TOKEN);

/// Same declaration. Key: hash32 (the provider event digest).
const DEPOSIT_PROVIDER_EVENT: SideTable<
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

fn put_deposit(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    row: &DepositRow,
) -> Result<(), BookingError> {
    DEPOSIT
        .put(&vault.store, wtxn, key, row)
        .map_err(|error| engine_failure("meta write", error))
}

/// The payload of one [`BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND`] row: the
/// deposit whose next move is owed. The move itself is read from committed
/// state when the row runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositSettlePayload {
    /// The deposit's key, lowercase hex.
    deposit_key: String,
}

fn enqueue_settle(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    cause: &str,
    now_utc: u64,
) -> Result<(), BookingError> {
    let hex = hex_lower(key);
    let payload = serde_json::to_vec(&DepositSettlePayload {
        deposit_key: hex.clone(),
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
}

/// Applies one verified provider event to its deposit, once.
///
/// An authorization counts only for exactly the deposit's amount and
/// currency. A refusal keeps the deposit, and the hold that waits on it,
/// open for a retry on the same payment. A cancellation closes any deposit
/// not yet captured.
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
            return Ok(DepositProviderEventOutcome::UnknownPayment);
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

/// A visitor's cancel's deposit step, in the cancel's own commit: the
/// refund the terms grant for a cancel at `now_utc` of a booking starting at
/// `start_utc`. Before the capture ran, the capture shrinks by it (to a void
/// when nothing is kept); after, the refund is owed. A booking with no
/// deposit, or none captured or due, is untouched.
pub(super) fn refund_on_visitor_cancel_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    start_utc: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let refund = row.terms.visitor_cancel_refund_minor(start_utc, now_utc);
    let refund = row.refund_cap_minor.map_or(refund, |cap| cap.min(refund));
    let next = match row.state {
        DepositState::CaptureDue { amount_minor } => {
            let kept = amount_minor.saturating_sub(refund);
            if kept == 0 {
                DepositState::VoidDue
            } else {
                DepositState::CaptureDue { amount_minor: kept }
            }
        }
        DepositState::Captured { amount_minor } if refund.min(amount_minor) > 0 => {
            DepositState::RefundDue {
                amount_minor: refund.min(amount_minor),
            }
        }
        _ => return Ok(()),
    };
    row.state = next;
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)?;
    enqueue_settle(vault, wtxn, &link.deposit_key, "cancel", now_utc)
}

/// A visitor's reschedule's deposit step, in the move's own commit (RULING
/// DEPOSIT-RESCHEDULE-REFUND = A, 15 Nov 18:27): what a cancel at `now_utc`
/// would refund against the slot being left, which starts at
/// `left_start_utc`, caps every later visitor cancel's refund. A move made
/// with full notice keeps the full refund; a late move, or one after a
/// no-show, keeps only what the owner's rule granted then. Host moves set no
/// cap. A booking with no deposit is untouched.
pub(super) fn cap_refund_on_visitor_reschedule_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    left_start_utc: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let refund = row
        .terms
        .visitor_cancel_refund_minor(left_start_utc, now_utc);
    let cap = row.refund_cap_minor.map_or(refund, |cap| cap.min(refund));
    if row.refund_cap_minor == Some(cap) {
        return Ok(());
    }
    row.refund_cap_minor = Some(cap);
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)
}

/// The host cancelled a booking in their own calendar, an explicit imported
/// cancellation (FIX 22385): its deposit comes back whole, whatever the
/// visitor's refund rule (RULING DEPOSIT-HOST-CANCEL-REFUND = A, the lead 15
/// Nov 12:1x: not a setting; the visitor did nothing wrong). Before the
/// capture ran, the authorization is released; after, the whole capture is
/// owed back. A booking the visitor already cancelled keeps the refund its
/// own cancel decided, and a booking with no deposit is untouched.
///
/// Calendar ingest calls this before it records the cancellation's status,
/// outside any writer of its own, and again on every later sighting of the
/// same explicit cancellation: the refund is its own commit, so a stop before
/// it is repaired by the next read of the feed. A deposit that already
/// owes or has made its refund, or was voided, is left as it stands, and an
/// EVENT with no deposit costs one read.
///
/// `seen_at` is when ingest first saw the cancellation. One seen at or after
/// the booking's start (a held meeting or a no-show tidied from the
/// calendar) leaves the deposit as it stands; the owner can still refund by
/// hand (RULING DEPOSIT-HOST-CANCEL-AFTER-START = A, parity with CAL-07). A
/// repair poll after the start of a cancellation first seen before it still
/// refunds.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub(crate) fn refund_deposit_on_host_cancel(
    vault: &Vault,
    event_ref: &EntityId,
    seen_at: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    if !host_cancel_may_owe_refund(vault, event_ref)? {
        return Ok(());
    }
    booking_writer(vault, |wtxn| {
        let booking = super::claim::read_booking_facts_to_cancel(vault, &*wtxn, event_ref)?;
        if booking.status == super::types::BookingStatus::Cancelled || seen_at >= booking.slot.start
        {
            return Ok(());
        }
        refund_on_host_cancel_in_writer(vault, wtxn, event_ref, now_utc)
    })
}

/// A host cancel's deposit step inside a booking writer the caller holds:
/// the calendar's imported cancellation above, and the owner's BK-09
/// emergency cancel in its own commit (OPUS-SECREAD-A N2, 15 Nov). A deposit
/// still to capture is released (`VoidDue`), a captured one is owed back
/// whole (`RefundDue`), and its settle row is queued "host-cancel". A booking
/// with no deposit, or one already voided, refunded or owing a refund, is
/// untouched. The caller decides whether the booking was still live.
pub(super) fn refund_on_host_cancel_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    row.state = match row.state {
        DepositState::CaptureDue { .. } => DepositState::VoidDue,
        DepositState::Captured { amount_minor } => DepositState::RefundDue { amount_minor },
        _ => return Ok(()),
    };
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)?;
    enqueue_settle(vault, wtxn, &link.deposit_key, "host-cancel", now_utc)
}

/// Whether the booking `event_ref` has a deposit a host cancel would move:
/// one still to capture, or captured. A read, so the repeated sighting of a
/// cancellation opens no writer.
fn host_cancel_may_owe_refund(vault: &Vault, event_ref: &EntityId) -> Result<bool, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &rtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(false);
    };
    Ok(DEPOSIT
        .get(&vault.store, &rtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
        .is_some_and(|row| {
            matches!(
                row.state,
                DepositState::CaptureDue { .. } | DepositState::Captured { .. }
            )
        }))
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
