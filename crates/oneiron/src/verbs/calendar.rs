//! Typed booking-page discovery, public lifecycle calls and calendar occupancy inputs.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::calendar::{
    BookingCancelRequest, BookingConstraintTurnInput, BookingConstraintTurnRequest,
    BookingConstraintTurnWindow, BookingPageTokenRequest, BookingPageTokenResponse,
    BookingRescheduleRequest, CalendarFreebusyRequest,
};

/// Public availability, using the canonical booking operation envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingAvailabilityRequest {
    Availability {
        page_token: String,
        input: crate::booking::agent_api::BookingAvailabilityInput,
    },
}

/// The full two-stage book flow, not an implicit confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingBookRequest {
    Book {
        page_token: String,
        input: crate::booking::agent_api::BookingBookInput,
    },
}

/// Offers, an email continuation, or a deflect; never booking authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BookingConstraintTurnResponse {
    Slots {
        card: crate::lens::GeneratedUiCard,
        flex_used: bool,
        hold: BookingConstraintHoldContext,
    },
    ContinueByEmail {
        continuation: crate::booking::agent_front::ConstraintContinuation,
    },
    Deflect {
        card: crate::lens::GeneratedUiCard,
    },
}

/// The rest of an explicit slot selection's hold input, not a hold itself.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BookingConstraintHoldContext {
    pub event_type: crate::booking::EventTypeKey,
    pub visitor_tz: String,
    pub constraint: crate::booking::ConstraintObject,
    pub session_ref: String,
}

// The owner's deposit refund (`vault.booking.deposit.refund`) and its mark
// of a refund paid outside Stripe (`vault.booking.deposit.mark_refunded_outside`).
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::calendar::{
    BookingDepositMarkRefundedOutsideReceipt, BookingDepositMarkRefundedOutsideRequest,
    BookingDepositRefundReceipt, BookingDepositRefundRequest, BookingDepositRefundState,
};

/// The owner's mark of a deposit refund paid outside Stripe: its public
/// spelling.
const DEPOSIT_MARK_REFUNDED_OUTSIDE_VERB: &str = "vault.booking.deposit.mark_refunded_outside";

/// `vault.booking.deposit.mark_refunded_outside` on an embedded handle, as
/// the vault's embedded owner.
pub fn mark_booking_deposit_refunded_outside(
    memory: &crate::memory::Memory<'_>,
    input: &BookingDepositMarkRefundedOutsideRequest,
) -> crate::memory::MemoryResult<BookingDepositMarkRefundedOutsideReceipt> {
    let owner = memory.embedded_owner(DEPOSIT_MARK_REFUNDED_OUTSIDE_VERB)?;
    mark_booking_deposit_refunded_outside_as(memory.vault(), &owner, input)
}

/// `vault.booking.deposit.mark_refunded_outside` under the owner's proof,
/// which the mark's write revalidates (BK-DEPOSIT-FAILED-REFUND-MARK-PAID =
/// B): a host selected at the booking's confirmation says the refund its
/// deposit owes now was paid back outside Stripe, and the deposit's settle
/// row then makes no refund. No agent grant and no visitor token reach it.
pub fn mark_booking_deposit_refunded_outside_as(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: &BookingDepositMarkRefundedOutsideRequest,
) -> crate::memory::MemoryResult<BookingDepositMarkRefundedOutsideReceipt> {
    let event_ref = crate::EntityId::from_hex(input.event_ref.trim()).map_err(|_| {
        crate::memory::MemoryError::bad_request("event_ref is an entity id in lowercase hex")
    })?;
    crate::booking::lifecycle::mark_booking_deposit_refunded_outside(
        vault,
        owner,
        &event_ref,
        input.amount_minor,
    )
    .map_err(crate::memory::booking_error)
}

/// The owner's deposit refund verb's public spelling.
const DEPOSIT_REFUND_VERB: &str = "vault.booking.deposit.refund";

/// `vault.booking.deposit.refund` on an embedded handle, as the vault's
/// embedded owner.
pub fn refund_booking_deposit(
    memory: &crate::memory::Memory<'_>,
    input: &BookingDepositRefundRequest,
) -> crate::memory::MemoryResult<BookingDepositRefundReceipt> {
    let owner = memory.embedded_owner(DEPOSIT_REFUND_VERB)?;
    refund_booking_deposit_as(memory.vault(), &owner, input)
}

/// `vault.booking.deposit.refund` under the owner's proof, which the
/// refund's money write revalidates (BK-DEPOSIT-OWNER-RETURN-ACT = A): a
/// host selected at the booking's confirmation gives its held deposit back
/// whole once the booking is cancelled or has started. No agent grant and no
/// visitor token reach it.
pub fn refund_booking_deposit_as(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: &BookingDepositRefundRequest,
) -> crate::memory::MemoryResult<BookingDepositRefundReceipt> {
    let event_ref = crate::EntityId::from_hex(input.event_ref.trim()).map_err(|_| {
        crate::memory::MemoryError::bad_request("event_ref is an entity id in lowercase hex")
    })?;
    crate::booking::lifecycle::refund_booking_deposit_as_owner(vault, owner, &event_ref)
        .map_err(crate::memory::booking_error)
}
