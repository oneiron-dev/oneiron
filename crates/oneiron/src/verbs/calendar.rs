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

// The owner's deposit refund (`vault.booking.deposit.refund`).
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::calendar::{
    BookingDepositRefundReceipt, BookingDepositRefundRequest, BookingDepositRefundState,
};

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
