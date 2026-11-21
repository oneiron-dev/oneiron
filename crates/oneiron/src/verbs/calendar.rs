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

// The owner's release of a calendar hold (`calendar.connector.release_hold`).
use crate::calendar::connectors::door::{
    CalendarConnectorReleaseHoldReceipt, CalendarConnectorReleaseHoldRequest, CalendarHoldRow,
};

/// The owner's calendar-hold release verb's public spelling.
pub const CALENDAR_HOLD_RELEASE_VERB: &str = "calendar.connector.release_hold";

/// What the owner's sheet shows of a `calendar.connector.release_hold` call, and what its
/// confirm binds: the booking EVENT and each outbox row that holds its pulls while the seat that
/// wrote it is out of service, as it stands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CalendarHoldReleaseView {
    event_ref: String,
    holds: Vec<CalendarHoldRow>,
}

/// The booking EVENT `input` names and its calendar holds as the sheet shows them, read under
/// `owner`'s proof as a vault-owner write would take it. A booking with no hold, or whose every
/// hold only reconnecting its seat lifts (a first write's), is refused.
pub(crate) fn calendar_hold_release_view(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: &CalendarConnectorReleaseHoldRequest,
) -> crate::memory::MemoryResult<(crate::EntityId, CalendarHoldReleaseView)> {
    let event = crate::EntityId::from_hex(input.event_ref.trim()).map_err(|_| {
        crate::memory::MemoryError::bad_request("event_ref is an entity id in lowercase hex")
    })?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    owner.owner_authored_write_in_txn(vault, &txn)?;
    let holds = crate::calendar::connectors::calendar_holds_in_txn(vault, &txn, &event)?;
    if holds.is_empty() {
        return Err(crate::memory::MemoryError::not_found(
            "no calendar change of this booking is on hold",
        ));
    }
    if !holds.iter().any(|hold| hold.releasable) {
        return Err(crate::memory::MemoryError::new(
            crate::memory::MEMORY_CODE_INVALID_STATE,
            "this hold holds the event's first write, whose copy would import a second event: \
             only reconnecting its connection lifts it",
            &["Reconnect it: vault.settings.set of calendar.connector_seat, same config."],
        ));
    }
    Ok((
        event,
        CalendarHoldReleaseView {
            event_ref: event.to_hex(),
            holds,
        },
    ))
}

/// `calendar.connector.release_hold` on an embedded handle, as the vault's embedded owner.
pub fn release_calendar_hold(
    memory: &crate::memory::Memory<'_>,
    input: &CalendarConnectorReleaseHoldRequest,
) -> crate::memory::MemoryResult<CalendarConnectorReleaseHoldReceipt> {
    let owner = memory.embedded_owner(CALENDAR_HOLD_RELEASE_VERB)?;
    release_calendar_hold_as(memory.vault(), &owner, input)
}

/// `calendar.connector.release_hold` under the vault owner's own proof, which the release's
/// write revalidates (PLAN-CALENDAR-CONNECTOR-RELEASE-HOLD = A, the lead 21 Nov 09:40): the
/// owner lets the pulls a dead seat's outbox rows hold of one booking land. It goes through the
/// owner's sheet (`vault.owner_confirm.preview`): the confirm binds the rows as the preview
/// showed them, and a row that moved since is refused. No agent grant, delegate credential or
/// visitor token reaches it. A host cancel of the booking then records the owner's line "a
/// cancel we can't attribute: refund by hand?" and never refunds by itself.
pub fn release_calendar_hold_as(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: &CalendarConnectorReleaseHoldRequest,
) -> crate::memory::MemoryResult<CalendarConnectorReleaseHoldReceipt> {
    let ask = super::owner_confirm::asked(CALENDAR_HOLD_RELEASE_VERB, input)?;
    let (event, view) = calendar_hold_release_view(vault, owner, input)?;
    super::owner_confirm::admit(vault, owner, ask, &view)?;
    if !crate::calendar::connectors::release_calendar_holds_as_owner(
        vault,
        owner,
        &event,
        &view.holds,
    )? {
        return Err(crate::memory::MemoryError::new(
            crate::memory::MEMORY_CODE_OWNER_CONFIRM_REQUIRED,
            "the booking's calendar hold changed since its preview",
            &["Preview it again and confirm what it shows now."],
        ));
    }
    Ok(CalendarConnectorReleaseHoldReceipt {
        event_ref: view.event_ref,
        released: view
            .holds
            .into_iter()
            .filter(|hold| hold.releasable)
            .collect(),
    })
}
