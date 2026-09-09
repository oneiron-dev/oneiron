//! ONE-1814 [BK-A-3] the booking page's standing invite grant.
//!
//! One bounded authority, minted once per published page, that turns the
//! owner's repeated "yes, send the invite" into remembered consent — and
//! nothing else. It is deliberately NOT a second send path:
//!
//! * **The gate still runs.** [`enqueue_confirm_invite`] builds an ordinary
//!   [`OutboundDispatchRequest`] and hands it to
//!   [`crate::Vault::dispatch_outbound_intent`], so the external-effect gate,
//!   the opt-out wall, the rate/budget stage, the intent ledger, and the
//!   connector adapter all execute exactly as they do for every other send.
//!   The grant removes the PING, never the gate.
//! * **CAL-04 still admits.** The invite is admitted through
//!   [`crate::calendar::admit_calendar_invite`] BEFORE the gate, so vault-only
//!   hygiene hydration and the UID/SEQUENCE law are never bypassed. This
//!   module defines no invite payload, hygiene, or consent type of its own; it
//!   imports CAL-04's.
//! * **The page never authorizes a stranger.** The scope names a PAGE. The
//!   recipient binding lives here, in
//!   [`booking_page_grant_covers_recipient`], and answers only from persisted
//!   claims: a CONFIRMED booking on exactly that page whose recorded booker
//!   identity IS the recipient. No caller-supplied page or booker string is
//!   ever consulted, so a forged context cannot widen a grant.
//!
//! Batch CANCEL and SEQUENCE increments are ONE-1820's; the only move this
//! layer makes is the first confirm's single `REQUEST`.

mod authorization;
mod codec;
mod dispatch;
mod mint;
mod types;

pub use self::authorization::{
    booking_page_grant_covers_recipient, booking_page_invites_authorizes,
};
pub use self::dispatch::enqueue_confirm_invite;
pub use self::mint::mint_publish_page_invite_grant;
pub use self::types::{
    BookingPageInviteContext, ConfirmedBookingInvite, PublishBookingPageGrantRequest,
};

pub(super) use self::authorization::booker_identity;
pub(super) use self::dispatch::{
    NoConfirmInviteSink, dispatch_confirm_booking_invite, sending_address,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{mint::*, types::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::blob_artifact::BlobVersionProvenance;
#[cfg(test)]
use crate::booking::lifecycle::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE, BookingBookerContactValue,
    BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus, BookingStatusValue,
    ConfirmReceipt,
};
#[cfg(test)]
use crate::calendar::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_VERB, CalendarInviteMethod, CalendarInvitePayload,
    ImipEmitRequest, admit_calendar_invite, decode_frozen_calendar_invite, emit_imip_ics,
    persist_imip_blob,
};
#[cfg(test)]
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
#[cfg(test)]
use crate::claim::ClaimLifecycleStatus;
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
#[cfg(test)]
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
};
#[cfg(test)]
use crate::outbound_intent_ledger::{IntentId, intent_ledger_records};
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteActor;
