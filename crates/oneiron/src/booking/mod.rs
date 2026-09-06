//! Engine-generic booking module.
//!
//! Declarations and re-exports only: every seam type is defined in
//! [`constraint`], which is the single home later booking layers import from.
//! This file defines no type, no function, and allocates no entity byte — an
//! invariant ONE-1816 asserts mechanically, which is why the `booking.*`
//! claim-family door lives in [`lifecycle`] and is only re-exported here.

pub mod agent_api;
pub mod agent_front;
pub mod anti_abuse;
pub mod companion_preset;
pub mod config;
pub mod constraint;
pub mod disclosure_rung;
pub mod emergency_reschedule;
pub mod invite_grant;
pub mod lifecycle;
pub mod solver;
#[cfg(test)]
mod tests;

pub use companion_preset::{
    COMPANION_PROPOSAL_LINK_PREFIX, COMPANION_PROPOSAL_META_PREFIX, COMPANION_PROPOSAL_TAP_ACTION,
    ChoiceId, CompanionConfirmationMode, CompanionPresetRow, CompanionProposal,
    CompanionProposalCreation, CompanionSoftConfirmation, OneTimeParticipantToken, ProposalCarrier,
    ProposalChoice, ProposalId, ProposalTap, TapAggregate, companion_solve_request,
    create_companion_proposal, load_companion_preset, opaque_proposal_message_link,
    ranked_authorized_common_intersection, record_proposal_tap, render_companion_proposal,
    soft_confirm_highest_common_on_home_node,
};
pub use config::{
    BOOKING_EVENT_TYPE_META_PREFIX, BOOKING_EVENT_TYPE_PREDICATE,
    BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue, ClaimClassDescriptorRow,
    DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, EventTypeConfig,
    HIGH_VALUE_MIN_NOTICE_SECS, HostAvailabilityConfig, MAX_BOOKING_WINDOW_SECS, RoutingMode,
    WeeklyWallWindow, decode_event_type_claim_value, encode_event_type_claim_value,
    event_type_index_key, is_booking_claim_predicate,
};
pub use constraint::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotHostBinding, SlotMask,
    SlotOracle, SolveRequest, SolveResult,
};
pub use disclosure_rung::{
    BusyBlockRow, CalendarDisclosureDefault, DisclosureRung, EventDetailsRow, EventRow,
    RungProjection, SurfaceClass, TitledEventRow, default_disclosure_rung, project_at_rung,
    project_calendar_grant,
};
pub use emergency_reschedule::{
    AffectedBooking, EmergencyActionPolicy, EmergencyBatchPlan, EmergencyItem, EmergencyLocalBasis,
    EmergencyPick, EmergencyPlan, EmergencyRescheduleRequest, OwnerInstructionRecord,
    canonical_emergency_request_hash, counterparty_pick, enumerate_affected_bookings,
    execute_emergency_plan, plan_emergency_reschedule, verify_logged_owner_instruction,
};
pub use invite_grant::{
    BookingPageInviteContext, ConfirmedBookingInvite, PublishBookingPageGrantRequest,
    booking_page_grant_covers_recipient, booking_page_invites_authorizes, enqueue_confirm_invite,
    mint_publish_page_invite_grant,
};
pub use lifecycle::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_HOLD_META_PREFIX,
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BOOKING_LIFECYCLE_PREDICATES, BOOKING_PASSPORT_SYSTEM,
    BOOKING_RECEIPT_META_PREFIX, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BOOKING_TOKEN_META_PREFIX, BOOKING_VERBS, BookingBookerContactValue, BookingEventTypeRefValue,
    BookingLifecycleAttempt, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingOracleRequest, BookingSourcePageValue, BookingStatus, BookingStatusValue, BookingVerb,
    BookingVerbReceipt, BookingVerbRequest, CalendarRevision, CancelSpec, ConfirmReceipt,
    ConfirmSpec, DEFAULT_HOLD_TTL_SECS, HoldLeaseSpec, HoldReceipt, HoldSpec, LifecycleTokenScope,
    MAX_CHECKOUT_HOLD_TTL_SECS, OpaqueCheckoutLeaseToken, OpaqueLifecycleToken, RescheduleSpec,
    RevisionReceipt, SessionKey, SoftHoldRow, VaultActiveHoldSource,
    booking_claim_class_descriptors, enqueue_booking_verb, is_booking_family_claim_predicate,
    is_booking_lifecycle_claim_predicate, issue_checkout_lease, run_booking_lifecycle_once,
    token_page_ref, validate_booking_family_claim,
};
pub use solver::{
    ActiveHoldSource, BookingCountBucket, BookingCounts, BookingSolver, NoActiveHolds, slot_mask,
};
