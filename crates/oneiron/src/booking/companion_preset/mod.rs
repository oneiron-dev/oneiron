//! ONE-1821 [BK-10] companion booking presets.
//!
//! A companion preset is a second set of *interaction* semantics over the SAME
//! solver, mask, and home-node writer the business booking page uses. It is not
//! a second booking system, and this module carries no product name: the
//! friend-hangout binding sits at the end of this file, and the preset's
//! behaviour is pack data, not code and not an entity kind.
//!
//! # What a companion preset changes
//!
//! - the proposal page is ephemeral and companion-generated, not a hosted page;
//! - the configuration is supplied by the preset ([`CompanionPresetRow`]), so a
//!   solve performs no `booking.event_type` claim lookup — ONE-1823's
//!   `synthetic_config` arm is exactly this;
//! - the carrier is a message link, and each participant gets ONE opaque token,
//!   returned once at creation with only its hash persisted;
//! - a group answer is the intersection of the AUTHORIZED taps, recomputed at
//!   confirm time from stored state rather than trusted from a caller;
//! - the terminal step is a soft confirmation through the companion — no
//!   outbound calendar dispatch, no business inventory, no hard commitment.
//!
//! # Expiry is lazy
//!
//! `expires_at` is compared at tap and at confirm. There is no timer, wake, or
//! daemon, and correctness never depends on cleanup running: a proposal whose
//! deadline has passed is refused by the liveness test on the read path.
//!
//! # One state machine
//!
//! A single participant is a group of one. Creation, tap, intersection, and
//! confirm are the same four functions at every participant count — there is no
//! poll-style parallel implementation for groups.

mod preset;
mod proposal;
mod render;
mod storage;
mod tap;

pub use self::preset::{
    CompanionConfirmationMode, CompanionPresetRow, FRIEND_HANGOUT_PRESET_ID,
    HangoutProposalAssembly, ProposalCarrier, assemble_hangout_proposal_message,
    friend_hangout_preset, load_companion_preset,
};
pub use self::proposal::{
    COMPANION_PROPOSAL_META_PREFIX, ChoiceId, CompanionProposal, CompanionProposalCreation,
    CompanionSoftConfirmation, OneTimeParticipantToken, ProposalChoice, ProposalId, ProposalTap,
    TapAggregate, companion_solve_request, create_companion_proposal,
};
pub use self::render::{
    COMPANION_PROPOSAL_LINK_PREFIX, COMPANION_PROPOSAL_TAP_ACTION, opaque_proposal_message_link,
    render_companion_proposal,
};
pub use self::tap::{
    ranked_authorized_common_intersection, record_proposal_tap,
    soft_confirm_highest_common_on_home_node,
};

#[cfg(test)]
mod tests;

// The flat companion_preset.rs module used to provide these names to the
// sibling test module through `use super::*`: every companion-internal item
// the tests name bare, plus the external names the tests used to inherit from
// the old file's import header. After the directory split the seam re-imports
// both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::proposal::{CompanionProposalRow, PARTICIPANT_TOKEN_HEX_LEN};
#[cfg(test)]
use self::render::validate_participant_token;
#[cfg(test)]
use self::storage::{decode_row, proposal_meta_key};
#[cfg(test)]
use crate::booking::lifecycle::read_meta_bytes;
#[cfg(test)]
use crate::booking::{BookingError, EventTypeConfig, EventTypeKey, RankedSlot, SlotOracle};
#[cfg(test)]
use crate::lens::LensAtom;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::{EntityId, Vault};
