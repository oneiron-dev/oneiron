//! Moved from `crates/oneiron/src/workspace_roster/rooms/offers.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::room_join::ConsentNeed;
pub use oneiron_verb_wire::workspace_roster::rooms::offers::OffersRequest;
use serde::Deserialize;
use serde::Serialize;

/// Where one card stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfferState {
    /// Waiting on the parties `needs` names. The host's admission is the one
    /// the card asks for; a payer answers through `rooms.consent`, and
    /// membership is read live.
    Open { needs: Vec<ConsentNeed> },
    /// The join was Ready and the agent's acceptance landed as `turn`, its
    /// own turn in the room or thread.
    Joined { turn: EntityId, receipt_ref: String },
    /// Not now. The decline is in the agent's private diary, or `None` when
    /// the agent's standing refused the note; it settles this card and bars no
    /// later ask.
    NotNow { diary_ref: Option<EntityId> },
    /// A newer card from the same agent for the same room or thread
    /// replaced this one.
    Superseded { by: String },
    /// No one answered in time: the card's thread ended, or a room-wide card
    /// went a day without engagement or passed its fixed deadline.
    AgedOut,
}

/// The advisory ballots on a room-wide card, as counts (FIX 2091): how
/// many voters said join and how many not now, never who. They keep the
/// card open and decide nothing; only the host's answer admits. A thread's
/// card counts none, since it takes no votes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferVoteTally {
    pub join: u64,
    pub not_now: u64,
}

/// An offer id: 64 lowercase hex.
pub fn is_offer_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
