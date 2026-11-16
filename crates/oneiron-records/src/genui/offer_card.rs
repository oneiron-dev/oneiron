//! Moved from `crates/oneiron/src/genui/offer_card.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::workspace_roster::rooms::offer_activity::OfferVoteRequest;
use oneiron_verb_wire::workspace_roster::rooms::offer_reopen::OfferReopenRequest;
use oneiron_verb_wire::workspace_roster::rooms::offer_settle::OfferAnswer;
use oneiron_verb_wire::workspace_roster::rooms::offer_settle::OfferAnswerRequest;
use serde::Deserialize;
use serde::Serialize;

pub const OFFER_JOIN_ACTION_ID: &str = "join";

pub const OFFER_NOT_NOW_ACTION_ID: &str = "not_now";

/// A room member's advisory ballot for join, on an open room-wide card.
pub const OFFER_VOTE_JOIN_ACTION_ID: &str = "vote_join";

/// A room member's advisory ballot for not now, on an open room-wide card.
pub const OFFER_VOTE_NOT_NOW_ACTION_ID: &str = "vote_not_now";

/// The room host's one-click reopening of a room-wide card that aged out.
pub const OFFER_REOPEN_ACTION_ID: &str = "reopen";

/// The most of an offer's `what` or artifact a drawn card shows (OF-530).
/// The offer keeps the whole text, and the card with its fallback stays
/// within a lens text.
pub const OFFER_CARD_PREVIEW_BYTES: usize = 4 * 1024;

/// `text` as a drawn card shows it: whole when it fits
/// [`OFFER_CARD_PREVIEW_BYTES`], else cut at a character boundary and marked
/// with an ellipsis.
pub fn card_preview(text: &str) -> String {
    if text.len() <= OFFER_CARD_PREVIEW_BYTES {
        return text.to_owned();
    }
    let mut end = OFFER_CARD_PREVIEW_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", text[..end].trim_end())
}

/// Where a drawn offer card stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferCardPhase {
    /// Waiting on the host's answer; a room-wide card also takes the room's
    /// advisory ballots.
    Open,
    /// A room-wide card no one engaged with in time, or past its fixed
    /// deadline: its host may reopen it. A thread card that ended is not
    /// drawn.
    AgedOut,
}

/// A validated answer from the authenticated actor. It is no join and no
/// permission to land one: the room's offer door checks that the actor
/// answers the room's admission, and decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerIntent {
    pub offer_id: String,
    pub action: OfferAnswer,
    pub answerer: EntityId,
    pub origin_component_id: String,
    pub origin_action_id: String,
}

impl OfferAnswerIntent {
    /// The request the room's offer door settles. The tap names only the
    /// card, the verb and its own replay key.
    #[must_use]
    pub fn request(&self) -> OfferAnswerRequest {
        OfferAnswerRequest {
            offer_id: self.offer_id.clone(),
            action: self.action,
            intent_key: format!(
                "card:{}:{}",
                self.origin_component_id, self.origin_action_id
            ),
        }
    }
}

/// A validated advisory ballot from the authenticated actor on an open
/// room-wide card. It is no answer, no consent and no admission: the room's
/// offer door checks that the voter reads the room, the ballot keeps the
/// card open, and only the host's answer admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferVoteIntent {
    pub offer_id: String,
    /// What the voter would have the host answer.
    pub action: OfferAnswer,
    pub voter: EntityId,
    pub origin_component_id: String,
    pub origin_action_id: String,
}

impl OfferVoteIntent {
    /// The request the room's offer door records.
    #[must_use]
    pub fn request(&self) -> OfferVoteRequest {
        OfferVoteRequest {
            offer_id: self.offer_id.clone(),
            action: self.action,
        }
    }
}

/// A validated reopening of a room-wide card that aged out, from the
/// authenticated actor, naming the last engagement the card was drawn with.
/// It is no permission: the room's offer door reopens only for the room's
/// owner or a delegated host, and only the card as drawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferReopenIntent {
    pub offer_id: String,
    pub expected_last_engaged_at: u64,
    /// The host's new fixed deadline, in Unix seconds; `None` reopens the
    /// card for a day without engagement.
    pub until: Option<u64>,
    pub host: EntityId,
    pub origin_component_id: String,
    pub origin_action_id: String,
}

impl OfferReopenIntent {
    /// The request the room's offer door decides.
    #[must_use]
    pub fn request(&self) -> OfferReopenRequest {
        OfferReopenRequest {
            offer_id: self.offer_id.clone(),
            expected_last_engaged_at: self.expected_last_engaged_at,
            until: self.until,
        }
    }
}

/// One tap on an offer card, typed by the verb its action names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfferCardIntent {
    Answer(OfferAnswerIntent),
    Vote(OfferVoteIntent),
    Reopen(OfferReopenIntent),
}
