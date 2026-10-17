//! The offer card's render-neutral payload and its write-free intents
//! (OF-530): the host's answer, a room member's advisory ballot on a
//! room-wide card, and the host's one-click reopening of a room-wide card
//! that aged out. Rendering belongs to clients (RD-18); the room's offer
//! doors decide each one, and none of them is a new consent power.

use super::consent_eval::{
    ConsentActionKind, ConsentActionRequest, ensure_component_request, ensure_declared_action,
    lens_text,
};
use super::protocol::Of336ActionDescriptor;
use crate::error::GateError;
use crate::llm::run_admission::DeclaredMaximum;
use crate::memory::{Memory, MemoryResult};
use crate::workspace_roster::{
    OfferAnswer, OfferAnswerRequest, OfferCard, OfferReopenRequest, OfferSettlement, OfferState,
    OfferVoteRequest, ROOM_OFFER_IDLE_SECS,
};
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};

pub const OFFER_JOIN_ACTION_ID: &str = "join";
pub const OFFER_NOT_NOW_ACTION_ID: &str = "not_now";
/// A room member's advisory ballot for join, on an open room-wide card.
pub const OFFER_VOTE_JOIN_ACTION_ID: &str = "vote_join";
/// A room member's advisory ballot for not now, on an open room-wide card.
pub const OFFER_VOTE_NOT_NOW_ACTION_ID: &str = "vote_not_now";
/// The room host's one-click reopening of a room-wide card that aged out.
pub const OFFER_REOPEN_ACTION_ID: &str = "reopen";

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

/// What a client draws for one offer card: who asks, what it would do, the
/// artifact it attaches, what it would cost and who pays, where it stands,
/// a room-wide card's deadline, and the verbs its state takes. Built from
/// the host-held card, never from a client's copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferCardPayload {
    /// The offer id.
    pub card_id: String,
    pub room_ref: String,
    pub thread_ref: Option<String>,
    /// Who asks: the AGENT_DEF.
    pub agent_ref: String,
    pub what: String,
    pub artifact_ref: Option<String>,
    /// The cost: the lease cap the payer accepted, in its unit.
    pub lease_cap: Option<DeclaredMaximum>,
    pub payer_ref: Option<String>,
    pub phase: OfferCardPhase,
    /// A room-wide card's fixed deadline, in Unix seconds; `None` on a card
    /// that ends after a day without engagement, and on a thread card.
    pub until: Option<u64>,
    /// A room-wide card's publication or reopening, or the last reply, vote,
    /// mention or answer that engaged it since, in Unix seconds: what a
    /// reopening names as `expected_last_engaged_at`. `None` on a thread
    /// card, which ends with its thread.
    pub last_engaged_at: Option<u64>,
    /// When a room-wide card ends unless engaged again: its `until`, else a
    /// day past `last_engaged_at`. `None` on a thread card.
    pub ends_at: Option<u64>,
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

/// What one dispatched tap left: the answer's settlement, or the card as
/// the ballot or the reopening left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfferCardOutcome {
    Answered(OfferSettlement),
    Voted(OfferCard),
    Reopened(OfferCard),
}

impl OfferCardPayload {
    /// The payload of an open card, or of a room-wide card that aged out
    /// (its one verb is the host's reopening). A card answered, declined or
    /// replaced asks nothing, and a thread card that ended is not drawn.
    pub fn of(card: &OfferCard) -> Result<Self> {
        let room_wide = card.branch.is_none();
        let phase = match card.state {
            OfferState::Open { .. } => OfferCardPhase::Open,
            OfferState::AgedOut if room_wide => OfferCardPhase::AgedOut,
            OfferState::AgedOut
            | OfferState::Joined { .. }
            | OfferState::NotNow { .. }
            | OfferState::Superseded { .. } => {
                return Err(Error::InvalidConfig(
                    "only an open offer card, or a room-wide one that aged out, is shown with its verbs"
                        .into(),
                ));
            }
        };
        let (until, last_engaged_at, ends_at) = if room_wide {
            let ends_at = card
                .until
                .unwrap_or_else(|| card.last_engaged_at.saturating_add(ROOM_OFFER_IDLE_SECS));
            (card.until, Some(card.last_engaged_at), Some(ends_at))
        } else {
            (None, None, None)
        };
        let payload = Self {
            card_id: card.offer_id.clone(),
            room_ref: card.room.to_hex(),
            thread_ref: card.branch.map(|branch| branch.to_hex()),
            agent_ref: card.agent.to_hex(),
            what: card.what.clone(),
            artifact_ref: card.artifact_ref.clone(),
            lease_cap: card.lease_cap.clone(),
            payer_ref: card.payer.map(|payer| payer.to_hex()),
            phase,
            until,
            last_engaged_at,
            ends_at,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Recheck before rendering or emitting an intent: decoded payloads must
    /// not bypass the card's constraints.
    pub fn validate(&self) -> Result<()> {
        if self.what.trim().is_empty() || self.what.contains(['\n', '\r']) {
            return Err(Error::InvalidConfig(
                "an offer card's what is one line of text".into(),
            ));
        }
        lens_text(self.what.clone())?;
        if let Some(artifact) = &self.artifact_ref {
            lens_text(artifact.clone())?;
        }
        if self.thread_ref.is_some() {
            if self.phase != OfferCardPhase::Open
                || self.until.is_some()
                || self.last_engaged_at.is_some()
                || self.ends_at.is_some()
            {
                return Err(Error::InvalidConfig(
                    "a thread offer card is drawn open, with no deadline of its own".into(),
                ));
            }
        } else if self.last_engaged_at.is_none() || self.ends_at.is_none() {
            return Err(Error::InvalidConfig(
                "a room-wide offer card carries its last engagement and its end".into(),
            ));
        }
        // A client that cannot draw the card shows this text instead.
        lens_text(self.fallback_text())?;
        Ok(())
    }

    /// The verbs this card's state takes: an open card's join and not now
    /// (the host's answer), and on a room-wide one the room's two advisory
    /// ballots; a room-wide card that aged out takes only its host's
    /// reopening.
    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        let verb =
            |action_id: &str, label: &str, action: ConsentActionKind| Of336ActionDescriptor {
                action_id: action_id.to_owned(),
                label: label.to_owned(),
                action,
            };
        match (self.phase, self.thread_ref.is_some()) {
            (OfferCardPhase::AgedOut, _) => vec![verb(
                OFFER_REOPEN_ACTION_ID,
                "Reopen",
                ConsentActionKind::Approve,
            )],
            (OfferCardPhase::Open, true) => vec![
                verb(OFFER_JOIN_ACTION_ID, "Join", ConsentActionKind::Approve),
                verb(
                    OFFER_NOT_NOW_ACTION_ID,
                    "Not now",
                    ConsentActionKind::Decline,
                ),
            ],
            (OfferCardPhase::Open, false) => vec![
                verb(OFFER_JOIN_ACTION_ID, "Join", ConsentActionKind::Approve),
                verb(
                    OFFER_NOT_NOW_ACTION_ID,
                    "Not now",
                    ConsentActionKind::Decline,
                ),
                verb(
                    OFFER_VOTE_JOIN_ACTION_ID,
                    "Vote join",
                    ConsentActionKind::Approve,
                ),
                verb(
                    OFFER_VOTE_NOT_NOW_ACTION_ID,
                    "Vote not now",
                    ConsentActionKind::Decline,
                ),
            ],
        }
    }

    /// The checks every tap runs before it emits an intent: it targets this
    /// card, names a verb its state declares, and comes from
    /// `authenticated`, the actor whose credential the host verified; a voice
    /// label is never that credential.
    fn check_tap(&self, request: &ConsentActionRequest, authenticated: EntityId) -> Result<()> {
        self.validate()?;
        ensure_component_request(&self.card_id, request)?;
        ensure_declared_action(&self.actions(), request)?;
        if !request
            .actor
            .authenticates_principal(&authenticated.to_hex())
        {
            return Err(Error::Gate(GateError::ConsentUnauthenticatedActor(
                "the action actor is not the authenticated answerer",
            )));
        }
        Ok(())
    }

    /// A tap only emits an intent: [`Self::check_tap`], on the answer's two
    /// verbs only. A ballot or a reopening is never an answer.
    pub fn evaluate_action(
        &self,
        request: &ConsentActionRequest,
        authenticated: EntityId,
    ) -> Result<OfferAnswerIntent> {
        self.check_tap(request, authenticated)?;
        let action = match request.action_id.as_str() {
            OFFER_JOIN_ACTION_ID => OfferAnswer::Join,
            OFFER_NOT_NOW_ACTION_ID => OfferAnswer::NotNow,
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "offer action {:?} is not an answer",
                    request.action_id
                )));
            }
        };
        Ok(OfferAnswerIntent {
            offer_id: self.card_id.clone(),
            action,
            answerer: authenticated,
            origin_component_id: self.card_id.clone(),
            origin_action_id: request.action_id.clone(),
        })
    }

    /// A ballot tap emits a vote intent: [`Self::check_tap`], on an open
    /// room-wide card's two ballot verbs only.
    pub fn evaluate_vote(
        &self,
        request: &ConsentActionRequest,
        authenticated: EntityId,
    ) -> Result<OfferVoteIntent> {
        self.check_tap(request, authenticated)?;
        let action = match request.action_id.as_str() {
            OFFER_VOTE_JOIN_ACTION_ID => OfferAnswer::Join,
            OFFER_VOTE_NOT_NOW_ACTION_ID => OfferAnswer::NotNow,
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "offer action {:?} is not a vote",
                    request.action_id
                )));
            }
        };
        Ok(OfferVoteIntent {
            offer_id: self.card_id.clone(),
            action,
            voter: authenticated,
            origin_component_id: self.card_id.clone(),
            origin_action_id: request.action_id.clone(),
        })
    }

    /// A reopen tap emits a reopen intent: [`Self::check_tap`], on a
    /// room-wide card that aged out, naming the last engagement it was
    /// drawn with and the host's new deadline, if any.
    pub fn evaluate_reopen(
        &self,
        request: &ConsentActionRequest,
        authenticated: EntityId,
        until: Option<u64>,
    ) -> Result<OfferReopenIntent> {
        self.check_tap(request, authenticated)?;
        let expected_last_engaged_at = match (request.action_id.as_str(), self.last_engaged_at) {
            (OFFER_REOPEN_ACTION_ID, Some(at)) => at,
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "offer action {:?} is not a reopening",
                    request.action_id
                )));
            }
        };
        Ok(OfferReopenIntent {
            offer_id: self.card_id.clone(),
            expected_last_engaged_at,
            until,
            host: authenticated,
            origin_component_id: self.card_id.clone(),
            origin_action_id: request.action_id.clone(),
        })
    }

    /// One tap, typed by the verb its action names. `until` is a
    /// reopening's new deadline and is refused on any other verb.
    pub fn evaluate_intent(
        &self,
        request: &ConsentActionRequest,
        authenticated: EntityId,
        until: Option<u64>,
    ) -> Result<OfferCardIntent> {
        if until.is_some() && request.action_id != OFFER_REOPEN_ACTION_ID {
            return Err(Error::InvalidConfig(
                "only a reopening names a new deadline".into(),
            ));
        }
        Ok(match request.action_id.as_str() {
            OFFER_VOTE_JOIN_ACTION_ID | OFFER_VOTE_NOT_NOW_ACTION_ID => {
                OfferCardIntent::Vote(self.evaluate_vote(request, authenticated)?)
            }
            OFFER_REOPEN_ACTION_ID => {
                OfferCardIntent::Reopen(self.evaluate_reopen(request, authenticated, until)?)
            }
            _ => OfferCardIntent::Answer(self.evaluate_action(request, authenticated)?),
        })
    }

    /// A tap settles through the room's offer door, as every other client
    /// does, bound to the tapping actor; the host-held card names the offer.
    pub fn answer(
        &self,
        memory: &Memory<'_>,
        request: &ConsentActionRequest,
    ) -> MemoryResult<OfferSettlement> {
        let intent = self.evaluate_action(request, memory.actor())?;
        memory.rooms_offer_answer(&intent.request())
    }

    /// A ballot tap records through the room's offer door
    /// ([`Memory::rooms_offer_vote`]), bound to the tapping actor: advisory,
    /// never admission.
    pub fn vote(
        &self,
        memory: &Memory<'_>,
        request: &ConsentActionRequest,
    ) -> MemoryResult<OfferCard> {
        let intent = self.evaluate_vote(request, memory.actor())?;
        memory.rooms_offer_vote(&intent.request())
    }

    /// A reopen tap goes to the room's offer door
    /// ([`Memory::rooms_offer_reopen`]), bound to the tapping actor, which
    /// reopens only for the room's owner or a delegated host.
    pub fn reopen(
        &self,
        memory: &Memory<'_>,
        request: &ConsentActionRequest,
        until: Option<u64>,
    ) -> MemoryResult<OfferCard> {
        let intent = self.evaluate_reopen(request, memory.actor(), until)?;
        memory.rooms_offer_reopen(&intent.request())
    }

    /// Any tap, through the door its verb names, bound to the tapping
    /// actor.
    pub fn dispatch(
        &self,
        memory: &Memory<'_>,
        request: &ConsentActionRequest,
        until: Option<u64>,
    ) -> MemoryResult<OfferCardOutcome> {
        Ok(
            match self.evaluate_intent(request, memory.actor(), until)? {
                OfferCardIntent::Answer(intent) => {
                    OfferCardOutcome::Answered(memory.rooms_offer_answer(&intent.request())?)
                }
                OfferCardIntent::Vote(intent) => {
                    OfferCardOutcome::Voted(memory.rooms_offer_vote(&intent.request())?)
                }
                OfferCardIntent::Reopen(intent) => {
                    OfferCardOutcome::Reopened(memory.rooms_offer_reopen(&intent.request())?)
                }
            },
        )
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        let artifact = self
            .artifact_ref
            .as_deref()
            .map_or_else(String::new, |artifact| format!(" Artifact: {artifact}."));
        let cost = self.lease_cap.as_ref().map_or_else(
            || " No paid work.".to_owned(),
            |cap| format!(" Cost: up to {} {}.", cap.units, cap.unit.as_str()),
        );
        let what = self.what.trim_end_matches('.');
        match (self.phase, self.ends_at) {
            (OfferCardPhase::AgedOut, _) => format!(
                "{} asked to join: {what}.{artifact}{cost} It aged out; the room's host may reopen it.",
                self.agent_ref,
            ),
            (OfferCardPhase::Open, Some(ends_at)) => format!(
                "{} asks to join: {what}.{artifact}{cost} Join or not now; the room may vote. Open until {ends_at} unless engaged.",
                self.agent_ref,
            ),
            (OfferCardPhase::Open, None) => format!(
                "{} asks to join: {what}.{artifact}{cost} Join or not now.",
                self.agent_ref,
            ),
        }
    }
}
