//! The offer card's render-neutral payload and its write-free answer intent
//! (OF-530). Rendering belongs to clients (RD-18); the room's offer door
//! settles the answer.

use super::consent_eval::{
    ConsentActionKind, ConsentActionRequest, ensure_component_request, ensure_declared_action,
    lens_text,
};
use super::protocol::Of336ActionDescriptor;
use crate::error::GateError;
use crate::llm::run_admission::DeclaredMaximum;
use crate::memory::{Memory, MemoryResult};
use crate::workspace_roster::{
    OfferAnswer, OfferAnswerRequest, OfferCard, OfferSettlement, OfferState,
};
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};

pub const OFFER_JOIN_ACTION_ID: &str = "join";
pub const OFFER_NOT_NOW_ACTION_ID: &str = "not_now";

/// What a client draws for one open offer card: who asks, what it would do,
/// the artifact it attaches, what it would cost and who pays, and the two
/// verbs. Built from the host-held card, never from a client's copy.
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

impl OfferCardPayload {
    /// The payload of an open card. A settled card asks nothing.
    pub fn of(card: &OfferCard) -> Result<Self> {
        if !matches!(card.state, OfferState::Open { .. }) {
            return Err(Error::InvalidConfig(
                "only an open offer card is shown with its verbs".into(),
            ));
        }
        let payload = Self {
            card_id: card.offer_id.clone(),
            room_ref: card.room.to_hex(),
            thread_ref: card.branch.map(|branch| branch.to_hex()),
            agent_ref: card.agent.to_hex(),
            what: card.what.clone(),
            artifact_ref: card.artifact_ref.clone(),
            lease_cap: card.lease_cap.clone(),
            payer_ref: card.payer.map(|payer| payer.to_hex()),
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
        // A client that cannot draw the card shows this text instead.
        lens_text(self.fallback_text())?;
        Ok(())
    }

    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        vec![
            Of336ActionDescriptor {
                action_id: OFFER_JOIN_ACTION_ID.to_owned(),
                label: "Join".to_owned(),
                action: ConsentActionKind::Approve,
            },
            Of336ActionDescriptor {
                action_id: OFFER_NOT_NOW_ACTION_ID.to_owned(),
                label: "Not now".to_owned(),
                action: ConsentActionKind::Decline,
            },
        ]
    }

    /// A tap only emits an intent. It must target this card, name a declared
    /// verb, and come from `authenticated`, the actor whose credential the
    /// host verified; a voice label is never that credential.
    pub fn evaluate_action(
        &self,
        request: &ConsentActionRequest,
        authenticated: EntityId,
    ) -> Result<OfferAnswerIntent> {
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
        let action = match request.action {
            ConsentActionKind::Approve => OfferAnswer::Join,
            _ => OfferAnswer::NotNow,
        };
        Ok(OfferAnswerIntent {
            offer_id: self.card_id.clone(),
            action,
            answerer: authenticated,
            origin_component_id: self.card_id.clone(),
            origin_action_id: request.action_id.clone(),
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
        format!(
            "{} asks to join: {}.{artifact}{cost} Join or not now.",
            self.agent_ref,
            self.what.trim_end_matches('.'),
        )
    }
}
