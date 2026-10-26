//! LINE chats the bot was seen in, and the owner's optional offers to bind
//! one to an agent (FIX 3115). A `join` and a message from a group or room
//! no identity serves are recorded once per (bot, chat) as an observed
//! claim, so the owner can see the chat and bind it through the ordinary
//! provision door. An observation is a fact, never a binding, and nothing
//! waits on it: a message keeps routing per sender either way.

use serde::{Deserialize, Serialize};

use super::shared_validate::normalize_line_chat_id;
use super::{LINE_CHANNEL, LineChat, LineOfficialAccountAdapter};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::SURFACE_PROVIDER_INBOUND_ACTOR;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

/// Predicate of one observed LINE chat (FIX 3115).
pub const LINE_CHAT_OBSERVATION_PREDICATE: &str = "channel_identity.line_chat_observed";

/// Domain of an observation's id: one per bot destination, chat kind and
/// chat id, whoever wrote and whichever event showed it.
const LINE_CHAT_OBSERVATION_DOMAIN: &[u8] = b"oneiron:line-chat-observation:v1";

/// One LINE group or room the bot was seen in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChatObservation {
    /// The bot (the webhook `destination`) the chat was seen on.
    pub destination: String,
    pub chat: LineChat,
    /// When the chat was first seen, Unix seconds at receipt.
    pub observed_at: u64,
    /// The archived provider event that first showed it.
    pub payload_ref: String,
}

/// An optional offer to bind one observed chat to an agent. Accepting it
/// provisions the chat's own route key through the owner's provision door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChatBindingOffer {
    /// The observation an accept names.
    pub observation_ref: EntityId,
    pub observation: LineChatObservation,
    /// The chat's own route key on the bot: what a bind provisions.
    pub address_or_handle: String,
    /// The identity that already holds that route key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_identity_ref: Option<EntityId>,
}

impl Vault {
    /// Records that the bot `destination` saw `chat` (FIX 3115), once per
    /// (bot, chat): the first sighting stays and a later one changes
    /// nothing. Archive the event first; the archive keeps the
    /// provider-inbound machine this observation is about.
    ///
    /// # Errors
    /// The chat id is not a LINE group or room id, or the write fails.
    pub fn observe_line_chat(
        &self,
        destination: &str,
        chat: &LineChat,
        payload_ref: &str,
        now: u64,
    ) -> Result<EntityId> {
        let chat = LineChat::new(chat.kind, normalize_line_chat_id(&chat.id, chat.kind)?);
        let id = line_chat_observation_ref(destination, &chat)?;
        // A chat already seen costs a read, never the writer.
        if self.line_chat_observation(&id)?.is_some() {
            return Ok(id);
        }
        let observation = LineChatObservation {
            destination: destination.to_owned(),
            chat,
            observed_at: now,
            payload_ref: payload_ref.to_owned(),
        };
        let value = rmpv::ext::to_value(&observation)
            .map_err(|_| Error::InvariantViolation("LINE chat observation did not encode"))?;
        let mut body = ClaimBody::new(
            LINE_CHAT_OBSERVATION_PREDICATE,
            ClaimSubject::Entity(provider_inbound_actor()?),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Observed);
        let mut wtxn = self.store.env.write_txn()?;
        if self.get_claim_in_txn(&wtxn, &id)?.is_none() {
            self.put_claim_in_txn(
                &mut wtxn,
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            wtxn.commit()?;
        }
        Ok(id)
    }

    /// One observation by its ref, or `None` when the ref names no live
    /// LINE chat observation.
    ///
    /// # Errors
    /// The read fails.
    pub fn line_chat_observation(
        &self,
        observation_ref: &EntityId,
    ) -> Result<Option<LineChatObservation>> {
        let subject = provider_inbound_actor()?;
        let rtxn = self.store.env.read_txn()?;
        let Some(body) = self.get_claim_in_txn(&rtxn, observation_ref)? else {
            return Ok(None);
        };
        Ok(observation_of(&body, &subject).filter(|observation| {
            line_chat_observation_ref(&observation.destination, &observation.chat).ok()
                == Some(*observation_ref)
        }))
    }

    /// Every chat the adapter's bot was seen in, each as an optional bind
    /// offer naming the route key a bind provisions and the identity that
    /// already holds it, if any. Nothing expires and nothing is withheld.
    ///
    /// # Errors
    /// A read fails.
    pub fn line_chat_binding_offers(
        &self,
        adapter: &LineOfficialAccountAdapter,
    ) -> Result<Vec<LineChatBindingOffer>> {
        let destination = adapter.config().messaging_api_destination();
        let subject = provider_inbound_actor()?;
        let mut observed = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            self.for_each_readable_claim_with_predicate_in_txn(
                &rtxn,
                LINE_CHAT_OBSERVATION_PREDICATE,
                |observation_ref, body| {
                    if let Some(observation) = observation_of(&body, &subject)
                        && observation.destination == destination
                    {
                        observed.push((observation_ref, observation));
                    }
                    Ok(())
                },
            )?;
        }
        observed
            .into_iter()
            .map(|(observation_ref, observation)| {
                let address_or_handle = adapter.address_for_line_chat(&observation.chat)?;
                let bound_identity_ref = self
                    .channel_identity_by_assignment(LINE_CHANNEL, &address_or_handle)?
                    .map(|(identity_ref, _)| identity_ref);
                Ok(LineChatBindingOffer {
                    observation_ref,
                    observation,
                    address_or_handle,
                    bound_identity_ref,
                })
            })
            .collect()
    }
}

/// The derived ref of one (bot, chat) observation.
fn line_chat_observation_ref(destination: &str, chat: &LineChat) -> Result<EntityId> {
    EntityId::derive(
        LINE_CHAT_OBSERVATION_DOMAIN,
        &[
            destination.as_bytes(),
            chat.kind.as_str().as_bytes(),
            chat.id.as_bytes(),
        ],
    )
}

/// The provider-inbound machine every archived provider event is kept
/// under: the subject of every chat observation.
fn provider_inbound_actor() -> Result<EntityId> {
    EntityId::derive(SURFACE_PROVIDER_INBOUND_ACTOR, &[])
}

fn observation_of(body: &ClaimBody, subject: &EntityId) -> Option<LineChatObservation> {
    if body.predicate != LINE_CHAT_OBSERVATION_PREDICATE
        || body.subject != ClaimSubject::Entity(*subject)
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return None;
    }
    rmpv::ext::from_value(body.value.clone()).ok()
}
