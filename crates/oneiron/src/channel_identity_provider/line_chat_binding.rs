//! LINE chats the bot was seen in, and the owner's optional offers to bind
//! one to an agent (FIX 3115). A `join` and a message from a group or room
//! no identity serves are recorded once per (bot, chat) as an observed
//! claim, so the owner can see the chat and bind it through the ordinary
//! provision door. An observation is a fact, never a binding, and nothing
//! waits on it: a message keeps routing per sender either way. Its id is
//! opaque (FIX 10807): nothing about a chat confirms that it was seen.

use serde::{Deserialize, Serialize};

use super::shared_validate::{
    MAX_LINE_COMPONENT_BYTES, normalize_line_chat_id, normalize_line_user_like_id,
};
use super::{LINE_CHANNEL, LineChat, LineOfficialAccountAdapter};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::SURFACE_PROVIDER_INBOUND_ACTOR;
use crate::error::{Error, Result};
use crate::surface_event::PROVIDER_EVENT_REF_PREFIX;
use crate::temporal::TimeRange;

/// Predicate of one observed LINE chat (FIX 3115).
pub const LINE_CHAT_OBSERVATION_PREDICATE: &str = "channel_identity.line_chat_observed";

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
    /// nothing. A new sighting gets a fresh opaque id (FIX 10807). Archive
    /// the event first; the archive keeps the provider-inbound machine this
    /// observation is about.
    ///
    /// # Errors
    /// The bot is not a LINE bot id, the chat id is not a LINE group or room
    /// id, or the write fails.
    pub fn observe_line_chat(
        &self,
        destination: &str,
        chat: &LineChat,
        payload_ref: &str,
        now: u64,
    ) -> Result<EntityId> {
        let destination = normalize_line_user_like_id(
            destination,
            "LINE OA Messaging API destination",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        let chat = LineChat::new(chat.kind, normalize_line_chat_id(&chat.id, chat.kind)?);
        let subject = provider_inbound_actor()?;
        // A chat already seen costs a read, never the writer.
        {
            let rtxn = self.store.env.read_txn()?;
            if let Some(id) =
                self.line_chat_observed_in_txn(&rtxn, &subject, &destination, &chat)?
            {
                return Ok(id);
            }
        }
        let observation = LineChatObservation {
            destination,
            chat,
            observed_at: now,
            payload_ref: payload_ref.to_owned(),
        };
        let value = rmpv::ext::to_value(&observation)
            .map_err(|_| Error::InvariantViolation("LINE chat observation did not encode"))?;
        let mut body = ClaimBody::new(
            LINE_CHAT_OBSERVATION_PREDICATE,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Observed);
        let mut wtxn = self.store.env.write_txn()?;
        // The first sighting stays under the writer too.
        if let Some(id) = self.line_chat_observed_in_txn(
            &wtxn,
            &subject,
            &observation.destination,
            &observation.chat,
        )? {
            return Ok(id);
        }
        let id = self.store.clock.entity_id()?;
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
        Ok(id)
    }

    /// The live observation of `chat` on the bot `destination` in `txn`, if
    /// one stands: found by its value, never by a key the chat derives.
    fn line_chat_observed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EntityId,
        destination: &str,
        chat: &LineChat,
    ) -> Result<Option<EntityId>> {
        let mut found = None;
        self.for_each_readable_claim_with_predicate_in_txn(
            txn,
            LINE_CHAT_OBSERVATION_PREDICATE,
            |observation_ref, body| {
                if found.is_none()
                    && let Some(observation) = observation_of(&body, subject)
                    && observation.destination == destination
                    && observation.chat == *chat
                {
                    found = Some(observation_ref);
                }
                Ok(())
            },
        )?;
        Ok(found)
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
        Ok(observation_of(&body, &subject))
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

/// The provider-inbound machine every archived provider event is kept
/// under: the subject of every chat observation.
fn provider_inbound_actor() -> Result<EntityId> {
    EntityId::derive(SURFACE_PROVIDER_INBOUND_ACTOR, &[])
}

/// Whether `predicate` is the LINE chat observation family's one predicate
/// (FIX 10810): a family of its own, apart from the ChannelIdentity record
/// fields.
#[must_use]
pub fn is_line_chat_observation_claim_predicate(predicate: &str) -> bool {
    predicate == LINE_CHAT_OBSERVATION_PREDICATE
}

/// The structural door of one observation claim (FIX 10810): it is about the
/// provider-inbound machine, and its value is a [`LineChatObservation`]
/// whose bot, chat and archived event are in intake's own shapes.
pub(crate) fn validate_line_chat_observation_claim_structure(body: &ClaimBody) -> Result<()> {
    let invalid = || Error::InvalidClaimBody("LINE chat observation claim structure is invalid");
    if body.subject != ClaimSubject::Entity(provider_inbound_actor()?) {
        return Err(invalid());
    }
    let observation: LineChatObservation =
        rmpv::ext::from_value(body.value.clone()).map_err(|_| invalid())?;
    let destination = normalize_line_user_like_id(
        &observation.destination,
        "LINE OA Messaging API destination",
        MAX_LINE_COMPONENT_BYTES,
    )
    .map_err(|_| invalid())?;
    let chat_id = normalize_line_chat_id(&observation.chat.id, observation.chat.kind)
        .map_err(|_| invalid())?;
    let archived = observation
        .payload_ref
        .strip_prefix(PROVIDER_EVENT_REF_PREFIX)
        .is_some_and(|rest| !rest.is_empty());
    if destination != observation.destination || chat_id != observation.chat.id || !archived {
        return Err(invalid());
    }
    Ok(())
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
