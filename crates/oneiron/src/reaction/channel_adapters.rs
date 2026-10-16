//! Channel-specific reaction forms. LINE Messaging API and Messages for Business
//! have no message-reaction verb; stickers and new messages are not substitutes.
use super::chain::{admission_in, reactions_on_in};
use super::write::invalid;
use super::{ReactionChange, ReactionExternalId, ReactionIngress, ReactionOutboundAttempt};
use crate::outbound::{OutboundDeliverySemanticsKind, outbound_capability_manifest};
use crate::{EntityId, Result, Vault};
use serde::Serialize;

/// Classic iMessage associated-message types, in provider code order.
pub const IMESSAGE_TAPBACK_GLYPHS: [&str; 6] = ["❤️", "👍", "👎", "😂", "‼️", "❓"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IMessageTapback {
    Love,
    Like,
    Dislike,
    Laugh,
    Emphasize,
    Question,
}

impl IMessageTapback {
    const ALL: [Self; 6] = [
        Self::Love,
        Self::Like,
        Self::Dislike,
        Self::Laugh,
        Self::Emphasize,
        Self::Question,
    ];

    #[must_use]
    pub fn glyph(self) -> &'static str {
        IMESSAGE_TAPBACK_GLYPHS[self as usize]
    }

    pub fn from_glyph(glyph: &str) -> Result<Self> {
        let glyph = match glyph {
            "❤" => "❤️",
            "‼" => "‼️",
            other => other,
        };
        Self::ALL
            .into_iter()
            .find(|tapback| tapback.glyph() == glyph)
            .ok_or_else(|| invalid("unsupported iMessage tapback glyph"))
    }

    /// 2000..=2005 add; 3000..=3005 remove. Other associated messages
    /// (including stickers) are not silently interpreted as classic tapbacks.
    pub fn from_associated_message_type(kind: u16) -> Result<(Self, bool)> {
        let (index, removed) = match kind {
            2000..=2005 => (kind - 2000, false),
            3000..=3005 => (kind - 3000, true),
            _ => return Err(invalid("unsupported iMessage associated message type")),
        };
        Ok((Self::ALL[index as usize], removed))
    }

    #[must_use]
    pub fn associated_message_type(self, removed: bool) -> u16 {
        (if removed { 3000 } else { 2000 }) + self as u16
    }
}

/// Host-resolved identities and provider generation, not a webhook delivery id.
#[derive(Debug, Clone)]
pub struct IMessageTapbackInput {
    pub message: EntityId,
    pub by: EntityId,
    pub associated_message_type: u16,
    /// On remove this is the generation of the add being removed.
    pub generation: String,
    pub occurred_at: Option<u64>,
    pub origin: Option<EntityId>,
}

/// The bridge resolves `message` to its provider message/part handle before
/// execution. No message text or credentials are copied into the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IMessageTapbackOperation {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub associated_message_type: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReactionChannelCapability {
    pub connector: String,
    pub send: bool,
    pub receive: bool,
    pub emoji_vocabulary: Option<serde_json::Value>,
}

/// Reaction support, distinct from permission to execute. Vocabulary comes
/// from the outbound manifest, not a second independently maintained list.
#[must_use]
pub fn reaction_channel_capability(connector: &str) -> Option<ReactionChannelCapability> {
    let manifest = outbound_capability_manifest(connector)?;
    let react = manifest.verbs.iter().find(|verb| {
        verb.kind == "react"
            && verb.delivery_semantics.kind == OutboundDeliverySemanticsKind::ReactionTarget
    });
    Some(ReactionChannelCapability {
        connector: manifest.connector.clone(),
        send: react.is_some(),
        receive: matches!(
            manifest.connector.as_str(),
            "telegram" | "slack" | "discord" | "imessage_bridge" | "in_app"
        ),
        emoji_vocabulary: react.and_then(|verb| verb.params.get("emoji_vocabulary").cloned()),
    })
}

pub(super) fn channel_glyph(connector: &str, glyph: &str) -> Result<String> {
    match connector {
        "line" => Err(invalid(
            "LINE Messaging API does not support message reactions",
        )),
        "imessage_mfb" => Err(invalid("Messages for Business does not support tapbacks")),
        "imessage_bridge" => Ok(IMessageTapback::from_glyph(glyph)?.glyph().to_owned()),
        _ => Ok(glyph.to_owned()),
    }
}

pub(super) fn replace_tapbacks_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fold: &crate::authority::AuthorityFold,
    message: EntityId,
    by: EntityId,
    glyph: &str,
    occurred_at: u64,
) -> Result<Option<EntityId>> {
    let rows = reactions_on_in(vault, txn, fold, message)?;
    let others: Vec<_> = rows
        .iter()
        .filter(|row| row.live() && row.value.by == by && row.value.glyph != glyph)
        .collect();
    if let Some(newer) = others
        .iter()
        .find(|row| row.value.occurred_at > occurred_at)
    {
        return Ok(Some(newer.id));
    }
    let now = vault.store.clock.now_recorded_at();
    for row in others {
        super::write::retract_in_txn(vault, txn, row, now)?;
    }
    Ok(None)
}

pub(super) fn first_party_glyph_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    glyph: &str,
) -> Result<String> {
    let body = crate::conversation::body_in(vault, txn, room)?;
    if body.kind == crate::conversation::ConversationKind::Mirror
        && body
            .external_id
            .as_deref()
            .and_then(|external| external.split_once(':'))
            .is_some_and(|(connector, _)| connector == "imessage_bridge")
    {
        return channel_glyph("imessage_bridge", glyph);
    }
    Ok(glyph.to_owned())
}

impl Vault {
    /// Classic bridge tapbacks enter through the same signed mirror door as
    /// all received reactions, including generation replay and echo binding.
    pub fn ingest_imessage_tapback(&self, input: IMessageTapbackInput) -> Result<ReactionChange> {
        let (tapback, removed) =
            IMessageTapback::from_associated_message_type(input.associated_message_type)?;
        let generation = ReactionExternalId {
            connector: "imessage_bridge".to_owned(),
            id: input.generation,
        };
        let glyph = tapback.glyph().to_owned();
        let ingress = match (removed, input.origin, input.occurred_at) {
            (true, None, None) => ReactionIngress::Remove {
                message: input.message,
                by: input.by,
                glyph,
                generation,
            },
            (false, Some(original), None) => ReactionIngress::Echo {
                original,
                message: input.message,
                by: input.by,
                glyph,
                generation,
            },
            (false, None, Some(occurred_at)) => ReactionIngress::ProviderAdd {
                message: input.message,
                by: input.by,
                glyph,
                occurred_at,
                generation,
            },
            _ => return Err(invalid("tapback mixes add, echo and removal")),
        };
        self.ingest_reaction(ingress)
    }

    /// Resolves a queued bridge reaction against current claims. Erased,
    /// held or superseded puts are not sent. The adapter still owns host
    /// consent, provider addressing and the ordinary outbound dispatch door.
    pub fn imessage_tapback_for_attempt(
        &self,
        attempt: &ReactionOutboundAttempt,
    ) -> Result<Option<IMessageTapbackOperation>> {
        if attempt.connector != "imessage_bridge" {
            return Err(invalid(
                "reaction attempt is not an iMessage bridge tapback",
            ));
        }
        let txn = self.store.env.read_txn()?;
        let Some(body) = self.get_claim_for_effect_in_txn(&txn, &attempt.reaction)? else {
            return Ok(None);
        };
        let crate::claim::ClaimSubject::Entity(message) = body.subject else {
            return Ok(None);
        };
        let fold = admission_in(self, &txn)?;
        let rows = reactions_on_in(self, &txn, &fold, message)?;
        let Some(row) = rows.iter().find(|row| row.id == attempt.reaction) else {
            return Ok(None);
        };
        if (attempt.remove && row.retracted_at().is_none())
            || (!attempt.remove && (!row.live() || !row.first_party()))
        {
            return Ok(None);
        }
        // An old operation must not replace or remove a newer tapback.
        if rows.iter().any(|other| {
            other.id != row.id
                && other.live()
                && other.value.by == row.value.by
                && (attempt.remove || (other.learned_at, other.id) > (row.learned_at, row.id))
        }) {
            return Ok(None);
        }
        let room = super::write::target_room_in(self, &txn, message)?;
        let room_body = crate::conversation::body_in(self, &txn, room)?;
        if room_body.kind != crate::conversation::ConversationKind::Mirror
            || room_body.external_id.as_deref() != Some(attempt.room_external_id.as_str())
            || !attempt.room_external_id.starts_with("imessage_bridge:")
        {
            return Err(invalid("tapback attempt differs from its mirror room"));
        }
        Ok(Some(IMessageTapbackOperation {
            reaction: row.id,
            message,
            by: row.value.by,
            associated_message_type: IMessageTapback::from_glyph(&row.value.glyph)?
                .associated_message_type(attempt.remove),
        }))
    }
}
