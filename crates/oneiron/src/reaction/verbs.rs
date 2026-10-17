//! `vault.messages.react` (OF-181): the one typed door that a reaction
//! button, an agent's call and `POST /v1/core/messages/{m}/reactions` share.
//! A local change writes as the bound actor, who must be the reacting
//! person. A provider's reaction is connector ingress: only a host admits it
//! (the served door checks owner grade), and the mirror MACHINE writes it,
//! so an embedded Memory refuses it.

use serde::{Deserialize, Serialize};

use super::{ReactionChange, ReactionExternalId, ReactionIngress, ReactionInput};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault, WriteActor};

/// One reaction change on a MESSAGE or a DAG TURN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionRequest {
    /// The MESSAGE or TURN reacted to.
    pub message: String,
    /// The reacting PERSON.
    pub by: String,
    pub glyph: String,
    /// When the person reacted, unix seconds. A local add needs it.
    #[serde(default)]
    pub occurred_at: Option<u64>,
    /// `true` removes the person's live reaction with this glyph.
    #[serde(default)]
    pub remove: bool,
    /// A provider's reaction, resolved to engine ids by its connector host.
    #[serde(default)]
    pub external: Option<MessageReactionExternal>,
}

/// The provider side of a mirrored reaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionExternal {
    pub connector: String,
    /// The provider's generation id.
    pub id: String,
    /// The first-party reaction claim a provider echo answers.
    #[serde(default)]
    pub origin: Option<String>,
}

/// The reaction claim a change resolved to, and its event:
/// `reaction.put`, `reaction.revoked` or `reaction.replayed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageReactionReceipt {
    pub id: String,
    pub event: String,
}

impl From<ReactionChange> for MessageReactionReceipt {
    fn from(change: ReactionChange) -> Self {
        Self {
            id: change.id.to_hex(),
            event: change.state.event().to_owned(),
        }
    }
}

impl MessageReactionRequest {
    /// Puts or removes the reaction as `actor`, who must be the reacting
    /// person; the vault revalidates the person and the room audience.
    /// # Errors
    /// An external request, a bad id, an actor other than `by`, an add with
    /// no occurrence, or the vault's refusal.
    pub fn apply_as(&self, vault: &Vault, actor: WriteActor) -> MemoryResult<ReactionChange> {
        if self.external.is_some() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a provider reaction is connector ingress, which only its host admits",
                &[],
            ));
        }
        let message = EntityId::from_hex(&self.message)?;
        let by = EntityId::from_hex(&self.by)?;
        if actor.entity_ref() != by {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only the reacting person puts or removes their reaction",
                &[],
            ));
        }
        if self.remove {
            return Ok(vault.remove_reaction(message, by, &self.glyph, actor)?);
        }
        let occurred_at = self
            .occurred_at
            .ok_or_else(|| MemoryError::bad_request("occurred_at is required"))?;
        Ok(vault.react(ReactionInput {
            message,
            by,
            glyph: self.glyph.clone(),
            occurred_at,
            actor,
        })?)
    }

    /// The provider fact an external request carries: an add needs its
    /// occurrence, an echo its origin, a removal neither. The caller is the
    /// host that admitted the connector's ingress.
    /// # Errors
    /// No `external`, a bad id, or a combination that is no provider fact.
    pub fn ingress(&self) -> MemoryResult<ReactionIngress> {
        let external = self
            .external
            .as_ref()
            .ok_or_else(|| MemoryError::bad_request("a provider reaction names its external"))?;
        let message = EntityId::from_hex(&self.message)?;
        let by = EntityId::from_hex(&self.by)?;
        let generation = ReactionExternalId {
            connector: external.connector.clone(),
            id: external.id.clone(),
        };
        let glyph = self.glyph.clone();
        Ok(
            match (self.remove, external.origin.as_deref(), self.occurred_at) {
                (true, None, _) => ReactionIngress::Remove {
                    message,
                    by,
                    glyph,
                    generation,
                },
                (false, Some(origin), _) => ReactionIngress::Echo {
                    original: EntityId::from_hex(origin)?,
                    message,
                    by,
                    glyph,
                    generation,
                },
                (false, None, Some(occurred_at)) => ReactionIngress::ProviderAdd {
                    message,
                    by,
                    glyph,
                    occurred_at,
                    generation,
                },
                _ => {
                    return Err(MemoryError::bad_request(
                        "a provider add needs occurred_at, an echo origin, a removal neither",
                    ));
                }
            },
        )
    }
}

impl Memory<'_> {
    /// `vault.messages.react`: puts or removes the bound actor's own
    /// reaction. Provider ingress is the served door's; here it is refused.
    /// # Errors
    /// As [`MessageReactionRequest::apply_as`].
    pub fn messages_react(
        &self,
        input: &MessageReactionRequest,
    ) -> MemoryResult<MessageReactionReceipt> {
        let actor = WriteActor::new(self.actor(), self.actor_class());
        Ok(input.apply_as(self.vault(), actor)?.into())
    }
}
