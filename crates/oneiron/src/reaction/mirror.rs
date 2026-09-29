//! Connector-mirrored reactions (connector in). The host resolves provider
//! identities, then calls one normalized door. Every mirrored claim is written
//! by the engine's conversation-mirror MACHINE through the signed-writer path:
//! the claim door refuses an unsigned MACHINE claim (#1183).
//!
//! A provider generation is the connector's id for one add. A replayed add or
//! remove of a known generation is idempotent, a provider remove retracts the
//! claim its generation names, and a later re-add carries a new generation and
//! becomes a new claim in the chain. The provider's echo of our own reaction
//! binds its generation to the original claim with a
//! `conversation.reaction.echo` claim about it, never a second reaction.
use super::chain::{StoredReaction, admission_in, chain_in, echoes_in, names_generation};
use super::value::{PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId, ReactionValue};
use super::write::{
    ReactionChange, ReactionState, invalid, require_occurrence, require_reactor_in, retract_in_txn,
    target_room_in, write_reaction_in_txn,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::entity_id::derived_domains::CONVERSATION_MIRROR_ACTOR;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::surface_event::{
    SurfaceEvent, SurfaceEventAction, SurfaceInteractionKind, SurfaceSourceApp,
};
use crate::{
    ClaimCandidate, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// A provider fact about one reaction, already resolved to engine ids.
#[derive(Debug, Clone)]
pub enum ReactionIngress {
    /// The person added the glyph on the provider.
    ProviderAdd {
        message: EntityId,
        by: EntityId,
        glyph: String,
        occurred_at: u64,
        generation: ReactionExternalId,
    },
    /// The provider's echo of the first-party reaction claim `original`.
    Echo {
        original: EntityId,
        message: EntityId,
        by: EntityId,
        glyph: String,
        generation: ReactionExternalId,
    },
    /// The provider removed the add `generation` names.
    Remove {
        message: EntityId,
        by: EntityId,
        glyph: String,
        generation: ReactionExternalId,
    },
}

/// The engine's conversation-mirror write actor: one deterministic MACHINE.
pub fn conversation_mirror_actor_id() -> Result<EntityId> {
    EntityId::derive(CONVERSATION_MIRROR_ACTOR, &[])
}

pub(crate) fn ensure_conversation_mirror_actor(vault: &Vault, now: u64) -> Result<EntityId> {
    let id = conversation_mirror_actor_id()?;
    if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_MACHINE) {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(
                Value::from("name"),
                Value::from("conversation mirror"),
            )]),
        )
        .map_err(|_| Error::InvariantViolation("actor body did not encode"))?;
        vault.put_entity(
            &id,
            ENTITY_TYPE_MACHINE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
    }
    Ok(id)
}

fn mirror_envelope(generation: &ReactionExternalId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(conversation_mirror_actor_id()?, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("kind"),
                Value::from("conversation_reaction_mirror"),
            ),
            (
                Value::from("connector"),
                Value::from(generation.connector.as_str()),
            ),
        ]))?,
        ClaimApprovalStatus::Auto,
    ))
}

fn unresolved(reason: &'static str) -> Error {
    Error::Record(RecordError::ConversationState(reason))
}

/// A mirrored fact lands only in the mirror room of the connector that
/// reported it, for a person who may still write there.
fn require_mirror_target(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
    by: EntityId,
    generation: &ReactionExternalId,
) -> Result<EntityId> {
    generation.validate()?;
    let room = target_room_in(vault, txn, message)?;
    let body = crate::conversation::body_in(vault, txn, room)?;
    if body.kind != crate::conversation::ConversationKind::Mirror
        || body
            .external_id
            .as_deref()
            .and_then(|external| external.split_once(':'))
            .is_none_or(|(connector, _)| connector != generation.connector)
    {
        return Err(invalid("mirrored reaction is outside its connector's room"));
    }
    require_reactor_in(vault, txn, room, by)?;
    Ok(room)
}

fn bind_echo_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reaction: EntityId,
    generation: &ReactionExternalId,
    now: u64,
) -> Result<()> {
    let id = vault.store.clock.entity_id()?;
    let candidate = ClaimCandidate::new(
        PREDICATE_CONVERSATION_REACTION_ECHO,
        ClaimSubject::Entity(reaction),
        generation.to_value(),
        1.0,
    )
    .with_salience(0.0);
    let mut envelope = mirror_envelope(generation)?;
    vault.sign_retained_machine_claim_in_txn(txn, &id, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply(txn)?;
    Ok(())
}

fn replayed(id: EntityId) -> ReactionChange {
    ReactionChange {
        id,
        state: ReactionState::Replayed,
    }
}

/// The chain row a generation already names, live or retracted.
fn named_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &crate::authority::AuthorityFold,
    chain: &[StoredReaction],
    generation: &ReactionExternalId,
) -> Result<Option<usize>> {
    for (index, row) in chain.iter().enumerate() {
        if names_generation(vault, txn, fold, row, generation)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

impl Vault {
    /// The single normalized connector-in door for reactions.
    pub fn ingest_reaction(&self, input: ReactionIngress) -> Result<ReactionChange> {
        self.with_write_txn(|txn| {
            let fold = admission_in(self, txn)?;
            match &input {
                ReactionIngress::ProviderAdd {
                    message,
                    by,
                    glyph,
                    occurred_at,
                    generation,
                } => {
                    require_mirror_target(self, txn, *message, *by, generation)?;
                    let now = require_occurrence(self, *occurred_at)?;
                    let chain = chain_in(self, txn, &fold, *message, *by, glyph)?;
                    if let Some(index) = named_in(self, txn, &fold, &chain, generation)? {
                        return Ok(replayed(chain[index].id));
                    }
                    if let Some(live) = chain.iter().rev().find(|row| row.live()) {
                        // The provider shows our own live reaction: an echo that
                        // arrived without its origin binds to it once.
                        if live.first_party() && echoes_in(self, txn, &fold, live.id)?.is_empty() {
                            bind_echo_in_txn(self, txn, live.id, generation, now)?;
                            return Ok(replayed(live.id));
                        }
                        // The live claim names another generation. A provider
                        // holds one add per person and glyph, so a newer add means
                        // the older one was removed there; an older add is stale.
                        if *occurred_at < live.value.occurred_at {
                            return Ok(replayed(live.id));
                        }
                        retract_in_txn(self, txn, live, now)?;
                    }
                    let value = ReactionValue {
                        glyph: glyph.clone(),
                        occurred_at: *occurred_at,
                        by: *by,
                        external_id: Some(generation.clone()),
                    };
                    let envelope = mirror_envelope(generation)?;
                    let id = write_reaction_in_txn(self, txn, *message, &value, envelope, now)?;
                    Ok(ReactionChange {
                        id,
                        state: ReactionState::Put,
                    })
                }
                ReactionIngress::Echo {
                    original,
                    message,
                    by,
                    glyph,
                    generation,
                } => {
                    require_mirror_target(self, txn, *message, *by, generation)?;
                    let chain = chain_in(self, txn, &fold, *message, *by, glyph)?;
                    let Some(row) = chain.iter().find(|row| row.id == *original) else {
                        return Err(invalid("echo differs from its original reaction"));
                    };
                    if let Some(index) = named_in(self, txn, &fold, &chain, generation)? {
                        if chain[index].id != row.id {
                            return Err(invalid("provider generation names another reaction"));
                        }
                        return Ok(replayed(row.id));
                    }
                    if !row.first_party() || !echoes_in(self, txn, &fold, row.id)?.is_empty() {
                        return Err(invalid(
                            "echo target is already bound to a provider generation",
                        ));
                    }
                    let now = self.store.clock.now_recorded_at();
                    bind_echo_in_txn(self, txn, row.id, generation, now)?;
                    Ok(replayed(row.id))
                }
                ReactionIngress::Remove {
                    message,
                    by,
                    glyph,
                    generation,
                } => {
                    require_mirror_target(self, txn, *message, *by, generation)?;
                    let chain = chain_in(self, txn, &fold, *message, *by, glyph)?;
                    let Some(index) = named_in(self, txn, &fold, &chain, generation)? else {
                        return Err(unresolved("reaction generation is not yet materialized"));
                    };
                    let row = &chain[index];
                    if !row.live() {
                        return Ok(replayed(row.id));
                    }
                    retract_in_txn(self, txn, row, self.store.clock.now_recorded_at())?;
                    Ok(ReactionChange {
                        id: row.id,
                        state: ReactionState::Revoked,
                    })
                }
            }
        })
    }

    /// Normalizes one inbound provider reaction event for `person`, the PERSON
    /// the host resolved the provider user to. A delivery id is never a
    /// generation: the event must carry the provider's reaction identity.
    pub fn ingest_surface_reaction(
        &self,
        event: &SurfaceEvent,
        person: EntityId,
    ) -> Result<ReactionChange> {
        let SurfaceEventAction::Interaction {
            interaction: SurfaceInteractionKind::Reaction,
            target_ref: Some(target),
            reaction: Some(reaction),
        } = &event.action
        else {
            return Err(invalid("surface event is not a reaction"));
        };
        if !event.foreign_inbound
            || SurfaceSourceApp::from_channel_key(&event.channel) != Some(event.source.app)
        {
            return Err(invalid("unbound surface reaction"));
        }
        let message = EntityId::from_hex(target).map_err(|_| invalid("reaction target id"))?;
        let generation = ReactionExternalId {
            connector: event.channel.clone(),
            id: reaction.external_id.clone(),
        };
        let glyph = reaction.glyph.clone();
        let input = match (reaction.removed, &reaction.origin_ref, reaction.occurred_at) {
            (true, None, None) => ReactionIngress::Remove {
                message,
                by: person,
                glyph,
                generation,
            },
            (false, Some(origin), None) => ReactionIngress::Echo {
                original: EntityId::from_hex(origin).map_err(|_| invalid("echo origin id"))?,
                message,
                by: person,
                glyph,
                generation,
            },
            (false, None, Some(occurred_at)) => ReactionIngress::ProviderAdd {
                message,
                by: person,
                glyph,
                occurred_at,
                generation,
            },
            (false, None, None) => {
                return Err(unresolved("provider add needs its occurrence time"));
            }
            _ => return Err(invalid("surface reaction mixes add, echo and removal")),
        };
        self.ingest_reaction(input)
    }
}
