//! Connector-neutral causal reaction ingress. Generic delivery is not a
//! provider generation; a connector worker must supply occurrence or origin.
use super::identity::{ReactionAcknowledgment, ReactionGeneration, bindings_in};
use super::{ReactionBody, ReactionChange, ReactionInput, ReactionState};
use crate::conversation::{AudienceCache, member_at_in, room_for_record_in};
use crate::conversation_dag::{actor_in_txn, require_type};
use crate::error::{Error, RecordError, Result};
use crate::registry::{
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_REACTION, ENTITY_TYPE_TURN,
};
use crate::surface_event::{
    SurfaceEvent, SurfaceEventAction, SurfaceInteractionKind, SurfaceSourceApp,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault, WriteActor};

fn invalid(why: &'static str) -> Error {
    RecordError::InvalidReactionBody(why).into()
}

/// A provider occurrence and a connector acknowledgment are different
/// causal facts. Delivery time/correlation_id never substitutes for either.
#[derive(Debug, Clone)]
pub enum ReactionIngress {
    ProviderAdd {
        message: EntityId,
        by: EntityId,
        glyph: String,
        occurred_at: u64,
        generation: ReactionGeneration,
        actor: WriteActor,
    },
    Echo {
        original: EntityId,
        message: EntityId,
        by: EntityId,
        glyph: String,
        generation: ReactionGeneration,
        actor: WriteActor,
    },
    Remove {
        message: EntityId,
        by: EntityId,
        glyph: String,
        generation: ReactionGeneration,
        actor: WriteActor,
    },
}

impl Vault {
    /// The host/adapter resolves connector identities, then invokes this
    /// single normalized ingress door. A missing causal field is a typed
    /// unresolved error, not an inferred toggle of a matching live tuple.
    pub fn ingest_reaction(&self, input: ReactionIngress) -> Result<ReactionChange> {
        match input {
            ReactionIngress::ProviderAdd {
                message,
                by,
                glyph,
                occurred_at,
                generation,
                actor,
            } => self.react(ReactionInput {
                message,
                by,
                glyph,
                occurred_at,
                external_id: Some(generation.into()),
                actor,
            }),
            ReactionIngress::Echo {
                original,
                message,
                by,
                glyph,
                generation,
                actor,
            } => self.acknowledge_reaction_asserted(
                ReactionAcknowledgment {
                    original,
                    generation,
                    actor,
                },
                Some((message, by, &glyph)),
            ),
            ReactionIngress::Remove {
                message,
                by,
                glyph,
                generation,
                actor,
            } => {
                let (canonical, commits) = self.with_write_txn(|txn| {
                    actor_in_txn(&self.store, txn, actor)?;
                    if actor.entity_ref() != by {
                        return Err(invalid("remover is not reactor"));
                    }
                    require_type(&self.store, txn, &by, ENTITY_TYPE_PERSON)?;
                    match live_entity_row_in_txn(&self.store, txn, &message)? {
                        LiveEntityRow::Live {
                            entity_type: ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN,
                            ..
                        } => {}
                        _ => {
                            return Err(invalid(
                                "external target is not a live conversation record",
                            ));
                        }
                    }
                    let room = room_for_record_in(self, txn, message)?
                        .ok_or(invalid("external target has no room"))?;
                    let metadata = crate::conversation::body_in(self, txn, room)?;
                    if metadata.kind != crate::conversation::ConversationKind::Mirror
                        || metadata
                            .external_id
                            .as_deref()
                            .and_then(|value| value.split_once(':'))
                            .is_none_or(|(connector, _)| connector != generation.connector)
                        || !AudienceCache::default().readable(self, txn, message, &[by])?
                    {
                        return Err(invalid("external removal is outside room audience"));
                    }
                    let bindings = bindings_in(&self.store, txn, &generation)?;
                    if bindings.is_empty() {
                        return Err(RecordError::ReactionNeedsReconciliation(
                            "external generation binding not yet materialized",
                        )
                        .into());
                    }
                    let mut commits = Vec::new();
                    let mut canonical = None;
                    for (_, receipt) in bindings {
                        if receipt.msg != message
                            || receipt.by != by
                            || receipt.glyph != glyph
                            || !member_at_in(self, txn, room, by, receipt.at)?
                        {
                            return Err(invalid(
                                "external removal differs from original generation",
                            ));
                        }
                        let id = receipt.reaction;
                        canonical =
                            Some(canonical.map_or(id, |previous: EntityId| previous.min(id)));
                        match live_entity_row_in_txn(&self.store, txn, &id)? {
                            LiveEntityRow::Live {
                                entity_type: ENTITY_TYPE_REACTION,
                                body,
                            } => {
                                let source = ReactionBody::from_bytes(&body)?;
                                if source.msg != message
                                    || source.by != by
                                    || source.glyph != glyph
                                    || source.at != receipt.at
                                {
                                    return Err(invalid("generation source differs from binding"));
                                }
                                if let Some(commit) = self.revoke_reaction_in_txn(txn, id, false)? {
                                    commits.push(commit);
                                }
                            }
                            LiveEntityRow::DeletedShell => {}
                            _ => return Err(invalid("generation source is unresolved")),
                        }
                    }
                    Ok((canonical.ok_or(invalid("empty generation"))?, commits))
                })?;
                for commit in &commits {
                    self.publish_reaction_revocation(commit)?;
                }
                Ok(ReactionChange {
                    id: canonical,
                    state: if commits.is_empty() {
                        ReactionState::Replayed
                    } else {
                        ReactionState::Revoked
                    },
                })
            }
        }
    }

    /// Normalize a provider event. Unlike a generic surface interaction,
    /// this reaction door requires explicit generation and add occurrence or
    /// the original outbound reaction ID for a provider echo.
    pub fn ingest_surface_reaction(
        &self,
        event: &SurfaceEvent,
        person: EntityId,
        actor: WriteActor,
    ) -> Result<ReactionChange> {
        let SurfaceEventAction::Interaction {
            interaction: SurfaceInteractionKind::Reaction,
            target_ref: Some(target),
            glyph: Some(glyph),
            external_reaction_id: Some(generation),
            reaction_occurred_at,
            reaction_origin_ref,
            revoked,
        } = &event.action
        else {
            return Err(invalid("surface event is not a reaction"));
        };
        if !event.foreign_inbound
            || event.event_id.trim().is_empty()
            || SurfaceSourceApp::from_channel_key(&event.channel) != Some(event.source.app)
            || actor.entity_ref() != person
        {
            return Err(invalid("unbound surface reaction"));
        }
        let message = EntityId::from_hex(target).map_err(|_| invalid("reaction target ID"))?;
        let generation = ReactionGeneration {
            connector: event.channel.clone(),
            id: generation.clone(),
        };
        let input = if *revoked {
            if reaction_origin_ref.is_some() || reaction_occurred_at.is_some() {
                return Err(invalid("removal carries add/echo causality"));
            }
            ReactionIngress::Remove {
                message,
                by: person,
                glyph: glyph.clone(),
                generation,
                actor,
            }
        } else if let Some(original) = reaction_origin_ref {
            if reaction_occurred_at.is_some() {
                return Err(invalid("echo carries new-add occurrence"));
            }
            ReactionIngress::Echo {
                original: EntityId::from_hex(original).map_err(|_| invalid("echo original ID"))?,
                message,
                by: person,
                glyph: glyph.clone(),
                generation,
                actor,
            }
        } else if let Some(occurred_at) = reaction_occurred_at {
            ReactionIngress::ProviderAdd {
                message,
                by: person,
                glyph: glyph.clone(),
                occurred_at: *occurred_at,
                generation,
                actor,
            }
        } else {
            return Err(RecordError::ReactionNeedsReconciliation(
                "provider add needs occurrence or echo needs original add ID",
            )
            .into());
        };
        self.ingest_reaction(input)
    }
}
