//! Mirrored reaction ingress through the normalized SurfaceEvent contract.
use super::write::external_key;
use super::{ReactionBody, ReactionChange, ReactionExternalId, ReactionInput, ReactionState};
use crate::conversation::{AudienceCache, member_at_in, room_for_record_in};
use crate::conversation_dag::{actor_in_txn, require_type};
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::surface_event::{
    SurfaceEvent, SurfaceEventAction, SurfaceInteractionKind, SurfaceSourceApp,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault, WriteActor};

fn invalid(why: &'static str) -> Error {
    RecordError::InvalidReactionBody(why).into()
}

impl Vault {
    /// A connector worker calls this after resolving the provider user to a
    /// PERSON and binding an actor credential. The event's stable external id
    /// is the reaction identity; redeliveries never toggle it again.
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
            external_reaction_id: Some(external_reaction_id),
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
        let message =
            EntityId::from_hex(target).map_err(|_| invalid("target must be a MESSAGE id"))?;
        let ext = ReactionExternalId {
            connector: event.channel.clone(),
            id: external_reaction_id.clone(),
        };
        if !*revoked {
            return self.react(ReactionInput {
                message,
                by: person,
                glyph: glyph.clone(),
                occurred_at: event.received_at,
                external_id: Some(ext),
                actor,
            });
        }
        let key = external_key(&ext);
        let (id, commit) = self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, actor)?;
            require_type(&self.store, txn, &person, ENTITY_TYPE_PERSON)?;
            match live_entity_row_in_txn(&self.store, txn, &message)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN,
                    ..
                } => {}
                _ => return Err(invalid("external target is not a live conversation record")),
            }
            let room = room_for_record_in(self, txn, message)?
                .ok_or(invalid("external target has no room"))?;
            let metadata = crate::conversation::body_in(self, txn, room)?;
            if metadata.kind != crate::conversation::ConversationKind::Mirror
                || metadata
                    .external_id
                    .as_deref()
                    .and_then(|id| id.split_once(':'))
                    .is_none_or(|(connector, _)| connector != event.channel)
                || !AudienceCache::default().readable(self, txn, message, &[person])?
            {
                return Err(invalid("external removal is outside the room audience"));
            }
            let binding = self
                .store
                .vault_meta
                .get(txn, &key)?
                .ok_or(invalid("unseen external reaction removal"))?;
            if binding.len() != 80
                || &binding[16..32] != message.as_bytes()
                || &binding[32..48] != person.as_bytes()
                || &binding[48..] != blake3::hash(glyph.as_bytes()).as_bytes()
            {
                return Err(invalid("external removal does not match put"));
            }
            let id = EntityId::from_bytes(
                binding[..16]
                    .try_into()
                    .map_err(|_| invalid("external index"))?,
            )?;
            match live_entity_row_in_txn(&self.store, txn, &id)? {
                LiveEntityRow::Live {
                    entity_type: crate::registry::ENTITY_TYPE_REACTION,
                    body,
                } => {
                    let original = ReactionBody::from_bytes(&body)
                        .map_err(|_| Error::CorruptedIndex("external reaction body"))?;
                    if original.msg != message
                        || original.by != person
                        || original.glyph != *glyph
                        || original
                            .ext
                            .as_ref()
                            .is_some_and(|recorded| recorded != &ext)
                        || !member_at_in(self, txn, room, person, original.at)?
                    {
                        return Err(invalid("external removal differs from original reaction"));
                    }
                }
                LiveEntityRow::DeletedShell => {} // An exact removal retry is a no-op.
                _ => return Err(invalid("external reaction no longer exists")),
            }
            Ok((id, self.revoke_reaction_in_txn(txn, id, false)?))
        })?;
        if let Some(commit) = commit {
            self.publish_reaction_revocation(&commit)?;
            Ok(ReactionChange {
                id,
                state: ReactionState::Revoked,
            })
        } else {
            Ok(ReactionChange {
                id,
                state: ReactionState::Replayed,
            })
        }
    }
}
