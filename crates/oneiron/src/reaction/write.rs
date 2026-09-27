//! One live reaction per (message, person, glyph), with a soft-delete toggle.
use super::{ReactionBody, ReactionExternalId};
use crate::conversation::{AudienceCache, room_for_record_in};
use crate::conversation_dag::{actor_in_txn, edge_ids, require_type};
use crate::deletion::ReactionRevocation;
use crate::error::{Error, RecordError, Result};
use crate::registry::{
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_REACTION, ENTITY_TYPE_TURN,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EdgeKind, EntityId, TimeRange, Vault, WriteActor};

fn invalid(why: &'static str) -> Error {
    RecordError::InvalidReactionBody(why).into()
}

/// The caller's requested reaction. A mirrored event carries its stable source
/// identity and can retry without toggling the result a second time.
#[derive(Debug, Clone)]
pub struct ReactionInput {
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub occurred_at: u64,
    pub external_id: Option<ReactionExternalId>,
    pub actor: WriteActor,
}

/// The observable effect of a reaction request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionState {
    Put,
    Revoked,
    Replayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactionChange {
    pub id: EntityId,
    pub state: ReactionState,
}

const EXTERNAL_PREFIX: &[u8] = b"reaction:external:v1:";
pub(super) fn external_key(ext: &ReactionExternalId) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(&(ext.connector.len() as u64).to_be_bytes());
    hash.update(ext.connector.as_bytes());
    hash.update(&(ext.id.len() as u64).to_be_bytes());
    hash.update(ext.id.as_bytes());
    [EXTERNAL_PREFIX, hash.finalize().as_bytes()].concat()
}

/// The caller's transaction sees the complete reaction neighborhood. Never
/// trust an About edge alone: require a live REACTION with matching body and
/// exactly one author/message binding.
pub(super) fn live_for_message(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<Vec<(EntityId, ReactionBody, u64)>> {
    match live_entity_row_in_txn(&vault.store, txn, &message)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN,
            ..
        } => {}
        _ => return Err(invalid("reaction target is not a live conversation record")),
    }
    let mut result = Vec::new();
    for id in edge_ids(&vault.store, txn, &message, EdgeKind::About, true, 100_000)? {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_REACTION,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        if body.is_empty() {
            continue;
        } // Replayed soft tombstone shell.
        let reaction = ReactionBody::from_bytes(&body)
            .map_err(|_| Error::CorruptedIndex("reaction stored body"))?;
        if !matches!(
            live_entity_row_in_txn(&vault.store, txn, &reaction.by)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PERSON,
                ..
            }
        ) || !AudienceCache::default().readable(vault, txn, message, &[reaction.by])?
            || reaction.msg != message
        {
            continue; // Incomplete or invalid remote rows never poison the page.
        }
        let author = edge_ids(&vault.store, txn, &id, EdgeKind::AuthoredBy, false, 2)?;
        let target = edge_ids(&vault.store, txn, &id, EdgeKind::About, false, 2)?;
        if author.as_slice() != [reaction.by] || target.as_slice() != [message] {
            continue;
        }
        let Some(room) = room_for_record_in(vault, txn, message)? else {
            continue;
        };
        if !crate::conversation::member_at_in(vault, txn, room, reaction.by, reaction.at)? {
            continue; // A hostile historical peer row cannot toggle a valid new put.
        }
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("reaction header missing"))?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("reaction header"))?;
        result.push((id, reaction, header.learned_at));
    }
    Ok(result)
}

pub(super) fn external_binding(id: EntityId, body: &ReactionBody) -> Vec<u8> {
    let mut binding = Vec::with_capacity(80);
    binding.extend_from_slice(id.as_bytes());
    binding.extend_from_slice(body.msg.as_bytes());
    binding.extend_from_slice(body.by.as_bytes());
    binding.extend_from_slice(blake3::hash(body.glyph.as_bytes()).as_bytes());
    binding
}

enum Effect {
    Put(ReactionChange),
    Revoke(Vec<ReactionRevocation>),
}

impl Vault {
    /// First-party toggle, or source-idempotent mirrored ingress. A mirrored
    /// retry returns its original ID even if that reaction was since revoked.
    pub fn react(&self, input: ReactionInput) -> Result<ReactionChange> {
        let body = ReactionBody {
            v: 1,
            msg: input.message,
            by: input.by,
            glyph: input.glyph,
            at: input.occurred_at,
            ext: input.external_id,
        };
        body.validate()?;
        if input.actor.entity_ref() != body.by {
            return Err(invalid("reactor must be the actor"));
        }
        let effect = self.with_write_txn(|txn| {
            if body.at > self.store.clock.now_recorded_at() {
                return Err(invalid("reaction occurrence is in the future"));
            }
            actor_in_txn(&self.store, txn, input.actor)?;
            match live_entity_row_in_txn(&self.store, txn, &body.msg)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN,
                    ..
                } => {}
                _ => {
                    return Err(invalid(
                        "target must be a live MESSAGE or conversation record",
                    ));
                }
            }
            require_type(&self.store, txn, &body.by, ENTITY_TYPE_PERSON)?;
            let room =
                room_for_record_in(self, txn, body.msg)?.ok_or(invalid("message has no room"))?;
            if let Some(ext) = body.ext.as_ref() {
                let metadata = crate::conversation::body_in(self, txn, room)?;
                if metadata.kind != crate::conversation::ConversationKind::Mirror
                    || metadata
                        .external_id
                        .as_deref()
                        .and_then(|id| id.split_once(':'))
                        .is_none_or(|(connector, _)| connector != ext.connector)
                {
                    return Err(invalid("external reaction must match a mirrored room"));
                }
            }
            if !AudienceCache::default().readable(self, txn, body.msg, &[body.by])? {
                return Err(invalid("reactor cannot read message"));
            }
            if !crate::conversation::member_at_in(self, txn, room, body.by, body.at)? {
                return Err(invalid("reactor is not a room member"));
            }
            let external = body.ext.as_ref().map(external_key);
            if let Some(key) = &external
                && let Some(prior) = self.store.vault_meta.get(txn, key)?
            {
                let (id_bytes, rest) = prior
                    .split_at_checked(16)
                    .ok_or(invalid("external index"))?;
                if rest.len() != 64
                    || &rest[..16] != body.msg.as_bytes()
                    || &rest[16..32] != body.by.as_bytes()
                    || &rest[32..] != blake3::hash(body.glyph.as_bytes()).as_bytes()
                {
                    return Err(invalid("external id bound to another reaction"));
                }
                let id = EntityId::from_bytes(
                    id_bytes.try_into().map_err(|_| invalid("external index"))?,
                )?;
                return Ok(Effect::Put(ReactionChange {
                    id,
                    state: ReactionState::Replayed,
                }));
            }
            let mut matching: Vec<_> = live_for_message(self, txn, body.msg)?
                .into_iter()
                .filter(|(_, row, _)| row.by == body.by && row.glyph == body.glyph)
                .collect();
            matching.sort_by_key(|(id, _, recorded_at)| (*recorded_at, *id));
            if let Some((canonical, _, _)) = matching.first() {
                if let Some(key) = &external {
                    // Connector echo of a first-party put is an ack, not a
                    // new toggle. The replicated identity repair is separate.
                    self.store
                        .vault_meta
                        .put(txn, key, &external_binding(*canonical, &body))?;
                    return Ok(Effect::Put(ReactionChange {
                        id: *canonical,
                        state: ReactionState::Replayed,
                    }));
                }
                let mut commits = Vec::with_capacity(matching.len());
                for (index, (id, _, _)) in matching.into_iter().enumerate() {
                    commits.push(
                        self.revoke_reaction_in_txn(txn, id, index == 0)?
                            .ok_or(invalid("reaction vanished during toggle"))?,
                    );
                }
                return Ok(Effect::Revoke(commits));
            }
            let id = self.store.clock.entity_id()?;
            super::admission::permit(&self.store, txn, &id)?;
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_REACTION,
                    TimeRange {
                        start: body.at,
                        end: body.at,
                    },
                    self.store.clock.now_recorded_at(),
                    &body.to_bytes()?,
                )
                .edge(&id, EdgeKind::About, &body.msg, 1.0)
                .edge(&id, EdgeKind::AuthoredBy, &body.by, 1.0)
                .apply(txn)?;
            super::admission::finish(&self.store, txn, &id)?;
            super::outbound::enqueue(self, txn, id, &body, false)?;
            if let Some(key) = &external {
                self.store
                    .vault_meta
                    .put(txn, key, &external_binding(id, &body))?;
            }
            Ok(Effect::Put(ReactionChange {
                id,
                state: ReactionState::Put,
            }))
        })?;
        match effect {
            Effect::Put(change) => Ok(change),
            Effect::Revoke(commits) => {
                for commit in &commits {
                    self.publish_reaction_revocation(commit)?;
                }
                Ok(ReactionChange {
                    id: commits[0].id,
                    state: ReactionState::Revoked,
                })
            }
        }
    }
}
