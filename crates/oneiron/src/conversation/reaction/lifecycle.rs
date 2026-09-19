//! Serialized toggle admission and mirrored delivery deduplication.
use super::codec::*;
use super::materialize::{invalid, revocation_time};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::visibility::{live_header, message_visible_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_REACTION};

pub(crate) type ReactionWrite = (
    ReactOutcome,
    Option<(EntityId, u64, crate::deletion::TombstoneValueV2)>,
);

impl Vault {
    /// Toggle as the bound person. Mirrored delivery is idempotent, including
    /// after revocation; repeated external IDs can never resurrect a row.
    pub fn react(&self, actor: &EntityId, input: ReactInput) -> Result<ReactOutcome> {
        let now = crate::unix_seconds_now();
        let (outcome, publish) =
            self.with_write_txn(|txn| self.react_in_txn(txn, actor, &input, now))?;
        if let Some((id, learned, tombstone)) = publish {
            self.publish_reaction_revocation(&id, learned, &tombstone)?;
        }
        Ok(outcome)
    }

    pub(crate) fn react_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
        input: &ReactInput,
        now: u64,
    ) -> Result<ReactionWrite> {
        let body = ReactionBody {
            msg: input.message,
            by: input.by,
            glyph: input.glyph.clone(),
            at: input.at,
            ext: input.ext.clone(),
        };
        let encoded = encode_reaction_body(&body)?;
        if input.by != *actor {
            return Err(invalid("reaction by must be the bound actor"));
        }

        if !live_header(&self.store, txn, actor)?
            .is_some_and(|h| h.entity_type == ENTITY_TYPE_PERSON)
        {
            return Err(invalid("reactor must be a live PERSON"));
        }
        if !message_visible_in_txn(&self.store, txn, &input.message, actor)? {
            return Err(invalid("message is not visible to the reactor"));
        }
        let mut live = None;
        for entry in self.store.entities.iter(txn)? {
            let (key, raw) = entry?;
            let Some(h) = EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if h.entity_type != ENTITY_TYPE_REACTION {
                continue;
            }
            let other_id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("reaction id"))?,
            )?;
            let other = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let revoked = revocation_time(&self.store, txn, &other_id, h.learned_at)?.is_some();
            if input.ext.is_some() && input.ext == other.ext {
                if other.msg != input.message || other.by != input.by || other.glyph != input.glyph
                {
                    return Err(invalid("external reaction id is bound to another reaction"));
                }
                return Ok((
                    ReactOutcome {
                        state: if revoked {
                            ReactionState::Revoked
                        } else {
                            ReactionState::Put
                        },
                        reaction_id: other_id,
                    },
                    None,
                ));
            }
            if !revoked
                && other.msg == input.message
                && other.by == input.by
                && other.glyph == input.glyph
            {
                live = Some((other_id, h.learned_at));
            }
        }
        if let Some((id, learned_at)) = live {
            // A new mirrored event for an already-live triple is an add,
            // never a first-party toggle. It must carry its unique ext.
            if input.ext.is_some() {
                return Err(invalid("mirrored reaction triple already live"));
            }
            let tombstone = crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::DeleteReason::UserDelete.into(),
                deleted_at: now,
                request_id: *uuid::Uuid::now_v7().as_bytes(),
            };
            self.stage_reaction_revocation(txn, &id, learned_at, &tombstone)?;
            super::outbound::enqueue(self, txn, input, &id, ReactionState::Revoked, now)?;
            Ok((
                ReactOutcome {
                    state: ReactionState::Revoked,
                    reaction_id: id,
                },
                Some((id, learned_at, tombstone)),
            ))
        } else {
            let id = EntityId::now();
            self.batch_in()
                .put_reaction(
                    &id,
                    actor,
                    crate::temporal::TimeRange {
                        start: input.at,
                        end: input.at,
                    },
                    now,
                    &encoded,
                )
                .apply(txn)?;
            super::outbound::enqueue(self, txn, input, &id, ReactionState::Put, now)?;
            Ok((
                ReactOutcome {
                    state: ReactionState::Put,
                    reaction_id: id,
                },
                None,
            ))
        }
    }

    /// Rebuild the disposable inbox from immutable reaction records and their
    /// tombstones. This also repairs joins after out-of-order replay.
    pub fn rebuild_reaction_inbox(&self) -> Result<()> {
        self.with_write_txn(|txn| super::materialize::rebuild_inbox_in_txn(&self.store, txn))
    }
}
