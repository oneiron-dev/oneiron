//! One-transaction grouped reads and person-addressed reaction signals.
use super::codec::*;
use super::materialize::{invalid, message_author};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::visibility::message_visible_in_txn;
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Hydrate all reaction pills for a page inside one read transaction.
    /// No entity or edge facade read runs after this batched read starts.
    pub fn grouped_reaction_pills(
        &self,
        messages: &[EntityId],
        viewer: &EntityId,
    ) -> Result<Vec<ReactionGrouping>> {
        if messages.len() > GROUPED_PILLS_MAX_MESSAGES {
            return Err(invalid("reaction page exceeds 50 messages"));
        }
        let txn = self.store.env.read_txn()?;
        #[cfg(test)]
        self.test_hooks().note_reaction_read("reaction.batch");
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            if !message_visible_in_txn(&self.store, &txn, message, viewer)? {
                out.push(ReactionGrouping {
                    message: message.to_hex(),
                    pills: vec![],
                });
                continue;
            }
            let live = live_reactions(self, &txn, message)?;
            out.push(group_live_reactions(message, &live, viewer));
        }
        Ok(out)
    }
    /// Reactions addressed to the author of the reacted-to message. Both put
    /// and revoke events survive; missing/revoked message membership suppresses
    /// the signal exactly as it suppresses the message and its pills.
    pub fn reactions_since(&self, person: &EntityId, since: u64) -> Result<Vec<ReactionSignal>> {
        self.reactions_since_with_disclosure(person, since, None)
    }
    /// Context-pack inbox projection under the same disclosure generation.
    pub fn reactions_since_with_disclosure(
        &self,
        person: &EntityId,
        since: u64,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<Vec<ReactionSignal>> {
        let txn = self.store.env.read_txn()?;
        if let Some(ctx) = disclosure {
            ctx.ensure_current()?;
        }
        let mut prefix = REACTION_INBOX_KEY_PREFIX.to_vec();
        prefix.extend_from_slice(person.as_bytes());
        let mut signals = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, value) = entry?;
            let signal: ReactionSignal = serde_json::from_slice(&value)
                .map_err(|_| Error::CorruptedIndex("reaction inbox"))?;
            if signal.at < since {
                continue;
            }
            let message = EntityId::from_hex(&signal.message)?;
            let reaction = EntityId::from_hex(&signal.reaction)?;
            if self
                .store
                .entities
                .get(&txn, reaction.as_bytes())?
                .is_none()
            {
                continue;
            }
            if message_author(&self.store, &txn, &message)? != Some(*person)
                || !message_visible_in_txn(&self.store, &txn, &message, person)?
            {
                continue;
            }
            if let Some(ctx) = disclosure {
                let by = EntityId::from_hex(&signal.by)?;
                if !ctx.admits(
                    &self.store,
                    &txn,
                    &message,
                    crate::registry::ENTITY_TYPE_MESSAGE,
                    None,
                )? || !ctx.admits(
                    &self.store,
                    &txn,
                    &by,
                    crate::registry::ENTITY_TYPE_PERSON,
                    None,
                )? {
                    continue;
                }
            }
            signals.push(signal);
        }
        signals.sort_by(|a, b| {
            a.at.cmp(&b.at)
                .then(a.recorded_at.cmp(&b.recorded_at))
                .then(a.reaction.cmp(&b.reaction))
                .then(a.kind.as_str().cmp(b.kind.as_str()))
        });
        if let Some(ctx) = disclosure {
            ctx.ensure_current()?;
        }
        Ok(signals)
    }
}

pub(super) fn live_reactions(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Vec<LiveReaction>> {
    let mut prefix = message.as_bytes().to_vec();
    prefix.push(EdgeKind::About as u8);
    let mut live = Vec::new();
    for entry in vault.store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        let id = parse_strict_edge_record(&key, &value)?.target;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let h =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("reaction header"))?;
        if h.entity_type != crate::registry::ENTITY_TYPE_REACTION
            || vault
                .store
                .entity_deletion_present_in_txn(txn, &id, h.learned_at)?
        {
            continue;
        }
        let body = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if body.msg == *message {
            live.push(LiveReaction {
                id,
                body,
                recorded_at: h.learned_at,
            });
        }
    }
    live.sort_by_key(|r| (r.recorded_at, r.id));
    Ok(live)
}

fn group_live_reactions(
    message: &EntityId,
    live: &[LiveReaction],
    viewer: &EntityId,
) -> ReactionGrouping {
    let mut pills: Vec<ReactionPill> = Vec::new();
    for reaction in live {
        let index = match pills.iter().position(|p| p.glyph == reaction.body.glyph) {
            Some(i) => i,
            None => {
                pills.push(ReactionPill {
                    glyph: reaction.body.glyph.clone(),
                    count: 0,
                    by: vec![],
                    mine: false,
                });
                pills.len() - 1
            }
        };
        let pill = &mut pills[index];
        pill.count += 1;
        pill.by.push(reaction.body.by.to_hex());
        pill.mine |= reaction.body.by == *viewer;
    }
    ReactionGrouping {
        message: message.to_hex(),
        pills,
    }
}
