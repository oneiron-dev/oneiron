//! One-snapshot, batched reaction pills and agent-facing reaction signal rows.
use super::write::live_for_message;
use crate::conversation::{AudienceCache, member_at_in, room_for_record_in, visible_at_in};
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One glyph's current reaction tally, in first-put order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReactionPill {
    pub glyph: String,
    pub count: usize,
    pub by: Vec<EntityId>,
    pub mine: bool,
}

/// A put or revocation, with the origin message and its author.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionSignal {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub revoked: bool,
}

impl Vault {
    /// Group a page of message IDs under one LMDB snapshot. A message the
    /// viewer cannot read gets no pills, including no contributor identities.
    pub fn reaction_pills(
        &self,
        messages: &[EntityId],
        viewer: EntityId,
    ) -> Result<BTreeMap<EntityId, Vec<ReactionPill>>> {
        let txn = self.store.env.read_txn()?;
        let mut audience = AudienceCache::default();
        let mut result = BTreeMap::new();
        for &message in messages {
            if !audience.readable(self, &txn, message, &[viewer])? {
                continue;
            }
            let room = room_for_record_in(self, &txn, message)?.ok_or(Error::EntityNotFound)?;
            let mut entries = live_for_message(self, &txn, message)?;
            entries.sort_by_key(|(id, _, recorded_at)| (*recorded_at, *id));
            let mut groups: Vec<ReactionPill> = Vec::new();
            let mut seen = BTreeSet::new();
            for (_, row, _) in entries {
                if !member_at_in(self, &txn, room, row.by, row.at)? {
                    return Err(Error::Record(RecordError::InvalidReactionBody(
                        "reactor was outside room",
                    )));
                }
                if !visible_at_in(self, &txn, room, viewer, row.at)? {
                    continue;
                }
                if !seen.insert((row.by, row.glyph.clone())) {
                    return Err(Error::Record(RecordError::InvalidReactionBody(
                        "duplicate live triple",
                    )));
                }
                if let Some(pill) = groups.iter_mut().find(|pill| pill.glyph == row.glyph) {
                    pill.by.push(row.by);
                    pill.count += 1;
                    pill.mine |= row.by == viewer;
                } else {
                    groups.push(ReactionPill {
                        glyph: row.glyph,
                        count: 1,
                        by: vec![row.by],
                        mine: row.by == viewer,
                    });
                }
            }
            result.insert(message, groups);
        }
        Ok(result)
    }
}
