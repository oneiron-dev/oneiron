//! Reactions riding along with the conversation records a scoped read admits.
use super::*;
use crate::context_pack::ContextPack;
use crate::reaction::{REACTIONS_FIELD, ReactionSignal};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use std::collections::HashMap;

impl ScopedRead<'_> {
    /// The current reactions on one conversation record this read may see,
    /// one grouped line per glyph (`👍×8 (Anna, Ben, +6)`), first put first.
    pub fn reaction_lines(&self, record: &EntityId) -> Result<Vec<String>> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        self.reaction_lines_in(&rtxn, &policy, record)
    }

    fn reaction_lines_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        record: &EntityId,
    ) -> Result<Vec<String>> {
        crate::reaction::grouped_lines_in(self.vault, rtxn, *record, |row| {
            self.is_entity_readable_with_policy_in(rtxn, policy, &row.id)
        })
    }

    /// Attaches each hydrated MESSAGE or TURN result's grouped reaction lines
    /// under [`REACTIONS_FIELD`]. Run after the pack's own scope filter.
    pub fn attach_reactions(&self, pack: &mut ContextPack) -> Result<()> {
        self.attach_reactions_quoting(pack, &HashMap::new())
    }

    /// [`Self::attach_reactions`] for a pack whose TURNs took the place of
    /// matched messages (`quoted`, per TURN): a TURN's lines are followed by
    /// those of each message it quotes that this read may see.
    pub(crate) fn attach_reactions_quoting(
        &self,
        pack: &mut ContextPack,
        quoted: &HashMap<EntityId, Vec<EntityId>>,
    ) -> Result<()> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        for entity in &mut pack.results {
            if !matches!(entity.entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
                continue;
            }
            let mut lines = self.reaction_lines_in(&rtxn, &policy, &entity.id)?;
            for message in quoted.get(&entity.id).into_iter().flatten() {
                if self.is_entity_readable_with_policy_in(&rtxn, &policy, message)? {
                    lines.extend(self.reaction_lines_in(&rtxn, &policy, message)?);
                }
            }
            if let (Some(fields), false) = (entity.fields.as_mut(), lines.is_empty()) {
                fields.insert(REACTIONS_FIELD.to_owned(), serde_json::json!(lines));
            }
        }
        Ok(())
    }

    /// Whether this read may see a reaction signal: the reacted record is
    /// readable here and the reaction passes this read's audience, which
    /// holds for a removal as for the put it removed.
    pub fn is_reaction_signal_readable(&self, signal: &ReactionSignal) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        Ok(self.is_entity_readable_in(&rtxn, &signal.message)?
            && self.audience_readable_in(&rtxn, &signal.reaction)?)
    }
}
