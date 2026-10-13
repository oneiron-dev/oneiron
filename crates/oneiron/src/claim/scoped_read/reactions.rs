//! Reactions riding along with the conversation records a scoped read admits.
use super::*;
use crate::context_pack::ContextPack;
use crate::disclosure::DisclosureContext;
use crate::reaction::{REACTIONS_FIELD, ReactionSignal};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use std::collections::HashMap;

impl ScopedRead<'_> {
    /// The current reactions on one conversation record this read may see,
    /// one grouped line per glyph (`👍×8 (Anna, Ben, +6)`), first put first.
    pub fn reaction_lines(&self, record: &EntityId) -> Result<Vec<String>> {
        self.reaction_lines_counting(record, &mut Vec::new())
    }

    /// [`Self::reaction_lines`], adding to `counted` each reaction claim its
    /// lines count.
    pub(crate) fn reaction_lines_counting(
        &self,
        record: &EntityId,
        counted: &mut Vec<EntityId>,
    ) -> Result<Vec<String>> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        self.reaction_lines_in(&rtxn, &policy, None, record, counted)
    }

    fn reaction_lines_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        disclosure: Option<&DisclosureContext>,
        record: &EntityId,
        counted: &mut Vec<EntityId>,
    ) -> Result<Vec<String>> {
        crate::reaction::grouped_lines_in(self.vault, rtxn, *record, |row| {
            let admitted = self.is_entity_readable_with_policy_in(rtxn, policy, &row.id)?
                && self.disclosed_in(rtxn, disclosure, &row.id)?;
            if admitted {
                counted.push(row.id);
            }
            Ok(admitted)
        })
    }

    /// Whether `disclosure`, when the read runs under one, admits the stored
    /// row `id`. A row that is gone, or a claim that does not decode, is not.
    fn disclosed_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        disclosure: Option<&DisclosureContext>,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(disclosure) = disclosure else {
            return Ok(true);
        };
        let Some(row) = self.entity_record_in(rtxn, id)? else {
            return Ok(false);
        };
        let claim = if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            match crate::claim::decode_claim_body(&row.body, true) {
                Ok(claim) => Some(claim),
                Err(_) => return Ok(false),
            }
        } else {
            None
        };
        disclosure.admits(&self.vault.store, rtxn, id, row.entity_type, claim.as_ref())
    }

    /// Attaches each hydrated MESSAGE or TURN result's grouped reaction lines
    /// under [`REACTIONS_FIELD`]. Run after the pack's own scope filter.
    pub fn attach_reactions(&self, pack: &mut ContextPack) -> Result<()> {
        self.attach_reactions_under(pack, None)
    }

    /// [`Self::attach_reactions`] for a pack assembled under `disclosure`:
    /// a line counts only the reactions the clamp admits as well.
    pub fn attach_reactions_under(
        &self,
        pack: &mut ContextPack,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<()> {
        self.attach_reactions_quoting(pack, &HashMap::new(), disclosure, &mut Vec::new())
    }

    /// [`Self::attach_reactions_under`] for a pack whose TURNs took the place
    /// of matched messages (`quoted`, per TURN): a TURN's lines are followed
    /// by those of each message it quotes that this read may see. Each
    /// reaction claim a line counts is added to `counted`.
    pub(crate) fn attach_reactions_quoting(
        &self,
        pack: &mut ContextPack,
        quoted: &HashMap<EntityId, Vec<EntityId>>,
        disclosure: Option<&DisclosureContext>,
        counted: &mut Vec<EntityId>,
    ) -> Result<()> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        for entity in &mut pack.results {
            if !matches!(entity.entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
                continue;
            }
            let mut lines =
                self.reaction_lines_in(&rtxn, &policy, disclosure, &entity.id, counted)?;
            for message in quoted.get(&entity.id).into_iter().flatten() {
                if self.is_entity_readable_with_policy_in(&rtxn, &policy, message)?
                    && self.disclosed_in(&rtxn, disclosure, message)?
                {
                    lines.extend(
                        self.reaction_lines_in(&rtxn, &policy, disclosure, message, counted)?,
                    );
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
        self.is_reaction_signal_readable_under(signal, None)
    }

    /// [`Self::is_reaction_signal_readable`] for a read under `disclosure`:
    /// the clamp must admit the reacted record and the reaction as well.
    pub fn is_reaction_signal_readable_under(
        &self,
        signal: &ReactionSignal,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        Ok(self.is_entity_readable_in(&rtxn, &signal.message)?
            && self.audience_readable_in(&rtxn, &signal.reaction)?
            && self.disclosed_in(&rtxn, disclosure, &signal.message)?
            && self.disclosed_in(&rtxn, disclosure, &signal.reaction)?)
    }
}
