//! Room-backed completion of a loaded goal-intake skill interview.
use super::{GoalRecord, invalid};
#[cfg(test)]
mod tests;
use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestKind};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::store::Store;
use crate::workspace_roster::rooms::{RoomTurn, require_member, turn_in};
use crate::{EntityId, Result, Vault};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

/// Four witnessed turns of one agent question, human answer, agent draft, human confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalInterviewTurns {
    pub question: EntityId,
    pub answer: EntityId,
    pub draft: EntityId,
    pub confirmation: EntityId,
}

impl GoalInterviewTurns {
    /// The digest a human confirms: the project's goal generation, recorded
    /// when the draft was shown (8 bytes, big-endian), then the draft's bytes.
    pub fn confirmation_digest(draft: &str, generation: u64) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&generation.to_be_bytes());
        hasher.update(draft.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

const GENERATION_KEY: &[u8] = b"project.goal_intake.generation/";

/// A project's durable goal generation; zero before its first goal commits.
pub(super) fn generation(store: &Store, txn: &RoTxn<'_>, project: EntityId) -> Result<u64> {
    let Some(raw) = store
        .vault_meta
        .get(txn, &[GENERATION_KEY, project.as_bytes()].concat())?
    else {
        return Ok(0);
    };
    Ok(u64::from_be_bytes(
        raw.as_ref().try_into().map_err(|_| invalid())?,
    ))
}

/// Called in the same write txn as every goal-pointer change, so no
/// confirmation shown against an earlier goal can apply after it.
pub(super) fn bump_generation(store: &Store, txn: &mut RwTxn<'_>, project: EntityId) -> Result<()> {
    let next = generation(store, txn, project)?
        .checked_add(1)
        .ok_or_else(invalid)?;
    store.vault_meta.put(
        txn,
        &[GENERATION_KEY, project.as_bytes()].concat(),
        &next.to_be_bytes(),
    )?;
    Ok(())
}

fn content(vault: &Vault, txn: &RoTxn<'_>, turn: &RoomTurn, author: &str) -> Result<String> {
    let [message] = turn.message_ids.as_slice() else {
        return Err(invalid());
    };
    let id = EntityId::from_hex(message).map_err(|_| invalid())?;
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(invalid)?;
    if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_MESSAGE)
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let bytes = crate::ports::safe_read_text(vault, txn, &id)?.ok_or_else(invalid)?;
    let body = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).map_err(|_| invalid())?;
    let entries = body.as_map().ok_or_else(invalid)?;
    let get = |name: &str| -> Result<&rmpv::Value> {
        let mut fields = entries.iter().filter(|(k, _)| k.as_str() == Some(name));
        let (_, value) = fields.next().ok_or_else(invalid)?;
        if fields.next().is_some() {
            return Err(invalid());
        }
        Ok(value)
    };
    if get("author")?.as_str() != Some(author) || get("is_visible")?.as_bool() != Some(true) {
        return Err(invalid());
    }
    get("content")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid)
}

impl Vault {
    /// The goal generation an interview records when it shows its draft. Goal
    /// intake, supersession and deletion move it; other project edits do not.
    pub fn project_goal_generation(&self, project_id: EntityId) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        generation(&self.store, &txn, project_id)
    }

    /// Finalize an agent-asked, human-answered interview, never a caller-supplied
    /// `GoalRecord`. The host must first dispatch an attempt, load the active
    /// goal-intake body with `load_attempt_skill_pack`, witness these room turns,
    /// and authenticate the answering human independently of their words.
    pub fn write_project_goal_from_room_intake(
        &self,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        attempt: AttemptId,
        turns: GoalInterviewTurns,
        now: u64,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let attempt = AttemptQueue::new(self)
                .get_in_txn(txn, attempt)?
                .ok_or_else(invalid)?;
            if !attempt
                .manifest
                .iter()
                .any(|item| item.kind == ManifestKind::Skill && item.reference == "goal-intake")
            {
                return Err(invalid());
            }
            let project: super::super::ProjectRecord =
                super::super::record(&self.store, txn, project_id, self.project_type_byte()?)?
                    .ok_or_else(invalid)?;
            let room = EntityId::from_hex(&project.home_room).map_err(|_| invalid())?;
            require_member(self, txn, room, owner.actor())?;
            let refs = [
                turns.question,
                turns.answer,
                turns.draft,
                turns.confirmation,
            ];
            let rows = refs
                .map(|id| turn_in(self, txn, id))
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            if rows.iter().any(|row| row.room_id != room.to_hex())
                || rows[0].actor != project.leader
                || rows[2].actor != project.leader
                || rows[1].actor != owner.actor().to_hex()
                || rows[3].actor != owner.actor().to_hex()
                || !(rows[0].at < rows[1].at
                    && rows[1].at < rows[2].at
                    && rows[2].at < rows[3].at
                    && rows[3].at <= now)
                || rows[1].reply_to.as_deref() != Some(rows[0].turn_id.as_str())
                || rows[2].reply_to.as_deref() != Some(rows[1].turn_id.as_str())
                || rows[3].reply_to.as_deref() != Some(rows[2].turn_id.as_str())
            {
                return Err(invalid());
            }
            content(self, txn, &rows[0], crate::gate::WITNESS_AUTHOR_COMPANION)?;
            let answer = content(self, txn, &rows[1], crate::gate::WITNESS_AUTHOR_USER)?;
            let record: GoalRecord = serde_json::from_str(&answer).map_err(|_| invalid())?;
            record.validate()?;
            let draft = content(self, txn, &rows[2], crate::gate::WITNESS_AUTHOR_COMPANION)?;
            if serde_json::from_str::<GoalRecord>(&draft).map_err(|_| invalid())? != record {
                return Err(invalid());
            }
            let confirmation = content(self, txn, &rows[3], crate::gate::WITNESS_AUTHOR_USER)?;
            // A confirmation is single-use. Its stored claim is stable on an
            // identical retry; an older retry after a newer goal never rolls
            // the project back to historical words.
            let completion_key = [
                b"project.goal_intake.confirmation/".as_slice(),
                turns.confirmation.as_bytes(),
            ]
            .concat();
            if let Some(raw) = self.store.vault_meta.get(txn, &completion_key)? {
                let id = EntityId::from_bytes(raw.as_ref().try_into().map_err(|_| invalid())?)?;
                return if project.goal.as_deref() == Some(id.to_hex().as_str()) {
                    Ok(id)
                } else {
                    Err(invalid())
                };
            }
            // The literal is a protocol token, not prompt copy; the skill owns
            // how the agent asks. The digest binds the human pick to this draft
            // and to the goal generation it was shown against, so a goal
            // committed or deleted since then refuses it.
            let current = generation(&self.store, txn, project_id)?;
            if confirmation
                != format!(
                    "confirm {}",
                    GoalInterviewTurns::confirmation_digest(&draft, current)
                )
            {
                return Err(invalid());
            }
            let id = self.write_project_goal_in_txn(txn, owner, project_id, &record, now)?;
            self.store
                .vault_meta
                .put(txn, &completion_key, id.as_bytes())?;
            Ok(id)
        })
    }
}
