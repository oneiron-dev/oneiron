//! Portable, immutable goal identity of an optimizer-born SKILL revision.
//! The human's goal definition is separate data keyed by this identity.
use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillRecord, decode_skill_record};
use crate::store::Store;

use super::{PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, SKILL_OPTIMIZE_BIRTH_PATH, invalid};
use crate::skill_convert::PROVENANCE_BIRTH_KEY;

pub(in crate::skill_optimize) const GOAL_ID_KEY: &str = "goal_id";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::skill_optimize) struct SkillGoalId(EntityId);

impl SkillGoalId {
    pub(in crate::skill_optimize) fn of(id: &EntityId, record: &SkillRecord) -> Result<Self> {
        let Value::Map(entries) = &record.provenance else {
            return Err(invalid(
                "skill goal identity requires structured provenance",
            ));
        };
        let birth = unique_string(entries, PROVENANCE_BIRTH_KEY)?;
        let goal = unique_string(entries, GOAL_ID_KEY)?;
        if birth.as_deref() != Some(SKILL_OPTIMIZE_BIRTH_PATH) {
            if goal.is_some() {
                return Err(invalid(
                    "non-optimizer skill cannot claim optimizer goal identity",
                ));
            }
            return Ok(Self(*id));
        }
        let hex = goal.ok_or(invalid("optimizer-born skill has no goal identity"))?;
        let parsed = EntityId::from_hex(&hex)
            .map_err(|_| invalid("optimizer-born skill has a malformed goal identity"))?;
        if parsed.to_hex() != hex {
            return Err(invalid(
                "optimizer goal identity must use canonical lowercase hex",
            ));
        }
        Ok(Self(parsed))
    }

    pub(in crate::skill_optimize) fn entity(self) -> EntityId {
        self.0
    }

    pub(in crate::skill_optimize) fn from_hex(hex: &str) -> Result<Self> {
        let parsed = EntityId::from_hex(hex)
            .map_err(|_| invalid("malformed retained optimizer goal identity"))?;
        if parsed.to_hex() != hex {
            return Err(invalid("non-canonical retained optimizer goal identity"));
        }
        Ok(Self(parsed))
    }
}

fn unique_string(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    let mut found = None;
    for (name, value) in entries {
        if name.as_str() == Some(key) {
            if found.is_some() {
                return Err(invalid("duplicate optimizer goal provenance key"));
            }
            found = Some(
                value
                    .as_str()
                    .ok_or(invalid("non-string optimizer goal provenance"))?
                    .to_owned(),
            );
        }
    }
    Ok(found)
}

/// Shared create door. Local drafts prove the parent and its goal in the same
/// snapshot. Replay checks that equality when the parent is present, but a
/// surviving successor can materialize after the parent was erased.
pub(crate) fn validate_goal_birth_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &SkillRecord,
    replicated: bool,
) -> Result<()> {
    let goal = SkillGoalId::of(id, created)?;
    let Value::Map(entries) = &created.provenance else {
        return Err(invalid("optimizer birth requires structured provenance"));
    };
    if unique_string(entries, PROVENANCE_BIRTH_KEY)?.as_deref() != Some(SKILL_OPTIMIZE_BIRTH_PATH) {
        return Ok(());
    }
    let parent_hex = unique_string(entries, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)?
        .ok_or(invalid("optimizer-born skill has no predecessor identity"))?;
    let parent = EntityId::from_hex(&parent_hex)
        .map_err(|_| invalid("optimizer-born skill has a malformed predecessor identity"))?;
    if parent == *id {
        return Err(invalid("optimizer skill cannot revise itself"));
    }
    // A user delete keeps the parent's header as a shell whose body is gone
    // (ARCH-0038); that parent is erased, not a record to decode.
    let parent_raw =
        if crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, &parent)?.deleted {
            None
        } else {
            store.entities.get(txn, parent.as_bytes())?
        };
    let Some(raw) = parent_raw else {
        if !replicated {
            return Err(invalid("local optimizer predecessor is missing"));
        }
        // Erasure removes instruction bytes, not the parent's immutable birth
        // marker. A first rematerialized child cannot contradict a goal fact
        // the receiver retained even though the parent body is absent.
        if super::gate::retained_optimizer_parent_goal_in_txn(store, txn, &parent)?.is_some_and(
            |(known_goal, known_skill_id)| known_goal != goal || known_skill_id != created.skill_id,
        ) {
            return Err(invalid(
                "orphaned optimizer goal conflicts with retained parent origin",
            ));
        }
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("skill goal predecessor header"))?;
    if header.entity_type != ENTITY_TYPE_SKILL {
        return Err(invalid("optimizer predecessor is not a skill"));
    }
    let prior = decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if prior.skill_id != created.skill_id || SkillGoalId::of(&parent, &prior)? != goal {
        return Err(invalid(
            "optimizer goal identity conflicts with predecessor",
        ));
    }
    Ok(())
}
