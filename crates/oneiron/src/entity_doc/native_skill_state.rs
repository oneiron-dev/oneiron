//! The immutable pointer row's typed SKILL state materialization.

use super::storage;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimApprovalStatus;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillLifecycle, SkillRecord, decode_skill_record};
use crate::store::Store;
use crate::{EntityId, TimeRange};
use heed::RoTxn;
use rmpv::Value;

pub(crate) struct SkillStateSnapshot {
    entity: EntityId,
    raw: Vec<u8>,
    head: Vec<u8>,
    prior: SkillRecord,
    occurred: TimeRange,
    learned_at: u64,
}

fn invalid() -> Error {
    Error::InvariantViolation("headed SKILL state no longer matches its typed write")
}

fn state_only(prior: &SkillRecord, updated: &SkillRecord) -> bool {
    let mut unchanged = updated.clone();
    unchanged.lifecycle_status = prior.lifecycle_status;
    unchanged.approval_status = prior.approval_status;
    &unchanged == prior
}

impl SkillStateSnapshot {
    pub(crate) fn capture(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        updated: &SkillRecord,
    ) -> Result<Option<Self>> {
        let Some(head) = storage::record_head_bytes(store, txn, &entity)? else {
            return Ok(None);
        };
        let raw = store
            .port_entity_raw(txn, &entity)?
            .ok_or(Error::EntityNotFound)?
            .to_vec();
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("SKILL state header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(invalid());
        }
        let body =
            storage::resolve_record_body(store, txn, &entity, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        let prior = decode_skill_record(&body)?;
        if !state_only(&prior, updated) {
            return Ok(None);
        }
        Ok(Some(Self {
            entity,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            raw,
            head,
            prior,
        }))
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.entity
    }

    pub(crate) fn times(&self) -> (TimeRange, u64) {
        (self.occurred, self.learned_at)
    }

    pub(crate) fn current(&self, store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<()> {
        if *entity != self.entity
            || storage::record_head_bytes(store, txn, entity)?.as_deref()
                != Some(self.head.as_slice())
            || store.port_entity_raw(txn, entity)?.as_deref() != Some(self.raw.as_slice())
        {
            return Err(invalid());
        }
        let current = storage::resolve_record_body(
            store,
            txn,
            entity,
            &self.raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        if decode_skill_record(&current)? != self.prior {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn validate_carrier(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        metadata: (u8, TimeRange, u64),
        data: &[u8],
        lifecycle: SkillLifecycle,
        approval: ClaimApprovalStatus,
    ) -> Result<()> {
        self.current(store, txn, entity)?;
        if metadata != (ENTITY_TYPE_SKILL, self.occurred, self.learned_at) {
            return Err(invalid());
        }
        let updated = decode_skill_record(data)?;
        if !state_only(&self.prior, &updated)
            || updated.lifecycle_status != lifecycle
            || updated.approval_status != approval
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn materialize(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        data: &[u8],
        lifecycle: SkillLifecycle,
    ) -> Result<Vec<u8>> {
        self.current(store, txn, entity)?;
        let updated = decode_skill_record(data)?;
        if !state_only(&self.prior, &updated) || updated.lifecycle_status != lifecycle {
            return Err(invalid());
        }
        let Value::Map(incoming) =
            rmpv::decode::read_value(&mut std::io::Cursor::new(data)).map_err(|_| invalid())?
        else {
            return Err(invalid());
        };
        patch_state_values(&self.raw[ENTITY_METADATA_HEADER_LEN..], &incoming)
    }
}

// Preserve every other byte, including unknown native fields and map encoding.
fn patch_state_values(body: &[u8], incoming: &[(Value, Value)]) -> Result<Vec<u8>> {
    let (count, offset) = match body.first().copied() {
        Some(marker @ 0x80..=0x8f) => (u32::from(marker & 0x0f), 1),
        Some(0xde) => (
            u32::from(u16::from_be_bytes(
                body.get(1..3)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            )),
            3,
        ),
        Some(0xdf) => (
            u32::from_be_bytes(
                body.get(1..5)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ),
            5,
        ),
        _ => return Err(invalid()),
    };
    let mut cursor = std::io::Cursor::new(body);
    cursor.set_position(offset);
    let mut output = Vec::new();
    let mut copied = 0;
    let mut found = [false; 2];
    for _ in 0..count {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
        let start = cursor.position() as usize;
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
        let end = cursor.position() as usize;
        let index = match key.as_str() {
            Some("lifecycleStatus") => 0,
            Some("approvalStatus") => 1,
            _ => continue,
        };
        if found[index] {
            return Err(invalid());
        }
        found[index] = true;
        let (_, value) = incoming
            .iter()
            .find(|(name, _)| name == &key)
            .ok_or_else(invalid)?;
        output.extend_from_slice(&body[copied..start]);
        rmpv::encode::write_value(&mut output, value).map_err(|_| invalid())?;
        copied = end;
    }
    if cursor.position() as usize != body.len() || found != [true; 2] {
        return Err(invalid());
    }
    output.extend_from_slice(&body[copied..]);
    Ok(output)
}
