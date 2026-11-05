//! The exact headed SKILL read captured by a typed state request.

use std::collections::BTreeMap;
use std::io::Cursor;

use super::super::storage;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillRecord, decode_skill_record};
use crate::store::Store;
use crate::{EntityId, TimeRange};
use heed::RoTxn;

/// A read binding, not admission or permission to publish a native fact.
/// The original row is retained verbatim; it is never patched with new state.
pub(crate) struct SkillStateSnapshot {
    entity: EntityId,
    raw: Vec<u8>,
    head: Vec<u8>,
    logical_body: Vec<u8>,
    prior: SkillRecord,
}

fn moved() -> Error {
    Error::InvariantViolation("headed SKILL changed during its typed state update")
}

impl SkillStateSnapshot {
    pub(crate) fn capture(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        requested: &[u8],
    ) -> Result<Option<Self>> {
        let Some(head) = storage::record_head_bytes(store, txn, &entity)? else {
            return Ok(None);
        };
        let raw = store
            .port_entity_raw(txn, &entity)?
            .ok_or(Error::EntityNotFound)?
            .to_vec();
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("headed SKILL header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Ok(None);
        }
        let logical_body =
            storage::resolve_record_body(store, txn, &entity, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        let prior = decode_skill_record(&logical_body)?;
        let updated = decode_skill_record(requested)?;
        if !state_only(&prior, &updated)
            || non_state_fields(&logical_body)? != non_state_fields(requested)?
        {
            return Ok(None);
        }
        Ok(Some(Self {
            entity,
            raw,
            head,
            logical_body,
            prior,
        }))
    }

    /// Re-read the original row, head and live body in the caller's transaction.
    /// The final input is the logical body after the old put gates and scan.
    pub(crate) fn recheck(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        final_body: &[u8],
    ) -> Result<SkillRecord> {
        if *entity != self.entity
            || storage::record_head_bytes(store, txn, entity)?.as_deref()
                != Some(self.head.as_slice())
            || store.port_entity_raw(txn, entity)?.as_deref() != Some(self.raw.as_slice())
        {
            return Err(moved());
        }
        let current = storage::resolve_record_body(
            store,
            txn,
            entity,
            &self.raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        if current != self.logical_body {
            return Err(moved());
        }
        let updated = decode_skill_record(final_body)?;
        if !state_only(&self.prior, &updated)
            || non_state_fields(&self.logical_body)? != non_state_fields(final_body)?
        {
            return Err(moved());
        }
        Ok(updated)
    }

    /// Fingerprint of the actual immutable physical source at this admission.
    /// It is evidence of that source, not an erase-stable current-row identity.
    pub(super) fn source_fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.raw).as_bytes()
    }

    pub(super) fn prior(&self) -> &SkillRecord {
        &self.prior
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.entity
    }

    pub(crate) fn physical_body(&self) -> &[u8] {
        &self.raw[ENTITY_METADATA_HEADER_LEN..]
    }

    pub(crate) fn physical_times(&self) -> Result<(TimeRange, u64)> {
        let header = EntityMetadataHeader::parse(&self.raw)
            .ok_or(Error::CorruptedIndex("headed SKILL header"))?;
        Ok((
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
        ))
    }
}

fn state_only(prior: &SkillRecord, updated: &SkillRecord) -> bool {
    let mut unchanged = updated.clone();
    unchanged.lifecycle_status = prior.lifecycle_status;
    unchanged.approval_status = prior.approval_status;
    &unchanged == prior
}

/// Compare every non-state value, including unknown fields, by its encoded bytes.
/// Map order is immaterial: the document projection moves its text field last.
fn non_state_fields(body: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut cursor = Cursor::new(body);
    let count = match body.first().copied() {
        Some(marker @ 0x80..=0x8f) => {
            cursor.set_position(1);
            u32::from(marker & 0x0f)
        }
        Some(0xde) => {
            let size: [u8; 2] = body
                .get(1..3)
                .ok_or_else(moved)?
                .try_into()
                .map_err(|_| moved())?;
            cursor.set_position(3);
            u32::from(u16::from_be_bytes(size))
        }
        Some(0xdf) => {
            let size: [u8; 4] = body
                .get(1..5)
                .ok_or_else(moved)?
                .try_into()
                .map_err(|_| moved())?;
            cursor.set_position(5);
            u32::from_be_bytes(size)
        }
        _ => return Err(moved()),
    };
    let mut fields = BTreeMap::new();
    let mut state = [false; 2];
    for _ in 0..count {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|_| moved())?;
        let key = key.as_str().ok_or_else(moved)?;
        let start = cursor.position() as usize;
        rmpv::decode::read_value(&mut cursor).map_err(|_| moved())?;
        let end = cursor.position() as usize;
        let state_index = match key {
            "lifecycleStatus" => Some(0),
            "approvalStatus" => Some(1),
            _ => None,
        };
        if let Some(index) = state_index {
            if state[index] {
                return Err(moved());
            }
            state[index] = true;
        } else if fields
            .insert(key.to_owned(), body[start..end].to_vec())
            .is_some()
        {
            return Err(moved());
        }
    }
    if cursor.position() as usize != body.len() || state != [true; 2] {
        return Err(moved());
    }
    Ok(fields)
}
