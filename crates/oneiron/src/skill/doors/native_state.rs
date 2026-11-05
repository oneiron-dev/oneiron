//! Target-bound requests constructible only inside the typed SKILL doors.

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_doc::SkillStateSnapshot;
use crate::error::{ArtifactError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::skill::{SkillLifecycle, SkillRecord, decode_skill_record, encode_skill_record};
use crate::store::Store;
use heed::RoTxn;

/// The operation's actual local door, not a caller-supplied admission label.
enum SkillStateDoor {
    Update,
    Supersede(SkillSupersessionRead),
}

/// The exact successor read by the supersede door in its writer. This read
/// binding is not recipient admission or proof that a remote source is trusted.
pub(crate) struct SkillSupersessionRead {
    entity: EntityId,
    raw: Vec<u8>,
    head: Option<Vec<u8>>,
    body: Vec<u8>,
    document_pin: Option<(EntityId, Vec<u8>)>,
}

impl SkillSupersessionRead {
    fn capture(store: &Store, txn: &RoTxn<'_>, entity: EntityId) -> Result<Self> {
        let raw = store
            .port_entity_raw(txn, &entity)?
            .ok_or(Error::EntityNotFound)?
            .to_vec();
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "entity is not a type-7 SKILL",
            )));
        }
        let body = crate::entity_doc::resolve_record_body(
            store,
            txn,
            &entity,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        // Use the same typed decoder as the original successor read.
        decode_skill_record(&body)?;
        Ok(Self {
            entity,
            head: crate::entity_doc::record_head_bytes(store, txn, &entity)?,
            document_pin: crate::entity_doc::source_document_pin_in_txn(store, txn, &entity)?,
            raw,
            body,
        })
    }

    fn recheck(&self, store: &Store, txn: &RoTxn<'_>) -> Result<SkillRecord> {
        let current = Self::capture(store, txn, self.entity)?;
        if current.raw != self.raw
            || current.head != self.head
            || current.body != self.body
            || current.document_pin != self.document_pin
        {
            return Err(Error::InvariantViolation(
                "native SKILL successor changed during supersession",
            ));
        }
        decode_skill_record(&self.body)
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.entity
    }

    /// Historical source bindings only; no hash establishes admission.
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.raw).as_bytes()
    }

    pub(crate) fn logical_body_fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.body).as_bytes()
    }

    pub(crate) fn document_pin(&self) -> Option<(EntityId, &[u8])> {
        self.document_pin
            .as_ref()
            .map(|(id, frontier)| (*id, frontier.as_slice()))
    }
}

/// A target-bound request, not a committed native fact. The ordinary put
/// gates, scan, caller effects and batch terminal still have to run.
pub(crate) struct SkillStateWrite {
    snapshot: SkillStateSnapshot,
    lifecycle: SkillLifecycle,
    door: SkillStateDoor,
}

impl std::fmt::Debug for SkillStateWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillStateWrite")
            .field("entity", &self.entity())
            .finish_non_exhaustive()
    }
}

impl SkillStateWrite {
    pub(super) fn prepare_update(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        record: &SkillRecord,
    ) -> Result<Option<Self>> {
        let requested = encode_skill_record(record)?;
        let Some(snapshot) = SkillStateSnapshot::capture(store, txn, entity, &requested)? else {
            return Ok(None);
        };
        super::validate_skill_update_door(
            &decode_skill_record(snapshot.logical_prior_body())?,
            record,
        )?;
        Ok(Some(Self {
            snapshot,
            lifecycle: record.lifecycle_status,
            door: SkillStateDoor::Update,
        }))
    }

    pub(super) fn prepare_supersede(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        successor: EntityId,
        record: &SkillRecord,
    ) -> Result<Option<Self>> {
        if entity == successor {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "a skill revision cannot supersede itself",
            )));
        }
        let requested = encode_skill_record(record)?;
        let Some(snapshot) = SkillStateSnapshot::capture(store, txn, entity, &requested)? else {
            return Ok(None);
        };
        let successor = SkillSupersessionRead::capture(store, txn, successor)?;
        super::validate_skill_successor(
            &decode_skill_record(snapshot.logical_prior_body())?,
            &decode_skill_record(&successor.body)?,
        )?;
        if record.lifecycle_status != SkillLifecycle::Superseded {
            return Err(Error::InvariantViolation(
                "native supersession must freeze its old revision",
            ));
        }
        Ok(Some(Self {
            snapshot,
            lifecycle: record.lifecycle_status,
            door: SkillStateDoor::Supersede(successor),
        }))
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.snapshot.entity()
    }

    /// The old scan may update approval; it cannot replace the requested lifecycle.
    pub(crate) fn recheck_final(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        final_body: &[u8],
    ) -> Result<SkillRecord> {
        let record = self.snapshot.recheck(store, txn, entity, final_body)?;
        if record.lifecycle_status != self.lifecycle {
            return Err(Error::InvariantViolation(
                "headed SKILL lifecycle differs from its typed request",
            ));
        }
        match &self.door {
            SkillStateDoor::Update => {
                super::validate_skill_update_door(
                    &decode_skill_record(self.snapshot.logical_prior_body())?,
                    &record,
                )?;
            }
            SkillStateDoor::Supersede(successor) => {
                let new = successor.recheck(store, txn)?;
                super::validate_skill_successor(
                    &decode_skill_record(self.snapshot.logical_prior_body())?,
                    &new,
                )?;
            }
        }
        Ok(record)
    }

    /// The current prior for overwrite validation, never the updated request.
    pub(crate) fn rechecked_prior_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        final_body: &[u8],
    ) -> Result<&[u8]> {
        self.recheck_final(store, txn, entity, final_body)?;
        Ok(self.snapshot.logical_prior_body())
    }

    pub(crate) fn snapshot(&self) -> &SkillStateSnapshot {
        &self.snapshot
    }

    /// None means the closed Update variant, not unknown remote provenance.
    pub(crate) fn superseding_revision(&self) -> Option<&SkillSupersessionRead> {
        match &self.door {
            SkillStateDoor::Update => None,
            SkillStateDoor::Supersede(successor) => Some(successor),
        }
    }
}
