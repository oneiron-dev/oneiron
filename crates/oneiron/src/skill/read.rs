//! Typed SKILL content reads over one canonical or composed snapshot.

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{ArtifactError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::ManifestDbs;

use super::codec::decode_skill_record;
use super::record::SkillRecord;

pub(crate) fn get_skill_record_on(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SkillRecord>> {
    // A user delete may leave a type-7 tombstone shell whose erased body
    // is not MessagePack. Return absence rather than decoding that shell.
    if crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, id)?.deleted {
        return Ok(None);
    }
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_SKILL {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "entity is not a type-7 SKILL",
        )));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let body = crate::entity_doc::resolve_record_body(store, txn, id, body)?;
    decode_skill_record(&body).map(Some)
}

pub(crate) fn read_skill_record_on(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<SkillRecord> {
    let raw = store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_SKILL {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "entity is not a type-7 SKILL",
        )));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let body = crate::entity_doc::resolve_record_body(store, txn, id, body)?;
    decode_skill_record(&body)
}
