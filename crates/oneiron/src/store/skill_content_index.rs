//! Content-hash lookup rows for stored skills and their maintenance.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::side_table::{self, Raw, SideTable};
use crate::write_envelope::skill_record::{SkillContentHash, decode_skill_record};

/// Empty-marker index from a skill content hash to every entity holding it.
pub(crate) const CONTENT_HASH_INDEX: SideTable<([u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_CONTENT_HASH_INDEX);
/// Schema-version byte gating the one-time content-hash-index backfill.
pub(crate) const SCHEMA_VERSION: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SKILL_HUB_CONTENT_HASH_INDEX_SCHEMA_VERSION);
pub(crate) const CONTENT_HASH_INDEX_SCHEMA_VERSION: u8 = 1;

pub(crate) fn maintain_skill_content_hash_index_for_put(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    previous_hash: Option<SkillContentHash>,
    content_hash: Option<SkillContentHash>,
) -> Result<()> {
    if previous_hash != content_hash
        && let Some(previous_hash) = previous_hash
    {
        CONTENT_HASH_INDEX.delete(store, wtxn, &(*previous_hash.as_bytes(), *entity))?;
    }
    if let Some(content_hash) = content_hash {
        CONTENT_HASH_INDEX.put(store, wtxn, &(*content_hash.as_bytes(), *entity), &())?;
    }
    Ok(())
}

pub(crate) fn maintain_skill_content_hash_index_for_delete(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    content_hash: SkillContentHash,
) -> Result<()> {
    CONTENT_HASH_INDEX.delete(store, wtxn, &(*content_hash.as_bytes(), *entity))?;
    Ok(())
}

/// Rebuilds the content-hash → holder index at open time when it is missing or
/// stale (schema-version gated), so import/sync dedup can resolve holders that
/// pre-date the index. ONE-1741: scan verdicts no longer ride this table (they
/// anchor to the content bytes), so this reconstructs ONLY the holder index —
/// the old verdict-dedup migration is gone.
pub(crate) fn backfill_content_hash_index_if_needed(vault: &Vault) -> Result<()> {
    let store = &vault.store;
    let rtxn = store.env.read_txn()?;
    let stored_version = match SCHEMA_VERSION.get(store, &rtxn, &())? {
        Some(raw) if raw.len() == 1 => raw[0],
        Some(_) => return Err(Error::InvalidKey),
        None => 0,
    };
    drop(rtxn);

    if stored_version > CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Err(Error::InvalidKey);
    }
    if stored_version == CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Ok(());
    }

    // Collect holders first, then write: the type-index cursor is dropped
    // before any vault_meta write, matching the proven pre-ONE-1741 pattern.
    let mut wtxn = store.env.write_txn()?;
    let mut holders = Vec::<(SkillContentHash, EntityId)>::new();
    for entry in store.port_entity_ids_by_type(&wtxn, ENTITY_TYPE_SKILL, None)? {
        let entity = entry?;
        let raw = store
            .port_entity_record(&wtxn, &entity)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("skill type index"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill type index"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let record = match decode_skill_record(body) {
            Ok(record) => record,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::write_envelope::skill_record::is_legacy_opaque_skill_body(body) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(content_hash) = record.content_hash {
            holders.push((content_hash, entity));
        }
    }

    for (content_hash, entity) in &holders {
        CONTENT_HASH_INDEX.put(store, &mut wtxn, &(*content_hash.as_bytes(), *entity), &())?;
    }

    SCHEMA_VERSION.put(
        store,
        &mut wtxn,
        &(),
        &vec![CONTENT_HASH_INDEX_SCHEMA_VERSION],
    )?;
    wtxn.commit()?;
    Ok(())
}
