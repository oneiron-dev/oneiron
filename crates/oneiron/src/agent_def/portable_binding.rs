//! Frozen source tree identity at genuine local birth. Not an execution grant.
use super::portable::{agent_pack_files, resolve_agent_skill_refs, select_agent_knowledge};
use super::{AgentDefinition, decode_agent_definition};
use crate::batch::export::ExportEntity;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::serialize::ExportBody;
use crate::skill::{SkillContentHash, decode_skill_record};
use crate::store::Store;

// Work bound for source composition reads; never silently truncate a hashed tree.
const SOURCE_SCAN_LIMIT: usize = 100_000;

fn key(id: &EntityId) -> Vec<u8> {
    let mut key = b"agent_def/portable-birth/v1\0".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

pub(crate) fn agent_fork_hash_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SkillContentHash>> {
    if let Some(raw) = store.vault_meta.get(txn, &key(id))? {
        return decode_binding(&raw).map(|(_, hash)| Some(hash));
    }
    super::read_birth_source(store, txn, id)?
        .map(|source| {
            crate::skill::SkillContentHash::parse_hex(
                source
                    .tree
                    .content_hash
                    .as_deref()
                    .ok_or_else(|| Error::CorruptedIndex("birth source hash"))?,
            )
        })
        .transpose()
}

fn decode_binding(raw: &[u8]) -> Result<(EntityId, SkillContentHash)> {
    if raw.len() != 48 {
        return Err(Error::CorruptedIndex("agent portable birth binding"));
    }
    let source = crate::entity_id::parse_entity_id(&raw[..16], "agent portable source")?;
    let hash: [u8; 32] = raw[16..]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("agent portable hash"))?;
    Ok((source, SkillContentHash::from_bytes(hash)))
}
fn put_binding(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    source: &EntityId,
    hash: SkillContentHash,
) -> Result<()> {
    let mut bytes = source.as_bytes().to_vec();
    bytes.extend_from_slice(hash.as_bytes());
    store.vault_meta.put(txn, &key(id), &bytes)?;
    Ok(())
}

/// Called only in apply_put's genuine local AGENT_DEF create arm. If a native
/// composition is not hash-resolvable, leave the binding absent. Never backfill
/// a historic fork from whatever its parent happens to contain at export time.
pub(crate) fn bind_agent_birth_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    created: &AgentDefinition,
) -> Result<Option<(EntityId, Vec<u8>)>> {
    if created.source == crate::claim::ClaimSource::Imported {
        return Ok(None);
    }
    if let Some(raw) = store.vault_meta.get(txn, &key(id))? {
        let (source, _) = decode_binding(&raw)?;
        if source != created.forked_from.unwrap_or(*id) {
            return Err(Error::InvalidConfig(
                "agent fork origin cannot change after deletion".into(),
            ));
        }
        return Ok(None);
    }
    let (source_id, def) = if let Some(parent) = created.forked_from {
        if store.off_record_sessions.contains_entity(&parent)?
            || !crate::vault::live_entity_row_in_txn(store, txn, &parent)?.is_live()
            || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, &parent)?.is_empty()
        {
            return Ok(None);
        }
        let raw = store
            .entities
            .get(txn, parent.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("agent parent"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::EntityNotFound);
        }
        (
            parent,
            decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])?,
        )
    } else {
        (*id, created.clone())
    };
    let skills = read_portable_skills(store, txn, &def)?;
    let claims = read_portable_knowledge(store, txn, &source_id)?;
    let Some(refs) = resolve_agent_skill_refs(&def, &skills) else {
        return Ok(None);
    };
    let files = agent_pack_files(
        &source_id,
        &def,
        &refs,
        &select_agent_knowledge(&source_id, &claims),
    )?;
    let tree = crate::serialize::export_source_tree(&files)?;
    if let Some(hash) = &tree.content_hash {
        put_binding(
            store,
            txn,
            id,
            &source_id,
            SkillContentHash::parse_hex(hash)?,
        )?;
    }
    if tree.content_hash.is_some() {
        return super::portable_source::encode_birth_source(id, created, &source_id, &def, tree)
            .map(Some);
    }
    Ok(None)
}

fn read_portable_skills(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    def: &AgentDefinition,
) -> Result<Vec<(EntityId, crate::skill::SkillRecord)>> {
    let mut skills = Vec::new();
    if !def.skills.is_empty() {
        for (scanned, entry) in store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_SKILL])?
            .enumerate()
        {
            if scanned >= SOURCE_SCAN_LIMIT {
                return Err(Error::IndexOverflow("agent source skills"));
            }
            let (key, _) = entry?;
            let row_id = crate::vault::entity_id_from_type_index_key(&key)?;
            if excluded(store, txn, &row_id)? {
                continue;
            }
            let raw = store
                .entities
                .get(txn, row_id.as_bytes())?
                .ok_or(Error::CorruptedIndex("agent skill index"))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("agent skill header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL {
                return Err(Error::CorruptedIndex("agent skill type"));
            }
            if let Ok(record) = decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]) {
                skills.push((row_id, record));
            }
        }
    }
    Ok(skills)
}
fn read_portable_knowledge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source_id: &EntityId,
) -> Result<Vec<ExportEntity>> {
    let mut claims = Vec::new();
    let mut prefix = source_id.as_bytes().to_vec();
    prefix.push(crate::edge::EdgeKind::ClaimOf as u8);
    for (scanned, entry) in store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
        if scanned >= SOURCE_SCAN_LIMIT {
            return Err(Error::IndexOverflow("agent selected knowledge"));
        }
        let (key, value) = entry?;
        let row_id = crate::edge::parse_strict_edge_record(&key, &value)?.target;
        if excluded(store, txn, &row_id)? {
            continue;
        }
        let Some(raw) = store.entities.get(txn, row_id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("agent knowledge header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        claims.push(ExportEntity {
            id: row_id.to_hex(),
            entity_type: header.entity_type,
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            body: ExportBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..], header.entity_type),
        });
    }
    Ok(claims)
}

fn excluded(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store.off_record_sessions.contains_entity(id)?
        || !crate::vault::live_entity_row_in_txn(store, txn, id)?.is_live()
        || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, id)?.is_empty())
}

/// Foreign lineage is archival provenance only. The caller has already admitted
/// a disabled/proposed AGENT_DEF through the ordinary local gate in this txn.
/// Do not call for preexisting rows: they keep their own birth binding.
pub(crate) fn import_agent_fork_hash_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hash: Option<&str>,
) -> Result<()> {
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("imported agent header"))?;
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        return Err(Error::EntityNotFound);
    }
    let def = decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if def.enabled
        || def.ceiling != super::AgentCeiling::Proposed
        || def.approval_status != crate::claim::ClaimApprovalStatus::Proposed
        || def.source != crate::claim::ClaimSource::Imported
    {
        return Err(Error::InvalidConfig(
            "archive agent binding requires inert imported definition".into(),
        ));
    }
    match hash {
        Some(hash) => {
            put_binding(
                store,
                txn,
                id,
                &def.forked_from.unwrap_or(*id),
                SkillContentHash::parse_hex(hash)?,
            )?;
        }
        None => {
            store.vault_meta.delete(txn, &key(id))?;
        }
    }
    Ok(())
}
