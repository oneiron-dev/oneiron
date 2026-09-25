//! Source-only retirement and payload cleanup, shared by local/raw/replay/erase.
//! Retained index rows contain only holder/hash identities, never source bytes.
use super::package_codec::invalid;
use super::source_carrier::{decode_source_carrier, source_carrier_id};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SKILL};
use crate::skill::{SkillContentHash, SkillRecord};
use crate::store::Store;

const INDEX: &[u8] = b"skill_hub/source-custody/v1\0";
const RETIRED: &[u8] = b"skill_hub/source-retired/v1\0";
const LIVE: &[u8] = &[0];
const DEAD: &[u8] = &[1];
const UNSEEN: &[u8] = &[2];
const BINDING: &[u8] = b"skill_hub/source-binding/v1\0";

fn owner_key(prefix: &[u8], owner: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(owner.as_bytes());
    key
}
fn source_key(owner: &EntityId, hash: &SkillContentHash) -> Vec<u8> {
    let mut key = owner_key(INDEX, owner);
    key.extend_from_slice(hash.as_bytes());
    key
}

/// Pure preflight: a retired holder/revision cannot regain its byte custody.
/// An absent holder is allowed so clean sync orders remain symmetric.
pub(super) fn check_source_custody(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
    hash: &SkillContentHash,
) -> Result<()> {
    if store.off_record_sessions.contains_entity(holder)? {
        return Err(Error::OffRecord(
            OffRecordError::OffRecordTaintedBaseWrite {
                entity_ref: holder.to_hex(),
            },
        ));
    }
    check_source_target(store, txn, holder)?;
    if store
        .vault_meta
        .get(txn, &source_key(holder, hash))?
        .is_some_and(|value| value.as_ref() != LIVE)
    {
        return Err(invalid("source custody has been retired"));
    }
    if let Some(raw) = store.entities.get(txn, holder.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("source holder header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL || raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Err(invalid(
                "source holder must be a live SKILL or not yet materialized",
            ));
        }
    }
    Ok(())
}

pub(super) fn check_source_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if store
        .vault_meta
        .get(txn, &owner_key(RETIRED, id))?
        .is_some()
        || store
            .sync_state
            .get(txn, &format!("dt:{}", id.to_hex()))?
            .is_some()
    {
        return Err(invalid("source custody target has been retired"));
    }
    Ok(())
}

/// A once-admitted source ID cannot be reused as an unrelated entity after
/// erasure. This binds only that concrete ID; it reserves no generic namespace.
pub(super) fn validate_registered_source_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
    let Some(binding) = store.vault_meta.get(txn, &owner_key(BINDING, id))? else {
        return Ok(());
    };
    if binding.len() != 48 {
        return Err(Error::CorruptedIndex("source binding"));
    }
    if entity_type != ENTITY_TYPE_ASSET {
        return Err(invalid("source ID cannot change type"));
    }
    let Some((holder, package)) = decode_source_carrier(bytes)? else {
        return Err(invalid("source ID cannot become an unrelated asset"));
    };
    if &binding[..16] != holder.as_bytes() || &binding[16..] != package.content_hash()?.as_bytes() {
        return Err(invalid("source ID binding changed"));
    }
    Ok(())
}

fn source_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<(SkillContentHash, u8)>> {
    let prefix = owner_key(INDEX, holder);
    let mut rows = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        let hash = SkillContentHash::from_bytes(
            key[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("source custody index key"))?,
        );
        if value.as_ref() != LIVE && value.as_ref() != DEAD && value.as_ref() != UNSEEN {
            return Err(Error::CorruptedIndex("source custody index value"));
        }
        rows.push((hash, value[0]));
    }
    Ok(rows)
}

pub(crate) fn source_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<bool> {
    Ok(source_rows(store, txn, holder)?
        .iter()
        .any(|(_, state)| *state == 0))
}

/// Only IDs remain after deletion, so the existing hard-history sweep can
/// cover every revision and pending carrier without retaining its payload.
pub(crate) fn source_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<EntityId>> {
    source_rows(store, txn, holder)?
        .iter()
        .filter(|(_, state)| *state != 2)
        .map(|(hash, _)| source_carrier_id(holder, hash))
        .collect()
}

/// Called after all put refusals and before commit. Source revisions retire
/// only the prior hash, never a pending new version or another SKILL holder.
pub(crate) fn stage_source_custody_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
    previous: Option<&SkillRecord>,
    current: Option<&SkillRecord>,
) -> Result<()> {
    if entity_type == ENTITY_TYPE_ASSET
        && let Some((holder, package)) = decode_source_carrier(bytes)?
    {
        let hash = package.content_hash()?;
        let mut binding = holder.as_bytes().to_vec();
        binding.extend_from_slice(hash.as_bytes());
        store
            .vault_meta
            .put(txn, &owner_key(BINDING, id), &binding)?;
        store
            .vault_meta
            .put(txn, &source_key(&holder, &hash), LIVE)?;
    }
    // A pending source cannot reserve another entity's kind. If the actual
    // holder is born as a non-SKILL, discard those invalid pending carriers
    // without refusing that unrelated entity or minting deletion authority.
    if entity_type != ENTITY_TYPE_SKILL {
        for (hash, state) in source_rows(store, txn, id)? {
            if state == 0 {
                retire_revision(store, txn, id, &hash)?;
            }
        }
    }
    if let (Some(previous), Some(current)) = (previous, current)
        && previous.content_hash != current.content_hash
    {
        super::package_codec::remove_package_sidecar_in_txn(store, txn, id)?;
        if let Some(hash) = previous.content_hash {
            retire_revision(store, txn, id, &hash)?;
        }
    }
    Ok(())
}

fn retire_revision(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
    hash: &SkillContentHash,
) -> Result<()> {
    let carrier = source_carrier_id(holder, hash)?;
    let seen = store
        .vault_meta
        .get(txn, &owner_key(BINDING, &carrier))?
        .is_some();
    // Do not remove an unrelated row that merely occupies a derived ID.
    if seen && let Some(raw) = store.entities.get(txn, carrier.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("source custody carrier header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex("source custody carrier type"));
        }
        let (bound_holder, package) = decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("source custody carrier body"))?
            .ok_or(Error::CorruptedIndex("source custody carrier body"))?;
        if bound_holder != *holder
            || package
                .content_hash()
                .map_err(|_| Error::CorruptedIndex("source custody carrier hash"))?
                != *hash
        {
            return Err(Error::CorruptedIndex("source custody carrier binding"));
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &carrier)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &carrier, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    store.vault_meta.put(
        txn,
        &source_key(holder, hash),
        if seen { DEAD } else { UNSEEN },
    )?;
    Ok(())
}

/// Source-only denial fact, not a fabricated generic tombstone or delete grant.
/// Replay calls this even when the holder has never had a local header.
pub(crate) fn retire_source_holder_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &owner_key(RETIRED, holder), &[])?;
    super::package_codec::remove_package_sidecar_in_txn(store, txn, holder)?;
    for (hash, state) in source_rows(store, txn, holder)? {
        if state == 0 {
            retire_revision(store, txn, holder, &hash)?;
        }
    }
    Ok(())
}

/// Every active-store purge calls this before tearing down its entity row.
/// Deleting a carrier also deletes the sidecar's duplicate bytes, not its SKILL.
pub(crate) fn remove_source_custody_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let raw = store.entities.get(txn, id.as_bytes())?;
    if let Some(raw) = &raw {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("source delete header"))?;
        if header.entity_type == ENTITY_TYPE_ASSET
            && let Some((holder, package)) =
                decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])
                    .map_err(|_| Error::CorruptedIndex("source delete body"))?
        {
            let hash = package.content_hash()?;
            if source_carrier_id(&holder, &hash)? != *id {
                return Err(Error::CorruptedIndex("source delete identity"));
            }
            store
                .vault_meta
                .put(txn, &source_key(&holder, &hash), DEAD)?;
            super::package_codec::remove_matching_package_sidecar_in_txn(
                store, txn, &holder, &hash,
            )?;
            return Ok(());
        }
        if header.entity_type == ENTITY_TYPE_SKILL {
            return retire_source_holder_in_txn(store, txn, id);
        }
    }
    if source_custody_exists_in_txn(store, txn, id)? {
        return retire_source_holder_in_txn(store, txn, id);
    }
    super::package_codec::remove_package_sidecar_in_txn(store, txn, id)
}
