//! Soft-tombstoned reaction audit recovery across sync observer and full remat.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{EntityId, Result, Vault};

pub(crate) fn soft_audit_blob(map: &loro::LoroMap, id: &EntityId, blob: &[u8]) -> bool {
    if EntityMetadataHeader::parse(blob)
        .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_REACTION)
    {
        return false;
    }
    let values = crate::sync::loro_support::tombstone_values_for_id(map, id);
    !values.is_empty()
        && values
            .iter()
            .all(|v| !crate::deletion::decode_tombstone_value(v).is_hard())
        && super::decode_reaction_body(&blob[ENTITY_METADATA_HEADER_LEN..]).is_ok()
}

pub(crate) fn materialize_soft_audit(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map: &loro::LoroMap,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    if !soft_audit_blob(map, id, blob) || vault.local_hard_delete_marker_exists_in_txn(txn, id)? {
        return Ok(false);
    }
    let header = EntityMetadataHeader::parse(blob).expect("soft_audit_blob checked the header");
    let values = crate::sync::loro_support::tombstone_values_for_id(map, id);
    let value = &values[0];
    let data = &blob[ENTITY_METADATA_HEADER_LEN..];
    let mut audit = vault.store.env.nested_write_txn(txn)?;
    let pending = crate::deletion::pending_tombstone_key(
        &crate::deletion::window_label_from_timestamp(header.learned_at),
        id,
    );
    vault
        .store
        .sync_state
        .put(&mut audit, pending.as_str(), value)?;
    vault
        .batch_in()
        .put_replicated(
            id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(&mut audit)?;
    super::stage_revoked(
        &vault.store,
        &mut audit,
        id,
        crate::deletion::decode_tombstone_value(value).deleted_at,
    )?;
    audit.commit()?;
    Ok(true)
}
