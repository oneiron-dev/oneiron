//! Principal index maintenance and lookup.

use super::codec::{invalid_grant, non_empty_string};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

const PRINCIPAL_INDEX_PREFIX: &[u8] = b"outbound_grant/principal/v1\0";

/// Bound to the same declaration `standing_outbound_grant_principal_index_prefix`
/// spells for the cross-module scanner (`booking`) that binds its own table over
/// this family: a `Vec<u8>` key holding everything after the declared prefix
/// (`principal_len ++ principal ++ id16`), the byte layout
/// `standing_outbound_grant_principal_index_key` already builds.
pub(super) const PRINCIPAL_INDEX: SideTable<Vec<u8>, (), Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_PRINCIPAL_INDEX);

pub(crate) fn standing_outbound_grant_principal_index_prefix(
    principal_ref: &str,
) -> Result<Vec<u8>> {
    let principal_ref = non_empty_string(principal_ref)?;
    let principal_len = u16::try_from(principal_ref.len()).map_err(|_| invalid_grant())?;
    let mut key = Vec::with_capacity(PRINCIPAL_INDEX_PREFIX.len() + 2 + principal_ref.len());
    key.extend_from_slice(PRINCIPAL_INDEX_PREFIX);
    key.extend_from_slice(&principal_len.to_be_bytes());
    key.extend_from_slice(principal_ref.as_bytes());
    Ok(key)
}

pub(super) fn standing_outbound_grant_principal_index_key(
    principal_ref: &str,
    id: &EntityId,
) -> Result<Vec<u8>> {
    let mut key = standing_outbound_grant_principal_index_prefix(principal_ref)?;
    key.extend_from_slice(id.as_bytes());
    Ok(key)
}

/// The `PRINCIPAL_INDEX` table key: everything after the declared prefix in a
/// full row key already built by [`standing_outbound_grant_principal_index_key`].
pub(super) fn principal_index_table_key(full_key: &[u8]) -> Vec<u8> {
    full_key[PRINCIPAL_INDEX_PREFIX.len()..].to_vec()
}

pub(crate) fn standing_outbound_grant_principal_index_entity_id(
    key: &[u8],
    principal_ref: &str,
) -> Result<EntityId> {
    let prefix = standing_outbound_grant_principal_index_prefix(principal_ref)?;
    if key.len() != prefix.len() + ENTITY_ID_LEN || !key.starts_with(&prefix) {
        return Err(Error::CorruptedIndex("outbound grant principal index key"));
    }
    let mut raw_id = [0; ENTITY_ID_LEN];
    raw_id.copy_from_slice(&key[prefix.len()..]);
    EntityId::from_bytes(raw_id)
        .map_err(|_| Error::CorruptedIndex("outbound grant principal index key"))
}

/// Every grant id indexed under `principal_ref`, in key order.
pub(crate) fn standing_outbound_grant_ids_for_principal(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &str,
) -> Result<Vec<EntityId>> {
    let prefix = standing_outbound_grant_principal_index_prefix(principal_ref)?;
    PRINCIPAL_INDEX
        .scan_keys(store, txn, &principal_index_table_key(&prefix))?
        .iter()
        .map(|key| {
            standing_outbound_grant_principal_index_entity_id(
                &PRINCIPAL_INDEX.key_bytes(key),
                principal_ref,
            )
        })
        .collect()
}

pub(crate) fn rebuild_checkpoint_grant_index(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<()> {
    let record = super::decode_standing_outbound_grant_body(body)?;
    let full_key = standing_outbound_grant_principal_index_key(&record.principal_ref, &id)?;
    PRINCIPAL_INDEX.put(store, txn, &principal_index_table_key(&full_key), &())?;
    Ok(())
}
