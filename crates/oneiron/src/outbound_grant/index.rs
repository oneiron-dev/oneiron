//! Principal index maintenance and lookup.

use super::codec::{invalid_grant, non_empty_string};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

const PRINCIPAL_INDEX_PREFIX: &[u8] = b"outbound_grant/principal/v1\0";

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
