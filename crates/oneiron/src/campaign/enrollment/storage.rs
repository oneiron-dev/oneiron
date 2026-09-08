//! Shared campaign-enrollment storage primitives: schema version, key prefixes, JSON-row codecs, and vault_meta helpers.

use serde::Serialize;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The ONE attempt kind this ticket introduces. No queue enum, no recurrence
/// primitive, no second kind for the outward leg.
pub const CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND: &str = "campaign.enrollment.macro";

/// Schema version shared by every campaign-local row this module persists.
pub const CAMPAIGN_ENROLLMENT_SCHEMA_VERSION: u32 = 1;

pub(super) const ENROLLMENT_EVENT_PREFIX: &[u8] = b"campaign:enrollment_event:v1:";

pub(super) const ENROLLMENT_BASELINE_PREFIX: &[u8] = b"campaign:enrollment_baseline:v1:";

pub(super) const CAMPAIGN_PROGRAM_PREFIX: &[u8] = b"campaign:program:v1:";

pub(super) const CAMPAIGN_PROGRAM_STEP_PREFIX: &[u8] = b"campaign:program_step:v1:";

pub(super) fn keyed(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(prefix.len() + parts.iter().map(|part| part.len()).sum::<usize>());
    key.extend_from_slice(prefix);
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

pub(super) fn baseline_key(query_ref: EntityId) -> Vec<u8> {
    keyed(ENROLLMENT_BASELINE_PREFIX, &[query_ref.as_bytes()])
}

pub(super) fn to_row<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid("campaign enrollment row encode failed"))
}

pub(super) fn from_row<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    context: &'static str,
) -> Result<T> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn pin_schema(schema_version: u32, context: &'static str) -> Result<()> {
    if schema_version == CAMPAIGN_ENROLLMENT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Error::CorruptedIndex(context))
    }
}

pub(super) fn id_from_hex(value: &str, context: &'static str) -> Result<EntityId> {
    EntityId::from_hex(value).map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn hash_from_hex(value: &str, context: &'static str) -> Result<[u8; 32]> {
    bytes_from_hex(value, context)?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn bytes_from_hex(value: &str, context: &'static str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::CorruptedIndex(context));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or(Error::CorruptedIndex(context))?;
        let lo = hex_nibble(pair[1]).ok_or(Error::CorruptedIndex(context))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn read_meta(vault: &Vault, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, key)?
        .map(|bytes| bytes.to_vec()))
}

pub(super) fn put_meta(vault: &Vault, key: &[u8], value: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, key, value)?;
        Ok(())
    })
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
