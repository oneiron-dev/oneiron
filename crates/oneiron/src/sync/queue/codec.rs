//! Key/value encode/decode plus metadata codecs.

use super::{
    DELETE_BEARING_PREFIX, EMBED_PREFIX, ERR_SYNC_QUEUE_EMBED_ROW, ERR_SYNC_QUEUE_UPDATE_ROW,
    QueuedEmbedJob, QueuedUpdate, UPDATE_PREFIX,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::transport::MAX_WINDOW_KEY_LEN;
use crate::sync::types::parse_window_key_str;

// ─── Key Encoding ────────────────────────────────────────────────────────────

/// Encodes an update queue key: `q:{seq:8BE}` (10 bytes).
pub(super) fn encode_update_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(UPDATE_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Encodes a delete-bearing marker key: `d:{seq:8BE}` (10 bytes).
pub(super) fn encode_delete_bearing_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(DELETE_BEARING_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Decodes the sequence number from a delete-bearing marker key.
pub(super) fn decode_delete_bearing_key(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(DELETE_BEARING_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

/// Decodes the sequence number from an update queue key.
pub(super) fn decode_update_key(key: &[u8]) -> Result<u64> {
    let seq = key
        .strip_prefix(UPDATE_PREFIX)
        .ok_or(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?;
    Ok(u64::from_be_bytes(seq.try_into().map_err(|_| {
        Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW)
    })?))
}

/// Encodes an update value: `[window_key_len:1][window_key][encoded_update]`.
pub(super) fn encode_update_value(window_key: &str, update_bytes: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = window_key.as_bytes();
    if key_bytes.is_empty()
        || key_bytes.len() > MAX_WINDOW_KEY_LEN
        || parse_window_key_str(window_key).is_none()
    {
        return Err(Error::InvalidKey);
    }
    let mut value = Vec::with_capacity(1 + key_bytes.len() + update_bytes.len());
    value.push(key_bytes.len() as u8);
    value.extend_from_slice(key_bytes);
    value.extend_from_slice(update_bytes);
    Ok(value)
}

/// Decodes an update value into (window_key, encoded_update).
fn decode_update_value(value: &[u8]) -> Result<(String, Vec<u8>)> {
    let (window_key, encoded) = decode_update_value_parts(value)?;
    Ok((window_key.to_string(), encoded.to_vec()))
}

pub(super) fn decode_update_value_parts(value: &[u8]) -> Result<(&str, &[u8])> {
    let Some((&key_len, rest)) = value.split_first() else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    };
    let key_len = key_len as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    let Some((window_key_bytes, encoded)) = rest.split_at_checked(key_len) else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    };
    let window_key = std::str::from_utf8(window_key_bytes)
        .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW))?;
    if parse_window_key_str(window_key).is_none() {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_UPDATE_ROW));
    }
    Ok((window_key, encoded))
}

pub(super) fn decode_update_row(key: &[u8], value: &[u8]) -> Result<QueuedUpdate> {
    let seq = decode_update_key(key)?;
    let (window_key, encoded) = decode_update_value(value)?;
    Ok(QueuedUpdate {
        seq,
        window_key,
        encoded,
    })
}

pub(super) fn validate_update_row(key: &[u8], value: &[u8]) -> Result<()> {
    let _ = decode_update_key(key)?;
    let _ = decode_update_value_parts(value)?;
    Ok(())
}

/// Encodes an embed job key: `e:{entity_id:16}` (18 bytes).
pub(super) fn encode_embed_key(entity_id: &EntityId) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[0..2].copy_from_slice(EMBED_PREFIX);
    key[2..18].copy_from_slice(entity_id.as_bytes());
    key
}

/// Decodes an entity ID from an embed job key.
pub(super) fn decode_embed_key(key: &[u8]) -> Result<EntityId> {
    let bytes = key
        .strip_prefix(EMBED_PREFIX)
        .ok_or(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?;
    EntityId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?,
    )
    .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))
}

pub(super) fn decode_embed_job_row(key: &[u8], value: &[u8]) -> Result<QueuedEmbedJob> {
    let entity_id = decode_embed_key(key)?;
    let (priority, queued_at) = decode_embed_job_value(value)?;
    Ok(QueuedEmbedJob {
        entity_id,
        priority,
        queued_at,
    })
}

pub(super) fn encode_embed_job_value(priority: u8, queued_at: u64) -> [u8; 9] {
    let mut value = [0_u8; 9];
    value[0] = priority;
    value[1..].copy_from_slice(&queued_at.to_be_bytes());
    value
}

pub(super) fn decode_embed_job_value(value: &[u8]) -> Result<(u8, u64)> {
    let Some((&priority, queued_at_bytes)) = value.split_first() else {
        return Err(Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW));
    };
    let queued_at = u64::from_be_bytes(
        queued_at_bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_SYNC_QUEUE_EMBED_ROW))?,
    );
    Ok((priority, queued_at))
}

pub(super) fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().min(u128::from(u64::MAX)) as u64)
}

pub(super) fn decode_last_update_seq_metadata(raw: &[u8]) -> Result<u64> {
    if raw.len() != 8 {
        return Err(Error::CorruptedIndex("sync queue metadata"));
    }
    let bytes = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("sync queue metadata"))?;
    Ok(u64::from_le_bytes(bytes))
}
