//! Wire protocol encoding/decoding for WebSocket transport.
//!
//! Shared between client and server. Defines the custom message tags
//! and encoding/decoding for WindowSync, BulkTransfer, BulkTransferDone.
//! Engine-agnostic — no CRDT library types here.

use crate::sync::types::parse_window_key_str;

// ─── Custom Message Tags ──────────────────────────────────────────────────────

/// CRDT update bytes for the root doc.
pub const TAG_SYNC_UPDATE: u8 = 0;
/// Custom awareness state (JSON-encoded).
pub const TAG_AWARENESS: u8 = 1;
/// Serialized VersionVector for sync negotiation.
pub const TAG_VERSION_VECTOR: u8 = 2;

/// WindowSync: `[window_key_len:1][window_key][sub_tag:1][payload]`.
pub const TAG_WINDOW_SYNC: u8 = 10;
/// BulkTransfer: `[window_key_len:1][window_key][zstd_msgpack]`.
pub const TAG_BULK_TRANSFER: u8 = 20;
/// BulkTransferDone: `[window_key_len:1][window_key][state_len:4BE][state]`.
pub const TAG_BULK_TRANSFER_DONE: u8 = 21;

/// Sub-tags within WindowSync messages.
pub mod window_sub_tags {
    /// CRDT update bytes for the window doc.
    pub const UPDATE: u8 = 0;
    /// Version vector request (sender's VV).
    pub const VV_REQUEST: u8 = 2;
    /// Version vector response (sender's VV).
    pub const VV_RESPONSE: u8 = 3;
}

/// Maximum window key length (YYYY-MM = 7 bytes).
pub const MAX_WINDOW_KEY_LEN: usize = 7;

// ─── Wire Format Encoding ─────────────────────────────────────────────────────

/// Encodes a WindowSync message for the wire.
///
/// Format: `[TAG_WINDOW_SYNC:1][window_key_len:1][window_key][sub_tag:1][payload]`
///
/// # Panics
///
/// Panics if `window_key` is empty or exceeds `MAX_WINDOW_KEY_LEN` bytes.
pub fn encode_window_sync(window_key: &str, sub_tag: u8, payload: &[u8]) -> Vec<u8> {
    let key_bytes = window_key.as_bytes();
    assert!(
        !key_bytes.is_empty()
            && key_bytes.len() <= MAX_WINDOW_KEY_LEN
            && parse_window_key_str(window_key).is_some(),
        "window key length {} exceeds MAX_WINDOW_KEY_LEN ({})",
        key_bytes.len(),
        MAX_WINDOW_KEY_LEN,
    );
    let mut buf = Vec::with_capacity(3 + key_bytes.len() + payload.len());
    buf.push(TAG_WINDOW_SYNC);
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf.push(sub_tag);
    buf.extend_from_slice(payload);
    buf
}

/// Decodes a WindowSync payload (after tag byte has been consumed).
/// Returns `(window_key, sub_tag, payload)`.
pub fn decode_window_sync(data: &[u8]) -> Result<(&str, u8, &[u8]), TransportError> {
    if data.is_empty() {
        return Err(TransportError::InvalidPayload("empty WindowSync"));
    }
    let key_len = data[0] as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(TransportError::InvalidWindowKey);
    }
    if data.len() < 1 + key_len + 1 {
        return Err(TransportError::InvalidPayload("WindowSync too short"));
    }
    let key =
        std::str::from_utf8(&data[1..1 + key_len]).map_err(|_| TransportError::InvalidWindowKey)?;
    if parse_window_key_str(key).is_none() {
        return Err(TransportError::InvalidWindowKey);
    }
    let sub_tag = data[1 + key_len];
    let payload = &data[2 + key_len..];
    Ok((key, sub_tag, payload))
}

/// Encodes a BulkTransfer message for the wire.
///
/// # Panics
///
/// Panics if `window_key` is empty or exceeds `MAX_WINDOW_KEY_LEN` bytes.
pub fn encode_bulk_transfer(window_key: &str, zstd_data: &[u8]) -> Vec<u8> {
    let key_bytes = window_key.as_bytes();
    assert!(
        !key_bytes.is_empty()
            && key_bytes.len() <= MAX_WINDOW_KEY_LEN
            && parse_window_key_str(window_key).is_some(),
        "window key length {} exceeds MAX_WINDOW_KEY_LEN ({})",
        key_bytes.len(),
        MAX_WINDOW_KEY_LEN,
    );
    let mut buf = Vec::with_capacity(2 + key_bytes.len() + zstd_data.len());
    buf.push(TAG_BULK_TRANSFER);
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf.extend_from_slice(zstd_data);
    buf
}

/// Decodes a BulkTransfer payload (after tag byte has been consumed).
pub fn decode_bulk_transfer(data: &[u8]) -> Result<(&str, &[u8]), TransportError> {
    if data.is_empty() {
        return Err(TransportError::InvalidPayload("empty BulkTransfer"));
    }
    let key_len = data[0] as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(TransportError::InvalidWindowKey);
    }
    if data.len() < 1 + key_len {
        return Err(TransportError::InvalidPayload("BulkTransfer too short"));
    }
    let key =
        std::str::from_utf8(&data[1..1 + key_len]).map_err(|_| TransportError::InvalidWindowKey)?;
    if parse_window_key_str(key).is_none() {
        return Err(TransportError::InvalidWindowKey);
    }
    Ok((key, &data[1 + key_len..]))
}

/// Encodes a BulkTransferDone message for the wire.
///
/// # Panics
///
/// Panics if `window_key` is empty or exceeds `MAX_WINDOW_KEY_LEN` bytes, or if
/// `doc_state` exceeds the BulkTransferDone u32 state-length field.
pub fn encode_bulk_transfer_done(window_key: &str, doc_state: &[u8]) -> Vec<u8> {
    encode_bulk_transfer_done_checked(window_key, doc_state)
        .expect("BulkTransferDone state length must fit in u32")
}

/// Encodes a BulkTransferDone message for the wire with checked state length.
///
/// Returns `Err(TransportError::InvalidPayload(_))` if `doc_state` exceeds the
/// BulkTransferDone u32 state-length field. Use this variant when callers need
/// to propagate oversized state errors; `encode_bulk_transfer_done` keeps the
/// existing panicking API.
///
/// # Panics
///
/// Panics if `window_key` is empty or exceeds `MAX_WINDOW_KEY_LEN` bytes.
pub fn encode_bulk_transfer_done_checked(
    window_key: &str,
    doc_state: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let key_bytes = window_key.as_bytes();
    assert!(
        !key_bytes.is_empty()
            && key_bytes.len() <= MAX_WINDOW_KEY_LEN
            && parse_window_key_str(window_key).is_some(),
        "window key length {} exceeds MAX_WINDOW_KEY_LEN ({})",
        key_bytes.len(),
        MAX_WINDOW_KEY_LEN,
    );
    let state_len = checked_bulk_transfer_done_state_len(doc_state.len())?;
    let mut buf = Vec::with_capacity(2 + key_bytes.len() + 4 + doc_state.len());
    buf.push(TAG_BULK_TRANSFER_DONE);
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf.extend_from_slice(&state_len.to_be_bytes());
    buf.extend_from_slice(doc_state);
    Ok(buf)
}

fn checked_bulk_transfer_done_state_len(state_len: usize) -> Result<u32, TransportError> {
    u32::try_from(state_len)
        .map_err(|_| TransportError::InvalidPayload("BulkTransferDone state too large"))
}

/// Decodes a BulkTransferDone payload (after tag byte has been consumed).
pub fn decode_bulk_transfer_done(data: &[u8]) -> Result<(&str, &[u8]), TransportError> {
    if data.is_empty() {
        return Err(TransportError::InvalidPayload("empty BulkTransferDone"));
    }
    let key_len = data[0] as usize;
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(TransportError::InvalidWindowKey);
    }
    if data.len() < 1 + key_len + 4 {
        return Err(TransportError::InvalidPayload("BulkTransferDone too short"));
    }
    let key =
        std::str::from_utf8(&data[1..1 + key_len]).map_err(|_| TransportError::InvalidWindowKey)?;
    if parse_window_key_str(key).is_none() {
        return Err(TransportError::InvalidWindowKey);
    }
    let off = 1 + key_len;
    let state_len = u32::from_be_bytes(
        data[off..off + 4]
            .try_into()
            .map_err(|_| TransportError::InvalidPayload("bad state_len"))?,
    ) as usize;
    let state_start = off + 4;
    if data.len() < state_start + state_len {
        return Err(TransportError::InvalidPayload("state truncated"));
    }
    Ok((key, &data[state_start..state_start + state_len]))
}

// ─── Transport Error ──────────────────────────────────────────────────────────

/// Transport-level errors for the sync wire protocol.
#[derive(Debug)]
pub enum TransportError {
    InvalidWindowKey,
    InvalidPayload(&'static str),
    UnknownTag(u8),
    FrameTooLarge { size: usize, max: usize },
    WebSocket(String),
    ConnectionClosed,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWindowKey => write!(f, "invalid window key"),
            Self::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            Self::UnknownTag(tag) => write!(f, "unknown tag: {tag}"),
            Self::FrameTooLarge { size, max } => write!(f, "frame too large: {size} (max {max})"),
            Self::WebSocket(msg) => write!(f, "websocket error: {msg}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_sync_roundtrip() {
        let key = "2026-02";
        let msg = b"test payload";
        let encoded = encode_window_sync(key, window_sub_tags::UPDATE, msg);
        assert_eq!(encoded[0], TAG_WINDOW_SYNC);
        let (dk, sub, dm) = decode_window_sync(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(sub, window_sub_tags::UPDATE);
        assert_eq!(dm, msg);
    }

    #[test]
    fn bulk_transfer_roundtrip() {
        let key = "2025-11";
        let data = vec![1, 2, 3];
        let encoded = encode_bulk_transfer(key, &data);
        assert_eq!(encoded[0], TAG_BULK_TRANSFER);
        let (dk, dd) = decode_bulk_transfer(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(dd, &data[..]);
    }

    #[test]
    fn bulk_transfer_done_roundtrip() {
        let key = "2025-09";
        let state = vec![10, 20];
        let encoded = encode_bulk_transfer_done(key, &state);
        assert_eq!(encoded[0], TAG_BULK_TRANSFER_DONE);
        let (dk, ds) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(ds, &state[..]);
    }

    #[test]
    fn bulk_transfer_done_empty_state() {
        let encoded = encode_bulk_transfer_done("2025-08", &[]);
        let (k, s) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
        assert_eq!(k, "2025-08");
        assert!(s.is_empty());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn bulk_transfer_done_checked_encoder_rejects_u32_overflow_len() {
        let err = checked_bulk_transfer_done_state_len(u32::MAX as usize + 1).unwrap_err();

        assert!(matches!(
            err,
            TransportError::InvalidPayload("BulkTransferDone state too large")
        ));
    }

    #[test]
    fn reject_invalid_key_len() {
        assert!(decode_window_sync(&[0, 0]).is_err()); // key_len = 0
        let mut d = vec![8];
        d.extend_from_slice(b"12345678");
        d.push(0); // sub_tag
        assert!(decode_window_sync(&d).is_err()); // key_len = 8
    }

    #[test]
    fn reject_invalid_calendar_window_keys() {
        let mut invalid = vec![7];
        invalid.extend_from_slice(b"2026-13");
        invalid.push(window_sub_tags::UPDATE);
        assert!(matches!(
            decode_window_sync(&invalid),
            Err(TransportError::InvalidWindowKey)
        ));

        let mut pre_epoch = vec![7];
        pre_epoch.extend_from_slice(b"1969-12");
        pre_epoch.push(window_sub_tags::UPDATE);
        assert!(matches!(
            decode_window_sync(&pre_epoch),
            Err(TransportError::InvalidWindowKey)
        ));
    }

    #[test]
    fn reject_invalid_bulk_window_keys() {
        let mut invalid = vec![7];
        invalid.extend_from_slice(b"2026-13");
        invalid.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(
            decode_bulk_transfer(&invalid),
            Err(TransportError::InvalidWindowKey)
        ));

        let mut pre_epoch = vec![7];
        pre_epoch.extend_from_slice(b"1969-12");
        pre_epoch.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            decode_bulk_transfer_done(&pre_epoch),
            Err(TransportError::InvalidWindowKey)
        ));
    }
}
