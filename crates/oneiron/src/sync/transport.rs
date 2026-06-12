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
/// Loro binary `VersionVector::encode()` bytes for sync negotiation.
pub const TAG_VERSION_VECTOR: u8 = 2;
/// Protocol-version hello: `[TAG_PROTOCOL_HELLO:1][version:1]`.
///
/// The client's FIRST frame on every connection. The server checks the
/// version byte and closes with a 4xxx code on mismatch, so the NEXT wire
/// break is detectable instead of surfacing as garbled decode errors
/// mid-sync (ONE-1127).
pub const TAG_PROTOCOL_HELLO: u8 = 3;

/// Current sync wire-protocol version.
///
/// Bump on any wire break (tag layout, payload encoding, VV encoding).
/// v1 = binary Loro VVs + delta export + protocol hello (ONE-1127).
pub const PROTOCOL_VERSION: u8 = 1;

/// Shared 8 MB cap for decoded payloads: bulk-transfer decompression and
/// root-doc imports both refuse anything larger (decompression-bomb /
/// memory-exhaustion guard).
pub const MAX_DECODED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

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

/// Encodes the protocol-version hello frame.
///
/// Format: `[TAG_PROTOCOL_HELLO:1][PROTOCOL_VERSION:1]` — exactly 2 bytes.
pub fn encode_protocol_hello() -> Vec<u8> {
    vec![TAG_PROTOCOL_HELLO, PROTOCOL_VERSION]
}

/// Decodes a protocol-version hello frame (the FULL frame, tag included).
///
/// Returns the peer's protocol version byte. Rejects anything that is not
/// exactly `[TAG_PROTOCOL_HELLO, version]` — version comparison is the
/// caller's job (the decoder must surface a mismatched version, not hide it).
pub fn decode_protocol_hello(frame: &[u8]) -> Result<u8, TransportError> {
    if frame.len() != 2 {
        return Err(TransportError::InvalidPayload(
            "protocol hello must be exactly 2 bytes",
        ));
    }
    if frame[0] != TAG_PROTOCOL_HELLO {
        return Err(TransportError::InvalidPayload("not a protocol hello"));
    }
    Ok(frame[1])
}

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
    let capacity = checked_bulk_transfer_done_capacity(key_bytes.len(), doc_state.len())?;
    let mut buf = Vec::with_capacity(capacity);
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

fn checked_bulk_transfer_done_capacity(
    key_len: usize,
    state_len: usize,
) -> Result<usize, TransportError> {
    2usize
        .checked_add(key_len)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(state_len))
        .ok_or(TransportError::InvalidPayload(
            "BulkTransferDone state too large",
        ))
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
    let state_end = state_start
        .checked_add(state_len)
        .ok_or(TransportError::InvalidPayload("state length overflow"))?;
    if data.len() < state_end {
        return Err(TransportError::InvalidPayload("state truncated"));
    }
    if data.len() > state_end {
        return Err(TransportError::InvalidPayload("state has trailing bytes"));
    }
    Ok((key, &data[state_start..state_end]))
}

// ─── Transport Error ──────────────────────────────────────────────────────────

/// Transport-level errors for the sync wire protocol.
#[derive(Debug)]
pub enum TransportError {
    InvalidWindowKey,
    InvalidPayload(&'static str),
    UnknownTag(u8),
    FrameTooLarge {
        size: usize,
        max: usize,
    },
    /// Inbound version-vector bytes failed Loro binary decoding.
    /// Fail-closed: malformed VVs are NEVER treated as an empty VV.
    VersionVectorDecode,
    WebSocket(String),
    ConnectionClosed,
    /// Engine/storage failure surfaced at the transport boundary (LMDB
    /// write, window open/recovery). The wire payload itself was valid.
    Storage(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWindowKey => write!(f, "invalid window key"),
            Self::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            Self::UnknownTag(tag) => write!(f, "unknown tag: {tag}"),
            Self::FrameTooLarge { size, max } => write!(f, "frame too large: {size} (max {max})"),
            Self::VersionVectorDecode => write!(f, "version vector decode failure"),
            Self::WebSocket(msg) => write!(f, "websocket error: {msg}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_hello_wire_literals() {
        // Contract literals (ONE-1127): the hello frame is EXACTLY
        // [TAG_PROTOCOL_HELLO=3, PROTOCOL_VERSION=1]. A drifted tag or
        // version byte is a silent wire break — assert the raw bytes.
        assert_eq!(TAG_PROTOCOL_HELLO, 3, "hello tag byte is pinned to 3");
        assert_eq!(PROTOCOL_VERSION, 1, "wire protocol version is pinned to 1");
        assert_eq!(encode_protocol_hello(), vec![3u8, 1u8]);
    }

    #[test]
    fn protocol_hello_decode_roundtrip() {
        let frame = encode_protocol_hello();
        assert_eq!(decode_protocol_hello(&frame).unwrap(), PROTOCOL_VERSION);
        // A future-version peer's hello must still DECODE (the caller
        // compares versions and closes) — decode returns the raw byte.
        assert_eq!(decode_protocol_hello(&[TAG_PROTOCOL_HELLO, 7]).unwrap(), 7);
    }

    #[test]
    fn protocol_hello_decode_rejects_malformed_frames() {
        // (case_name, frame)
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("tag_only", &[TAG_PROTOCOL_HELLO]),
            ("trailing_bytes", &[TAG_PROTOCOL_HELLO, PROTOCOL_VERSION, 0]),
            ("wrong_tag", &[TAG_VERSION_VECTOR, PROTOCOL_VERSION]),
        ];
        for (case_name, frame) in cases {
            assert!(
                matches!(
                    decode_protocol_hello(frame),
                    Err(TransportError::InvalidPayload(_))
                ),
                "case {case_name}: expected InvalidPayload"
            );
        }
    }

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
    fn bulk_transfer_done_capacity_rejects_usize_overflow() {
        let err = checked_bulk_transfer_done_capacity(MAX_WINDOW_KEY_LEN, usize::MAX).unwrap_err();

        assert!(matches!(
            err,
            TransportError::InvalidPayload("BulkTransferDone state too large")
        ));
    }

    #[test]
    fn bulk_transfer_done_rejects_trailing_bytes() {
        let state = vec![10, 20];
        let mut encoded = encode_bulk_transfer_done("2025-09", &state);
        encoded.push(30);

        assert!(matches!(
            decode_bulk_transfer_done(&encoded[1..]),
            Err(TransportError::InvalidPayload("state has trailing bytes"))
        ));
    }

    #[test]
    fn bulk_transfer_done_rejects_truncated_state() {
        let state = vec![10, 20];
        let mut encoded = encode_bulk_transfer_done("2025-09", &state);
        encoded.pop();

        assert!(matches!(
            decode_bulk_transfer_done(&encoded[1..]),
            Err(TransportError::InvalidPayload("state truncated"))
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
    fn decoders_reject_invalid_calendar_window_keys() {
        // Every wire decoder must reject window keys that fail
        // parse_window_key_str — both calendar-OOB (2026-13) and pre-epoch
        // (1969-12). Each decoder has its own trailing payload shape, so we
        // build a payload tail per decoder.
        type Decoder = fn(&[u8]) -> Result<(), TransportError>;

        let window_sync_decoder: Decoder = |data| decode_window_sync(data).map(|_| ());
        let bulk_transfer_decoder: Decoder = |data| decode_bulk_transfer(data).map(|_| ());
        let bulk_done_decoder: Decoder = |data| decode_bulk_transfer_done(data).map(|_| ());

        let cases: &[(&str, Decoder, &[u8])] = &[
            // (case_name, decoder, payload_tail_after_window_key)
            (
                "decode_window_sync_calendar_oob",
                window_sync_decoder,
                &[window_sub_tags::UPDATE],
            ),
            (
                "decode_window_sync_pre_epoch",
                window_sync_decoder,
                &[window_sub_tags::UPDATE],
            ),
            (
                "decode_bulk_transfer_calendar_oob",
                bulk_transfer_decoder,
                &[1, 2, 3],
            ),
            (
                "decode_bulk_transfer_pre_epoch",
                bulk_transfer_decoder,
                &[1, 2, 3],
            ),
            (
                "decode_bulk_transfer_done_calendar_oob",
                bulk_done_decoder,
                &[0, 0, 0, 0],
            ),
            (
                "decode_bulk_transfer_done_pre_epoch",
                bulk_done_decoder,
                &[0, 0, 0, 0],
            ),
        ];

        let invalid_keys: &[&[u8]] = &[b"2026-13", b"1969-12"];

        for ((case_name, decoder, tail), invalid_key) in cases
            .iter()
            .zip(invalid_keys.iter().cycle().take(cases.len()))
        {
            let mut data = vec![invalid_key.len() as u8];
            data.extend_from_slice(invalid_key);
            data.extend_from_slice(tail);

            assert!(
                matches!(decoder(&data), Err(TransportError::InvalidWindowKey)),
                "case {case_name}: expected InvalidWindowKey for key {:?}",
                std::str::from_utf8(invalid_key).unwrap_or("<bytes>")
            );
        }
    }
}
