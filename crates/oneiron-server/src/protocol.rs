//! Custom Oneiron sync protocol — server-side extensions.
//!
//! Re-exports the shared wire protocol from `oneiron::sync` and adds
//! server-specific types: `AwarenessState`, `SyncMessage`, `ProtocolError`,
//! and close codes.

// Re-export shared wire constants and encode/decode functions.
pub use oneiron::sync::{
    decode_bulk_transfer, decode_bulk_transfer_done, decode_window_sync, encode_window_sync,
    TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_WINDOW_SYNC,
};

/// Loro update bytes for the root doc.
pub const TAG_SYNC_UPDATE: u8 = 0;
/// Custom awareness state (JSON-encoded).
pub const TAG_AWARENESS: u8 = 1;
/// Serialized VersionVector for sync negotiation.
pub const TAG_VERSION_VECTOR: u8 = 2;

/// Sub-tags within WindowSync messages.
pub mod window_sub_tags {
    pub use oneiron::sync::transport::window_sub_tags::*;
}

// ─── Awareness ────────────────────────────────────────────────────────────────

/// Custom awareness state (Loro doesn't have built-in awareness).
/// Simple JSON-serializable presence state per device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct AwarenessState {
    pub online: bool,
    pub typing: bool,
    pub device_name: String,
}

impl Default for AwarenessState {
    fn default() -> Self {
        Self {
            online: true,
            typing: false,
            device_name: String::new(),
        }
    }
}

/// Encodes an awareness message for the wire.
///
/// Format: `[TAG_AWARENESS:1][json_bytes]`
pub fn encode_awareness(state: &AwarenessState) -> Vec<u8> {
    let json = serde_json::to_vec(state).unwrap_or_default();
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.push(TAG_AWARENESS);
    buf.extend_from_slice(&json);
    buf
}

/// Decodes an awareness message (after tag byte has been consumed).
pub fn decode_awareness(data: &[u8]) -> Result<AwarenessState, ProtocolError> {
    serde_json::from_slice(data)
        .map_err(|_| ProtocolError::InvalidPayload("invalid awareness JSON"))
}

// ─── Top-level Message Dispatch ───────────────────────────────────────────────

/// Parsed top-level message from the wire.
#[derive(Debug)]
pub enum SyncMessage {
    /// Root doc update bytes (tag 0). Server rejects these from clients.
    RootUpdate(Vec<u8>),
    /// Awareness state (tag 1). Bidirectional.
    Awareness(AwarenessState),
    /// Root version vector (tag 2). Used for sync negotiation.
    RootVersionVector(Vec<u8>),
    /// WindowSync (tag 10). Routed to per-window handler.
    WindowSync {
        window_key: String,
        sub_tag: u8,
        payload: Vec<u8>,
    },
    /// BulkTransfer (tag 20).
    BulkTransfer {
        window_key: String,
        compressed: Vec<u8>,
    },
    /// BulkTransferDone (tag 21).
    BulkTransferDone {
        window_key: String,
        doc_state: Vec<u8>,
    },
}

/// Parses a raw wire message into a typed SyncMessage.
pub fn parse_message(data: &[u8]) -> Result<SyncMessage, ProtocolError> {
    if data.is_empty() {
        return Err(ProtocolError::InvalidPayload("empty message"));
    }
    let tag = data[0];
    let payload = &data[1..];

    match tag {
        TAG_SYNC_UPDATE => Ok(SyncMessage::RootUpdate(payload.to_vec())),
        TAG_AWARENESS => {
            let state = decode_awareness(payload)?;
            Ok(SyncMessage::Awareness(state))
        }
        TAG_VERSION_VECTOR => Ok(SyncMessage::RootVersionVector(payload.to_vec())),
        TAG_WINDOW_SYNC => {
            let (key, sub_tag, inner) = decode_window_sync(payload)
                .map_err(|e| ProtocolError::InvalidPayload(transport_err_msg(e)))?;
            Ok(SyncMessage::WindowSync {
                window_key: key.to_string(),
                sub_tag,
                payload: inner.to_vec(),
            })
        }
        TAG_BULK_TRANSFER => {
            let (key, compressed) = decode_bulk_transfer(payload)
                .map_err(|e| ProtocolError::InvalidPayload(transport_err_msg(e)))?;
            Ok(SyncMessage::BulkTransfer {
                window_key: key.to_string(),
                compressed: compressed.to_vec(),
            })
        }
        TAG_BULK_TRANSFER_DONE => {
            let (key, state) = decode_bulk_transfer_done(payload)
                .map_err(|e| ProtocolError::InvalidPayload(transport_err_msg(e)))?;
            Ok(SyncMessage::BulkTransferDone {
                window_key: key.to_string(),
                doc_state: state.to_vec(),
            })
        }
        _ => Err(ProtocolError::UnknownTag(tag)),
    }
}

/// Maps a `TransportError` to a static error message for `ProtocolError`.
fn transport_err_msg(e: oneiron::sync::TransportError) -> &'static str {
    match e {
        oneiron::sync::TransportError::InvalidWindowKey => "invalid window key",
        oneiron::sync::TransportError::InvalidPayload(msg) => msg,
        oneiron::sync::TransportError::UnknownTag(_) => "unknown tag",
        oneiron::sync::TransportError::FrameTooLarge { .. } => "frame too large",
        oneiron::sync::TransportError::WebSocket(_) => "websocket error",
        oneiron::sync::TransportError::ConnectionClosed => "connection closed",
    }
}

/// Encodes a root doc update for the wire.
///
/// Format: `[TAG_SYNC_UPDATE:1][update_bytes]`
pub fn encode_root_update(update_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + update_bytes.len());
    buf.push(TAG_SYNC_UPDATE);
    buf.extend_from_slice(update_bytes);
    buf
}

// ─── Protocol Error ───────────────────────────────────────────────────────────

/// Protocol-level errors specific to Oneiron's custom sync protocol.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    #[error("unknown custom tag: {0}")]
    UnknownTag(u8),
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("bulk transfer decode failure")]
    BulkTransferDecode,
    #[error("loro import error: {0}")]
    LoroImport(String),
}

/// WebSocket close codes per ARCH-023 section 3.5.
pub mod close_codes {
    /// JWT expired mid-session or device lease expired.
    pub const AUTH_EXPIRED: u16 = 4001;
    /// CRDT decode error (malformed update bytes).
    pub const DECODE_ERROR: u16 = 4002;
    /// Unknown custom tag.
    pub const UNKNOWN_TAG: u16 = 4003;
    /// Frame/payload exceeds size limit.
    pub const FRAME_TOO_LARGE: u16 = 4004;
    /// BulkTransfer decompression/decode failure.
    pub const BULK_DECODE_FAILURE: u16 = 4005;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_sync_roundtrip() {
        let key = "2026-02";
        let payload = b"hello world";
        let encoded = encode_window_sync(key, window_sub_tags::UPDATE, payload);
        assert_eq!(encoded[0], TAG_WINDOW_SYNC);

        let (dk, sub, dp) = decode_window_sync(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(sub, window_sub_tags::UPDATE);
        assert_eq!(dp, payload);
    }

    #[test]
    fn parse_message_root_update() {
        let update = vec![1, 2, 3];
        let mut msg = vec![TAG_SYNC_UPDATE];
        msg.extend_from_slice(&update);
        match parse_message(&msg).unwrap() {
            SyncMessage::RootUpdate(data) => assert_eq!(data, update),
            other => panic!("expected RootUpdate, got {:?}", other),
        }
    }

    #[test]
    fn parse_message_awareness() {
        let state = AwarenessState {
            online: true,
            typing: true,
            device_name: "iPhone".to_string(),
        };
        let encoded = encode_awareness(&state);
        match parse_message(&encoded).unwrap() {
            SyncMessage::Awareness(s) => assert_eq!(s, state),
            other => panic!("expected Awareness, got {:?}", other),
        }
    }

    #[test]
    fn parse_message_unknown_tag() {
        assert!(parse_message(&[50, 1, 2, 3]).is_err());
    }

    #[test]
    fn parse_message_window_sync() {
        let encoded = encode_window_sync("2026-02", window_sub_tags::UPDATE, b"data");
        match parse_message(&encoded).unwrap() {
            SyncMessage::WindowSync {
                window_key,
                sub_tag,
                payload,
            } => {
                assert_eq!(window_key, "2026-02");
                assert_eq!(sub_tag, window_sub_tags::UPDATE);
                assert_eq!(payload, b"data");
            }
            other => panic!("expected WindowSync, got {:?}", other),
        }
    }

    #[test]
    fn awareness_roundtrip() {
        let state = AwarenessState {
            online: false,
            typing: false,
            device_name: "MacBook".to_string(),
        };
        let encoded = encode_awareness(&state);
        let decoded = decode_awareness(&encoded[1..]).unwrap();
        assert_eq!(decoded, state);
    }
}
