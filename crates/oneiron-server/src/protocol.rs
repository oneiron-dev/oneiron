//! Custom Oneiron sync protocol — server-side extensions.
//!
//! Re-exports the shared wire protocol from `oneiron::sync` and adds
//! server-specific types: `AwarenessState`, `SyncMessage`, `ProtocolError`,
//! and close codes.

// Re-export shared wire constants and encode/decode functions.
pub(crate) use oneiron::sync::{
    TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_WINDOW_SYNC, decode_bulk_transfer,
    decode_bulk_transfer_done, decode_window_sync, encode_window_sync,
};

// Re-export tag constants from shared transport (avoid redefinition).
pub(crate) use oneiron::sync::transport::{
    LEASE_STATUS_GRANTED, LEASE_STATUS_REJECTED, PROTOCOL_VERSION, TAG_AWARENESS,
    TAG_LEASE_REQUEST, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR, decode_lease_request,
    decode_protocol_hello, encode_lease_granted,
};

/// Sub-tags within WindowSync messages.
pub(crate) mod window_sub_tags {
    pub(crate) use oneiron::sync::transport::window_sub_tags::*;
}

// ─── Paginated HTTP Response Metadata ────────────────────────────────────────

/// Count precision requested by list/search callers and reported in
/// paginated response metadata.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CountMode {
    /// Skip count work and report `total = 0`.
    None,
    /// Report a non-exact search/list estimate.
    Estimate,
    /// Report an exact count derived from deterministic indexes.
    #[default]
    Exact,
}

impl CountMode {
    pub(crate) fn default_estimate() -> Self {
        Self::Estimate
    }

    pub(crate) fn for_search_response(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Estimate | Self::Exact => Self::Estimate,
        }
    }
}

/// Metadata block shared by paginated list/search responses.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct ResponseMeta {
    pub total: u64,
    #[serde(rename = "countMode")]
    pub count_mode: CountMode,
}

impl ResponseMeta {
    pub(crate) fn new(total: u64, count_mode: CountMode) -> Self {
        Self { total, count_mode }
    }

    pub(crate) fn none() -> Self {
        Self::new(0, CountMode::None)
    }

    pub(crate) fn estimate(total: u64) -> Self {
        Self::new(total, CountMode::Estimate)
    }
}

/// Standard paginated response envelope: primary data plus metadata, with the
/// cursor slot omitted for non-cursor search endpoints.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct PaginatedResponse<T> {
    pub items: Vec<T>,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub meta: ResponseMeta,
}

impl<T> PaginatedResponse<T> {
    pub(crate) fn new(items: Vec<T>, next_cursor: Option<String>, meta: ResponseMeta) -> Self {
        Self {
            items,
            next_cursor,
            meta,
        }
    }
}

// ─── Awareness ────────────────────────────────────────────────────────────────

/// Custom awareness state (Loro doesn't have built-in awareness).
/// Simple JSON-serializable presence state per device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub(crate) struct AwarenessState {
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
pub(crate) fn encode_awareness(state: &AwarenessState) -> Vec<u8> {
    let json = serde_json::to_vec(state).expect("AwarenessState serialization cannot fail");
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.push(TAG_AWARENESS);
    buf.extend_from_slice(&json);
    buf
}

/// Decodes an awareness message (after tag byte has been consumed).
pub(crate) fn decode_awareness(data: &[u8]) -> Result<AwarenessState, ProtocolError> {
    serde_json::from_slice(data)
        .map_err(|_| ProtocolError::InvalidPayload("invalid awareness JSON"))
}

// ─── Top-level Message Dispatch ───────────────────────────────────────────────

/// Parsed top-level message from the wire.
#[derive(Debug)]
pub(crate) enum SyncMessage {
    /// Root doc update bytes (tag 0). Server rejects these from clients.
    RootUpdate(Vec<u8>),
    /// Awareness state (tag 1). Bidirectional.
    Awareness(AwarenessState),
    /// Root version vector (tag 2). Used for sync negotiation.
    RootVersionVector(Vec<u8>),
    /// LeaseRequest (tag 4, ONE-1140): the client's frame #2 on every
    /// connect — device-lease registration/renewal with an Ed25519 proof
    /// of possession. Routed to the server registrar (OD-3).
    LeaseRequest {
        client_id: u64,
        pubkey: [u8; 32],
        pop_sig: [u8; 64],
    },
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
pub(crate) fn parse_message(data: &[u8]) -> Result<SyncMessage, ProtocolError> {
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
        TAG_LEASE_REQUEST => {
            let (client_id, pubkey, pop_sig) = decode_lease_request(payload)
                .map_err(|e| ProtocolError::InvalidPayload(transport_err_msg(e)))?;
            Ok(SyncMessage::LeaseRequest {
                client_id,
                pubkey,
                pop_sig,
            })
        }
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
pub(crate) fn transport_err_msg(e: oneiron::sync::TransportError) -> &'static str {
    match e {
        oneiron::sync::TransportError::InvalidWindowKey => "invalid window key",
        oneiron::sync::TransportError::InvalidPayload(msg) => msg,
        oneiron::sync::TransportError::UnknownTag(_) => "unknown tag",
        oneiron::sync::TransportError::FrameTooLarge { .. } => "frame too large",
        oneiron::sync::TransportError::VersionVectorDecode => "version vector decode failure",
        oneiron::sync::TransportError::WebSocket(_) => "websocket error",
        oneiron::sync::TransportError::ConnectionClosed => "connection closed",
        oneiron::sync::TransportError::Storage(_) => "storage error",
    }
}

/// Encodes a root doc update for the wire.
///
/// Format: `[TAG_SYNC_UPDATE:1][update_bytes]`
pub(crate) fn encode_root_update(update_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + update_bytes.len());
    buf.push(TAG_SYNC_UPDATE);
    buf.extend_from_slice(update_bytes);
    buf
}

// ─── Protocol Error ───────────────────────────────────────────────────────────

/// Protocol-level errors specific to Oneiron's custom sync protocol.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Variants used in match arms; some constructed only in future Phase 2+ paths
pub(crate) enum ProtocolError {
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
    /// Inbound version-vector bytes failed Loro binary decoding.
    /// Fail-closed: the connection is dropped, NEVER answered with a
    /// full export as if the VV were empty (ONE-1127).
    #[error("version vector decode failure: {0}")]
    VvDecode(String),
    /// Durable sync_state persistence failed (load or append). Fail-closed:
    /// the connection is closed instead of relaying state the server cannot
    /// replay after a restart.
    #[error("sync persistence error: {0}")]
    Persistence(String),
}

/// WebSocket close codes per ARCH-023 section 3.5.
#[allow(dead_code)] // Used when WebSocket handler sends close frames
pub(crate) mod close_codes {
    /// JWT expired mid-session or device lease expired.
    pub(crate) const AUTH_EXPIRED: u16 = 4001;
    /// CRDT decode error (malformed update bytes).
    pub(crate) const DECODE_ERROR: u16 = 4002;
    /// Unknown custom tag.
    pub(crate) const UNKNOWN_TAG: u16 = 4003;
    /// Frame/payload exceeds size limit.
    pub(crate) const FRAME_TOO_LARGE: u16 = 4004;
    /// BulkTransfer decompression/decode failure.
    pub(crate) const BULK_DECODE_FAILURE: u16 = 4005;
    /// Protocol-version hello mismatch, missing, malformed, or timed out
    /// (ONE-1127). Sent BEFORE any sync payload flows.
    pub(crate) const VERSION_MISMATCH: u16 = 4006;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message_dispatch() {
        // Two top-level wire tags get routed to their typed SyncMessage
        // variant by parse_message:
        //   (case_name, encoded_message, assertion)
        // - root_update: TAG_SYNC_UPDATE + payload -> SyncMessage::RootUpdate
        // - window_sync: encode_window_sync(...) -> SyncMessage::WindowSync
        //   with the original window_key/sub_tag/payload preserved.
        let root_update_payload = vec![1u8, 2, 3];
        let mut root_msg = vec![TAG_SYNC_UPDATE];
        root_msg.extend_from_slice(&root_update_payload);

        let window_msg = encode_window_sync("2026-02", window_sub_tags::UPDATE, b"data")
            .into_result()
            .unwrap();

        // (case_name, encoded, assertion_fn)
        type Asserter = fn(SyncMessage);
        let assert_root: Asserter = |msg| {
            let SyncMessage::RootUpdate(data) = msg else {
                panic!("expected RootUpdate, got {msg:?}");
            };
            assert_eq!(data, vec![1u8, 2, 3]);
        };
        let assert_window: Asserter = |msg| {
            let SyncMessage::WindowSync {
                window_key,
                sub_tag,
                payload,
            } = msg
            else {
                panic!("expected WindowSync, got {msg:?}");
            };
            assert_eq!(window_key, "2026-02");
            assert_eq!(sub_tag, window_sub_tags::UPDATE);
            assert_eq!(payload, b"data");
        };

        let cases: &[(&str, Vec<u8>, Asserter)] = &[
            ("root_update", root_msg, assert_root),
            ("window_sync", window_msg, assert_window),
        ];

        for (case_name, encoded, asserter) in cases {
            let parsed = parse_message(encoded)
                .unwrap_or_else(|e| panic!("case {case_name}: parse failed: {e:?}"));
            asserter(parsed);
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
        let SyncMessage::Awareness(s) = parse_message(&encoded).unwrap() else {
            panic!("expected Awareness");
        };
        assert_eq!(s, state);
    }

    #[test]
    fn parse_message_unknown_tag() {
        assert!(parse_message(&[50, 1, 2, 3]).is_err());
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

    #[test]
    fn paginated_response_serializes_contract_meta_literals() {
        let response = PaginatedResponse::new(
            vec![1_u8],
            Some("cursor-1".to_owned()),
            ResponseMeta::new(42, CountMode::Exact),
        );
        let json = serde_json::to_value(response).unwrap();

        assert_eq!(json["items"], serde_json::json!([1]));
        assert_eq!(json["nextCursor"], "cursor-1");

        let meta = json["meta"].as_object().unwrap();
        assert_eq!(meta.len(), 2);
        assert_eq!(meta["total"], 42);
        assert_eq!(meta["countMode"], "exact");
    }

    #[test]
    fn count_mode_literals_are_lowercase_and_stable() {
        let cases = [
            (CountMode::None, "none"),
            (CountMode::Estimate, "estimate"),
            (CountMode::Exact, "exact"),
        ];

        for (mode, literal) in cases {
            assert_eq!(serde_json::to_value(mode).unwrap(), literal);
            assert_eq!(
                serde_json::from_value::<CountMode>(serde_json::json!(literal)).unwrap(),
                mode
            );
        }
    }
}
