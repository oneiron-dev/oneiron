//! Wire protocol encoding/decoding for WebSocket transport.
//!
//! Shared between client and server. Defines the custom message tags
//! and encoding/decoding for WindowSync, BulkTransfer, BulkTransferDone.
//! Mostly engine-agnostic. The ephemeral lane intentionally exposes Loro's
//! native wire record shape so untrusted `EphemeralStore` bytes can be bounded
//! and timestamp-validated before apply.

use crate::sync::types::parse_window_key_str;
use loro::LoroValue;
use serde::{Deserialize, Serialize};
use std::debug_assert_matches;
use std::ops::{Deref, DerefMut};

// ─── Custom Message Tags ──────────────────────────────────────────────────────

/// CRDT update bytes for the root doc.
pub const TAG_SYNC_UPDATE: u8 = 0;
/// Loro-native ephemeral state bytes (`EphemeralStore::encode*()`).
pub const TAG_EPHEMERAL: u8 = 1;
/// Loro binary `VersionVector::encode()` bytes for sync negotiation.
pub const TAG_VERSION_VECTOR: u8 = 2;
/// Protocol-version hello: `[TAG_PROTOCOL_HELLO:1][version:1]`.
///
/// The client's FIRST frame on every connection. The server checks the
/// version byte and closes with a 4xxx code on mismatch, so the NEXT wire
/// break is detectable instead of surfacing as garbled decode errors
/// mid-sync (ONE-1127).
pub const TAG_PROTOCOL_HELLO: u8 = 3;

/// LeaseRequest (ONE-1140, OD-5): frame #2 on EVERY connect, right after
/// the protocol hello. Fixed 105 B layout (wire scalars BE):
///
/// `[TAG_LEASE_REQUEST:1][client_id:8 BE][pubkey:32][pop_sig:64]`
///
/// `pop_sig` = Ed25519 over the proof-of-possession transcript
/// `"oneiron/lease-pop/v1" || client_id:8 BE || pubkey:32`. Replay of a
/// captured frame re-registers the same binding (harmless); binding someone
/// ELSE's pubkey requires their signature over YOUR client id (the
/// transcript binds both) — no challenge round needed.
pub const TAG_LEASE_REQUEST: u8 = 4;
/// LeaseGranted (ONE-1140, OD-5): the server's direct reply to a
/// LeaseRequest. Fixed 18 B layout (wire scalars BE):
///
/// `[TAG_LEASE_GRANTED:1][status:1 0x01 granted/renewed | 0x00 rejected]`
/// `[client_id:8 BE][expires_at:8 BE]`
///
/// `expires_at = 0` when rejected. A rejection surfaces as a typed
/// `SyncEvent` and sync PROCEEDS — fail-closed lives at the replay doors
/// (peers quarantine the unleased device's receipts), not the pipe.
pub const TAG_LEASE_GRANTED: u8 = 5;

/// Total LeaseRequest frame length, tag byte included (OD-5).
pub const LEASE_REQUEST_FRAME_LEN: usize = 105;
/// Total LeaseGranted frame length, tag byte included (OD-5).
pub const LEASE_GRANTED_FRAME_LEN: usize = 18;
/// LeaseGranted status byte: granted or renewed.
pub const LEASE_STATUS_GRANTED: u8 = 0x01;
/// LeaseGranted status byte: rejected (binding conflict or revoked).
pub const LEASE_STATUS_REJECTED: u8 = 0x00;

/// Current sync wire-protocol version.
///
/// Bump on any wire break (tag layout, payload encoding, VV encoding).
/// v1 = binary Loro VVs + delta export + protocol hello (ONE-1127).
/// v2 = lease frames (TAG_LEASE_REQUEST/TAG_LEASE_GRANTED), the
/// `[hello][lease_request][…]` connect sequence, the root-doc `leases`
/// registry, and the attested-receipt `verification` pin (ONE-1140, OD-5 —
/// one atomic wire train; v1 peers are rejected at hello with close 4006).
/// v3 = pre-FED-005 grant-backed selector sync (`SELECTOR_VV_REQUEST`).
/// v4 = scoped lease root keys for full-window clients; v2/v3 are rejected
/// so old clients do not quarantine scoped root `leases` entries.
/// v5 = scoped lease root keys for selector-capable clients (ONE-1271,
/// FED-002 plus FED-005 scoped keys).
/// v6 = Loro-native ephemeral tag 1 payloads for full-window clients
/// (SYNC-EPH-1 replaces JSON awareness bytes).
/// v7 = Loro-native ephemeral tag 1 payloads for selector-capable clients,
/// kept distinct from v6 for broadcast filtering.
pub const PROTOCOL_VERSION: u8 = 7;
/// Full-window protocol version kept separate from selector-capable clients.
///
/// Full-window peers cannot use selector sync, but their
/// `VV_REQUEST`/`VV_RESPONSE`/`UPDATE` flow remains byte-compatible once they
/// send the scoped-lease-capable hello.
pub const LEGACY_FULL_WINDOW_PROTOCOL_VERSION: u8 = 6;

/// Shared 8 MB cap for decoded payloads: bulk-transfer decompression and
/// root-doc imports both refuse anything larger (decompression-bomb /
/// memory-exhaustion guard).
pub const MAX_DECODED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Maximum encoded custom sync frame size produced by transport helpers.
const MAX_ENCODED_FRAME_BYTES: usize = MAX_DECODED_PAYLOAD_BYTES;

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
    /// Grant-backed closed-subgraph selector request.
    ///
    /// Payload: `[selector_len:4BE][selector_msgpack][remote_vv]`.
    /// The server replies with a normal `UPDATE` frame containing only the
    /// selected subgraph. Full-window `VV_REQUEST`/`VV_RESPONSE` remain
    /// unchanged and backward compatible.
    pub const SELECTOR_VV_REQUEST: u8 = 4;
}

/// Maximum window key length (YYYY-MM = 7 bytes).
pub const MAX_WINDOW_KEY_LEN: usize = 7;

/// Encoded sync wire frame, preserving typed encoder failures.
///
/// Production callers that handle untrusted input must consume
/// [`EncodedFrame::into_result`]. The byte/Vec conversions keep existing
/// valid-frame builders source-compatible, but deliberately fail closed if an
/// encode error is ignored instead of returning an empty or garbage frame.
#[must_use]
#[derive(Debug)]
pub struct EncodedFrame(Result<Vec<u8>, TransportError>);

impl EncodedFrame {
    fn ok(frame: Vec<u8>) -> Self {
        Self(Ok(frame))
    }

    fn err(err: TransportError) -> Self {
        Self(Err(err))
    }

    /// Consumes the frame and returns the typed encode result.
    pub fn into_result(self) -> Result<Vec<u8>, TransportError> {
        self.0
    }

    fn valid_frame(&self) -> &Vec<u8> {
        self.0
            .as_ref()
            .expect("encoded frame error was ignored by caller")
    }

    fn valid_frame_mut(&mut self) -> &mut Vec<u8> {
        self.0
            .as_mut()
            .expect("encoded frame error was ignored by caller")
    }
}

impl Deref for EncodedFrame {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.valid_frame()
    }
}

impl DerefMut for EncodedFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.valid_frame_mut()
    }
}

impl AsRef<[u8]> for EncodedFrame {
    fn as_ref(&self) -> &[u8] {
        self.valid_frame()
    }
}

impl From<EncodedFrame> for Vec<u8> {
    fn from(frame: EncodedFrame) -> Self {
        frame
            .into_result()
            .expect("encoded frame error was ignored by caller")
    }
}

impl From<EncodedFrame> for tokio_tungstenite::tungstenite::Bytes {
    fn from(frame: EncodedFrame) -> Self {
        Vec::<u8>::from(frame).into()
    }
}

// ─── Wire Format Encoding ─────────────────────────────────────────────────────

/// Encodes the protocol-version hello frame.
///
/// Format: `[TAG_PROTOCOL_HELLO:1][PROTOCOL_VERSION:1]` — exactly 2 bytes.
pub fn encode_protocol_hello() -> Vec<u8> {
    vec![TAG_PROTOCOL_HELLO, PROTOCOL_VERSION]
}

/// Encodes the legacy full-window protocol hello frame.
///
/// Clients that use the pre-FED-002 full-window WindowSync flow send a
/// distinct scoped-lease-capable version so selector-capable connections
/// cannot downgrade themselves to a full-window export after negotiating the
/// selector protocol.
pub fn encode_legacy_full_window_protocol_hello() -> Vec<u8> {
    vec![TAG_PROTOCOL_HELLO, LEGACY_FULL_WINDOW_PROTOCOL_VERSION]
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

/// Encodes a LeaseRequest frame (ONE-1140, OD-5).
///
/// Format: `[TAG_LEASE_REQUEST:1][client_id:8 BE][pubkey:32][pop_sig:64]`
/// — exactly [`LEASE_REQUEST_FRAME_LEN`] (105) bytes.
pub fn encode_lease_request(client_id: u64, pubkey: &[u8; 32], pop_sig: &[u8; 64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(LEASE_REQUEST_FRAME_LEN);
    buf.push(TAG_LEASE_REQUEST);
    buf.extend_from_slice(&client_id.to_be_bytes());
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(pop_sig);
    debug_assert_eq!(buf.len(), LEASE_REQUEST_FRAME_LEN);
    buf
}

/// Decodes a LeaseRequest payload (after the tag byte has been consumed).
///
/// Exhaustive length validation: exactly 104 bytes (8 + 32 + 64), no
/// trailing bytes. Returns `(client_id, pubkey, pop_sig)` — signature
/// verification is the caller's job (the server registrar).
pub fn decode_lease_request(data: &[u8]) -> Result<(u64, [u8; 32], [u8; 64]), TransportError> {
    if data.len() != LEASE_REQUEST_FRAME_LEN - 1 {
        return Err(TransportError::InvalidPayload(
            "LeaseRequest must be exactly 105 bytes",
        ));
    }
    let client_id = u64::from_be_bytes(data[0..8].try_into().expect("length checked"));
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[8..40]);
    let mut pop_sig = [0u8; 64];
    pop_sig.copy_from_slice(&data[40..104]);
    Ok((client_id, pubkey, pop_sig))
}

/// Encodes a LeaseGranted frame (ONE-1140, OD-5).
///
/// Format: `[TAG_LEASE_GRANTED:1][status:1][client_id:8 BE][expires_at:8 BE]`
/// — exactly [`LEASE_GRANTED_FRAME_LEN`] (18) bytes. `expires_at` must be 0
/// when rejected.
pub fn encode_lease_granted(status: u8, client_id: u64, expires_at: u64) -> Vec<u8> {
    debug_assert_matches!(status, LEASE_STATUS_GRANTED | LEASE_STATUS_REJECTED);
    debug_assert!(status == LEASE_STATUS_GRANTED || expires_at == 0);
    let mut buf = Vec::with_capacity(LEASE_GRANTED_FRAME_LEN);
    buf.push(TAG_LEASE_GRANTED);
    buf.push(status);
    buf.extend_from_slice(&client_id.to_be_bytes());
    buf.extend_from_slice(&expires_at.to_be_bytes());
    debug_assert_eq!(buf.len(), LEASE_GRANTED_FRAME_LEN);
    buf
}

/// Encodes a Loro `EphemeralStore` update or snapshot frame.
///
/// Format: `[TAG_EPHEMERAL:1][ephemeral_store_bytes]`.
pub fn encode_ephemeral(payload: &[u8]) -> EncodedFrame {
    let capacity = match checked_encoded_frame_len(1, payload.len()) {
        Ok(capacity) => capacity,
        Err(err) => return EncodedFrame::err(err),
    };
    let mut buf = Vec::with_capacity(capacity);
    buf.push(TAG_EPHEMERAL);
    buf.extend_from_slice(payload);
    EncodedFrame::ok(buf)
}

/// Decoded Loro `EphemeralStore` wire record.
///
/// This mirrors the postcard-encoded shape used by Loro 1.10.x. It is shared
/// so callers can validate untrusted ephemeral bytes before applying them to a
/// store while still relaying the native bytes on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EphemeralWireState {
    pub key: String,
    pub value: Option<LoroValue>,
    pub timestamp: i64,
}

/// Decodes Loro-native `EphemeralStore` bytes into timestamped wire records.
pub fn decode_ephemeral_states(payload: &[u8]) -> Result<Vec<EphemeralWireState>, TransportError> {
    postcard::from_bytes(payload)
        .map_err(|_| TransportError::InvalidPayload("invalid ephemeral payload"))
}

/// Encodes timestamped Loro-native ephemeral records.
///
/// Production callers normally use `EphemeralStore::encode*`; this helper is
/// kept with the decoder so tests and defensive transport tooling can build
/// exact timestamp fixtures without hand-rolling postcard details.
pub fn encode_ephemeral_states(states: &[EphemeralWireState]) -> Result<Vec<u8>, TransportError> {
    postcard::to_allocvec(states)
        .map_err(|_| TransportError::InvalidPayload("invalid ephemeral payload"))
}

/// Decodes a LeaseGranted payload (after the tag byte has been consumed).
///
/// Exhaustive validation: exactly 17 bytes, status byte drawn from the
/// pinned set, `expires_at == 0` when rejected. Returns
/// `(status, client_id, expires_at)`.
pub fn decode_lease_granted(data: &[u8]) -> Result<(u8, u64, u64), TransportError> {
    if data.len() != LEASE_GRANTED_FRAME_LEN - 1 {
        return Err(TransportError::InvalidPayload(
            "LeaseGranted must be exactly 18 bytes",
        ));
    }
    let status = data[0];
    if !matches!(status, LEASE_STATUS_GRANTED | LEASE_STATUS_REJECTED) {
        return Err(TransportError::InvalidPayload(
            "LeaseGranted status byte must be 0x00 or 0x01",
        ));
    }
    let client_id = u64::from_be_bytes(data[1..9].try_into().expect("length checked"));
    let expires_at = u64::from_be_bytes(data[9..17].try_into().expect("length checked"));
    if status == LEASE_STATUS_REJECTED && expires_at != 0 {
        return Err(TransportError::InvalidPayload(
            "rejected LeaseGranted must carry expires_at = 0",
        ));
    }
    Ok((status, client_id, expires_at))
}

/// Encodes a WindowSync message for the wire.
///
/// Format: `[TAG_WINDOW_SYNC:1][window_key_len:1][window_key][sub_tag:1][payload]`
pub fn encode_window_sync(window_key: &str, sub_tag: u8, payload: &[u8]) -> EncodedFrame {
    let key_bytes = match validate_window_key(window_key) {
        Ok(key_bytes) => key_bytes,
        Err(err) => return EncodedFrame::err(err),
    };
    let capacity = match checked_encoded_frame_len(3 + key_bytes.len(), payload.len()) {
        Ok(capacity) => capacity,
        Err(err) => return EncodedFrame::err(err),
    };
    let mut buf = Vec::with_capacity(capacity);
    buf.push(TAG_WINDOW_SYNC);
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf.push(sub_tag);
    buf.extend_from_slice(payload);
    EncodedFrame::ok(buf)
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
pub fn encode_bulk_transfer(window_key: &str, zstd_data: &[u8]) -> EncodedFrame {
    let key_bytes = match validate_window_key(window_key) {
        Ok(key_bytes) => key_bytes,
        Err(err) => return EncodedFrame::err(err),
    };
    let capacity = match checked_encoded_frame_len(2 + key_bytes.len(), zstd_data.len()) {
        Ok(capacity) => capacity,
        Err(err) => return EncodedFrame::err(err),
    };
    let mut buf = Vec::with_capacity(capacity);
    buf.push(TAG_BULK_TRANSFER);
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf.extend_from_slice(zstd_data);
    EncodedFrame::ok(buf)
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
pub fn encode_bulk_transfer_done(window_key: &str, doc_state: &[u8]) -> EncodedFrame {
    match encode_bulk_transfer_done_checked(window_key, doc_state) {
        Ok(frame) => EncodedFrame::ok(frame),
        Err(err) => EncodedFrame::err(err),
    }
}

/// Encodes a BulkTransferDone message for the wire with checked state length.
///
/// Returns `Err(TransportError::InvalidPayload(_))` if `doc_state` exceeds the
/// BulkTransferDone u32 state-length field. Use this variant when callers need
/// to propagate oversized state errors.
pub fn encode_bulk_transfer_done_checked(
    window_key: &str,
    doc_state: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let key_bytes = validate_window_key(window_key)?;
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

fn validate_window_key(window_key: &str) -> Result<&[u8], TransportError> {
    let key_bytes = window_key.as_bytes();
    if key_bytes.is_empty()
        || key_bytes.len() > MAX_WINDOW_KEY_LEN
        || parse_window_key_str(window_key).is_none()
    {
        return Err(TransportError::InvalidWindowKey);
    }
    Ok(key_bytes)
}

fn checked_bulk_transfer_done_state_len(state_len: usize) -> Result<u32, TransportError> {
    u32::try_from(state_len)
        .map_err(|_| TransportError::InvalidPayload("BulkTransferDone state too large"))
}

fn checked_bulk_transfer_done_capacity(
    key_len: usize,
    state_len: usize,
) -> Result<usize, TransportError> {
    let prefix_len = 2usize
        .checked_add(key_len)
        .and_then(|len| len.checked_add(4))
        .ok_or(TransportError::FrameTooLarge {
            size: usize::MAX,
            max: MAX_ENCODED_FRAME_BYTES,
        })?;
    checked_encoded_frame_len(prefix_len, state_len)
}

fn checked_encoded_frame_len(
    prefix_len: usize,
    payload_len: usize,
) -> Result<usize, TransportError> {
    let size = prefix_len
        .checked_add(payload_len)
        .ok_or(TransportError::FrameTooLarge {
            size: usize::MAX,
            max: MAX_ENCODED_FRAME_BYTES,
        })?;
    if size > MAX_ENCODED_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge {
            size,
            max: MAX_ENCODED_FRAME_BYTES,
        });
    }
    Ok(size)
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
    use core::assert_matches;

    fn production_source(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    fn assert_typed_encoder_callers_use_into_result(source_name: &str, source: &str) {
        for function_name in [
            "encode_window_sync(",
            "encode_bulk_transfer(",
            "encode_bulk_transfer_done(",
        ] {
            for (start, _) in source.match_indices(function_name) {
                let end = source.len().min(start + 400);
                let call_site = &source[start..end];
                assert!(
                    call_site.contains(".into_result()"),
                    "{source_name}: {function_name} call must consume EncodedFrame with into_result(): {call_site:?}"
                );
            }
        }
    }

    #[test]
    fn production_typed_encoder_callers_consume_results() {
        let sources = [
            (
                "sync/client.rs",
                production_source(include_str!("client.rs")),
            ),
            (
                "sync/connection.rs",
                production_source(include_str!("connection.rs")),
            ),
            (
                "oneiron-server/src/handler.rs",
                production_source(include_str!("../../../oneiron-server/src/handler.rs")),
            ),
        ];
        for (source_name, source) in sources {
            assert_typed_encoder_callers_use_into_result(source_name, source);
        }
    }

    #[test]
    fn protocol_hello_wire_literals() {
        // Contract literals: the hello frame is EXACTLY
        // [TAG_PROTOCOL_HELLO=3, PROTOCOL_VERSION=7]. A drifted tag or
        // version byte is a silent wire break — assert the raw bytes.
        // Version pinned 1→2 by the ONE-1140 atomic wire train (OD-5):
        // lease frames + connect sequence + leases registry + attested
        // receipts land behind this single bump; v1 peers close 4006.
        // Version pinned 2→3 by FED-002 selector sync so v3 clients do not
        // negotiate successfully with pre-selector daemons.
        // Version pinned 3→4/5 by FED-005 scoped lease keys so v2/v3 clients
        // are rejected before they can quarantine scoped root `leases` rows.
        // Version pinned 4/5→6/7 by SYNC-EPH-1 because tag 1 payloads changed
        // from JSON awareness to Loro-native EphemeralStore bytes.
        assert_eq!(TAG_PROTOCOL_HELLO, 3, "hello tag byte is pinned to 3");
        assert_eq!(PROTOCOL_VERSION, 7, "wire protocol version is pinned to 7");
        assert_eq!(
            LEGACY_FULL_WINDOW_PROTOCOL_VERSION, 6,
            "legacy full-window version is pinned to 6"
        );
        assert_eq!(encode_protocol_hello(), vec![3u8, 7u8]);
        assert_eq!(encode_legacy_full_window_protocol_hello(), vec![3u8, 6u8]);
    }

    #[test]
    fn window_subtag_literals() {
        assert_eq!(window_sub_tags::UPDATE, 0);
        assert_eq!(window_sub_tags::VV_REQUEST, 2);
        assert_eq!(window_sub_tags::VV_RESPONSE, 3);
        assert_eq!(window_sub_tags::SELECTOR_VV_REQUEST, 4);
    }

    #[test]
    fn full_window_sync_wire_frames_remain_backward_compatible_under_selector_bump() {
        let vv_payload = [0xAA, 0xBB, 0xCC];
        let update_payload = [0x11, 0x22];
        let key = "2026-09";

        let vv_request = encode_window_sync(key, window_sub_tags::VV_REQUEST, &vv_payload)
            .into_result()
            .unwrap();
        assert_eq!(
            vv_request,
            [
                &[TAG_WINDOW_SYNC, 7],
                key.as_bytes(),
                &[window_sub_tags::VV_REQUEST],
                &vv_payload,
            ]
            .concat()
        );
        let (decoded_key, decoded_subtag, decoded_payload) =
            decode_window_sync(&vv_request[1..]).unwrap();
        assert_eq!(decoded_key, key);
        assert_eq!(decoded_subtag, window_sub_tags::VV_REQUEST);
        assert_eq!(decoded_payload, vv_payload);

        let vv_response = encode_window_sync(key, window_sub_tags::VV_RESPONSE, &vv_payload)
            .into_result()
            .unwrap();
        let (_, decoded_subtag, decoded_payload) = decode_window_sync(&vv_response[1..]).unwrap();
        assert_eq!(decoded_subtag, window_sub_tags::VV_RESPONSE);
        assert_eq!(decoded_payload, vv_payload);

        let update = encode_window_sync(key, window_sub_tags::UPDATE, &update_payload)
            .into_result()
            .unwrap();
        let (_, decoded_subtag, decoded_payload) = decode_window_sync(&update[1..]).unwrap();
        assert_eq!(decoded_subtag, window_sub_tags::UPDATE);
        assert_eq!(decoded_payload, update_payload);
    }

    /// ONE-1140 (OD-5) wire literals: TAG_LEASE_REQUEST=4 (105 B) and
    /// TAG_LEASE_GRANTED=5 (18 B), BE scalars at pinned offsets. Byte-exact
    /// round-trips plus exhaustive malformed-frame rejection — a transposed
    /// field, LE flip, or length drift fails here, not at a peer.
    #[test]
    fn lease_frame_layout_literals() {
        assert_eq!(TAG_LEASE_REQUEST, 4, "lease request tag pinned to 4");
        assert_eq!(TAG_LEASE_GRANTED, 5, "lease granted tag pinned to 5");

        // LeaseRequest: [0x04][client_id:8 BE][pubkey:32][pop_sig:64].
        let pubkey = [0xAAu8; 32];
        let pop_sig = [0xBBu8; 64];
        let request = encode_lease_request(0x0102030405060708, &pubkey, &pop_sig);
        assert_eq!(request.len(), 105, "LeaseRequest frame is exactly 105 B");
        assert_eq!(request[0], 4);
        assert_eq!(
            &request[1..9],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "client_id is u64 BE at offset 1"
        );
        assert_eq!(&request[9..41], &[0xAA; 32]);
        assert_eq!(&request[41..105], &[0xBB; 64][..]);
        let (cid, pk, sig) = decode_lease_request(&request[1..]).unwrap();
        assert_eq!(cid, 0x0102030405060708);
        assert_eq!(pk, pubkey);
        assert_eq!(sig, pop_sig);
        // Exhaustive length validation: truncated and trailing both reject.
        assert!(decode_lease_request(&request[1..104]).is_err());
        let mut long = request[1..].to_vec();
        long.push(0);
        assert!(decode_lease_request(&long).is_err());

        // LeaseGranted: [0x05][status:1][client_id:8 BE][expires_at:8 BE].
        let granted = encode_lease_granted(LEASE_STATUS_GRANTED, 0x0102030405060708, 0x11223344);
        assert_eq!(granted.len(), 18, "LeaseGranted frame is exactly 18 B");
        assert_eq!(granted[0], 5);
        assert_eq!(granted[1], 0x01, "granted status byte");
        assert_eq!(
            &granted[2..10],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            &granted[10..18],
            &0x11223344u64.to_be_bytes(),
            "expires_at is u64 BE at offset 10"
        );
        assert_eq!(
            decode_lease_granted(&granted[1..]).unwrap(),
            (LEASE_STATUS_GRANTED, 0x0102030405060708, 0x11223344)
        );
        // Rejection frame: status 0x00, expires_at MUST be 0.
        let rejected = encode_lease_granted(LEASE_STATUS_REJECTED, 7, 0);
        assert_eq!(rejected[1], 0x00);
        assert_eq!(
            decode_lease_granted(&rejected[1..]).unwrap(),
            (LEASE_STATUS_REJECTED, 7, 0)
        );
        // Malformed: unknown status byte, nonzero expires_at on rejection,
        // wrong lengths — all typed rejections (fail closed).
        let mut bad_status = granted[1..].to_vec();
        bad_status[0] = 0x02;
        assert!(decode_lease_granted(&bad_status).is_err());
        let mut rejected_nonzero = rejected[1..].to_vec();
        rejected_nonzero[16] = 1;
        assert!(decode_lease_granted(&rejected_nonzero).is_err());
        assert!(decode_lease_granted(&granted[1..17]).is_err());
        let mut granted_long = granted[1..].to_vec();
        granted_long.push(0);
        assert!(decode_lease_granted(&granted_long).is_err());
    }

    #[test]
    fn protocol_hello_decode_roundtrip() {
        let frame = encode_protocol_hello();
        assert_eq!(decode_protocol_hello(&frame).unwrap(), PROTOCOL_VERSION);
        let legacy_frame = encode_legacy_full_window_protocol_hello();
        assert_eq!(
            decode_protocol_hello(&legacy_frame).unwrap(),
            LEGACY_FULL_WINDOW_PROTOCOL_VERSION
        );
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
            assert_matches!(
                decode_protocol_hello(frame),
                Err(TransportError::InvalidPayload(_)),
                "case {case_name}: expected InvalidPayload"
            );
        }
    }

    #[test]
    fn window_sync_roundtrip() {
        let key = "2026-02";
        let msg = b"test payload";
        let encoded = encode_window_sync(key, window_sub_tags::UPDATE, msg)
            .into_result()
            .unwrap();
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
        let encoded = encode_bulk_transfer(key, &data).into_result().unwrap();
        assert_eq!(encoded[0], TAG_BULK_TRANSFER);
        let (dk, dd) = decode_bulk_transfer(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(dd, &data[..]);
    }

    #[test]
    fn bulk_transfer_done_roundtrip() {
        let key = "2025-09";
        let state = vec![10, 20];
        let encoded = encode_bulk_transfer_done(key, &state)
            .into_result()
            .unwrap();
        assert_eq!(encoded[0], TAG_BULK_TRANSFER_DONE);
        let (dk, ds) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
        assert_eq!(dk, key);
        assert_eq!(ds, &state[..]);
    }

    #[test]
    fn bulk_transfer_done_empty_state() {
        let encoded = encode_bulk_transfer_done("2025-08", &[])
            .into_result()
            .unwrap();
        let (k, s) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
        assert_eq!(k, "2025-08");
        assert!(s.is_empty());
    }

    #[test]
    fn window_sync_encoder_rejects_hostile_keys_without_panicking() {
        for key in ["", "2026-003", "window", "2026-0x"] {
            assert_matches!(
                encode_window_sync(key, window_sub_tags::UPDATE, b"payload").into_result(),
                Err(TransportError::InvalidWindowKey),
                "key {key:?} should return InvalidWindowKey"
            );
        }
    }

    #[test]
    fn bulk_transfer_encoder_rejects_hostile_keys_without_panicking() {
        for key in ["", "2026-003", "window", "2026-0x"] {
            assert_matches!(
                encode_bulk_transfer(key, b"zstd").into_result(),
                Err(TransportError::InvalidWindowKey),
                "key {key:?} should return InvalidWindowKey"
            );
        }
    }

    #[test]
    fn bulk_transfer_done_encoders_reject_hostile_keys_without_panicking() {
        for key in ["", "2026-003", "window", "2026-0x"] {
            assert_matches!(
                encode_bulk_transfer_done(key, b"state").into_result(),
                Err(TransportError::InvalidWindowKey),
                "key {key:?} should return InvalidWindowKey"
            );
            assert_matches!(
                encode_bulk_transfer_done_checked(key, b"state"),
                Err(TransportError::InvalidWindowKey),
                "key {key:?} should return InvalidWindowKey"
            );
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn bulk_transfer_done_checked_encoder_rejects_u32_overflow_len() {
        let err = checked_bulk_transfer_done_state_len(u32::MAX as usize + 1).unwrap_err();

        assert_matches!(
            err,
            TransportError::InvalidPayload("BulkTransferDone state too large")
        );
    }

    #[test]
    fn bulk_transfer_done_capacity_rejects_usize_overflow() {
        let err = checked_bulk_transfer_done_capacity(MAX_WINDOW_KEY_LEN, usize::MAX).unwrap_err();

        assert_matches!(
            err,
            TransportError::FrameTooLarge { size, max }
                if size == usize::MAX && max == MAX_ENCODED_FRAME_BYTES
        );
    }

    #[test]
    fn window_sync_encoder_rejects_oversized_payload_without_panicking() {
        let payload = vec![0u8; MAX_ENCODED_FRAME_BYTES];

        assert_matches!(
            encode_window_sync("2026-02", window_sub_tags::UPDATE, &payload).into_result(),
            Err(TransportError::FrameTooLarge { size, max })
                if size == MAX_ENCODED_FRAME_BYTES + 10 && max == MAX_ENCODED_FRAME_BYTES
        );
    }

    #[test]
    fn bulk_transfer_encoder_rejects_oversized_payload_without_panicking() {
        let payload = vec![0u8; MAX_ENCODED_FRAME_BYTES];

        assert_matches!(
            encode_bulk_transfer("2026-02", &payload).into_result(),
            Err(TransportError::FrameTooLarge { size, max })
                if size == MAX_ENCODED_FRAME_BYTES + 9 && max == MAX_ENCODED_FRAME_BYTES
        );
    }

    #[test]
    fn bulk_transfer_done_encoder_rejects_oversized_payload_without_panicking() {
        let state = vec![0u8; MAX_ENCODED_FRAME_BYTES];

        assert_matches!(
            encode_bulk_transfer_done("2026-02", &state).into_result(),
            Err(TransportError::FrameTooLarge { size, max })
                if size == MAX_ENCODED_FRAME_BYTES + 13 && max == MAX_ENCODED_FRAME_BYTES
        );
    }

    #[test]
    fn encoded_frame_len_rejects_usize_overflow() {
        assert_matches!(
            checked_encoded_frame_len(MAX_WINDOW_KEY_LEN, usize::MAX),
            Err(TransportError::FrameTooLarge { size, max })
                if size == usize::MAX && max == MAX_ENCODED_FRAME_BYTES
        );
    }

    #[test]
    fn bulk_transfer_done_rejects_trailing_bytes() {
        let state = vec![10, 20];
        let mut encoded = encode_bulk_transfer_done("2025-09", &state);
        encoded.push(30);

        assert_matches!(
            decode_bulk_transfer_done(&encoded[1..]),
            Err(TransportError::InvalidPayload("state has trailing bytes"))
        );
    }

    #[test]
    fn bulk_transfer_done_rejects_truncated_state() {
        let state = vec![10, 20];
        let mut encoded = encode_bulk_transfer_done("2025-09", &state);
        encoded.pop();

        assert_matches!(
            decode_bulk_transfer_done(&encoded[1..]),
            Err(TransportError::InvalidPayload("state truncated"))
        );
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

            assert_matches!(
                decoder(&data),
                Err(TransportError::InvalidWindowKey),
                "case {case_name}: expected InvalidWindowKey for key {:?}",
                std::str::from_utf8(invalid_key).unwrap_or("<bytes>")
            );
        }
    }
}
