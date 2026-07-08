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
mod tests;
