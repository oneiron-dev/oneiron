//! By-reference ASSET body frames (FIX 5489).
//!
//! A receiver asks for the body a window's `asset_body_refs` entry names
//! (Want), its holder sends the bytes in ordered, bounded frames (Data) and
//! closes the attempt (End), and the receiver answers whether it committed
//! the body (Receipt). Either peer may be either side. The bytes stay out of
//! Loro and out of document batches. Every frame names its attempt, which
//! the receiver picks for its Want. A frame is bounded; a body is not
//! (Rule 5): its length is a u64 and no total is refused.
//!
//! Encode and decode only: no peer sends or reads these tags yet, so either
//! side still refuses one as an unknown tag.

use std::time::Duration;

use super::{
    EncodedFrame, MAX_ENCODED_FRAME_BYTES, MAX_WINDOW_KEY_LEN, TransportError,
    checked_encoded_frame_len, validate_window_key,
};
use crate::EntityId;
use crate::sync::types::parse_window_key_str;

/// Want: `[tag][attempt:16][window_key_len:1][window_key][entity:16]`
/// `[carrier_blake3:32][body_blake3:32][len:8BE][max_frame_bytes:4BE]`.
pub const TAG_ASSET_BODY_WANT: u8 = 23;
/// Data: `[tag][attempt:16][offset:8BE][bytes]`.
pub const TAG_ASSET_BODY_DATA: u8 = 24;
/// End: `[tag][attempt:16][complete:1]`.
pub const TAG_ASSET_BODY_END: u8 = 25;
/// Receipt: `[tag][attempt:16][window_key_len:1][window_key][entity:16]`
/// `[carrier_blake3:32][body_blake3:32][len:8BE][committed:1]`.
pub const TAG_ASSET_BODY_RECEIPT: u8 = 26;

/// The body bytes one Data frame carries by default (a call, FIX 5489): one
/// line-index block, 64 KiB. It bounds a frame, never a body.
pub const ASSET_BODY_FRAME_BYTES: usize = crate::store::LINE_INDEX_BLOCK_BYTES as usize;

/// How long a peer waits before it asks again for a body it is still owed,
/// while no attempt for it runs (a call, FIX 5489).
pub const ASSET_BODY_RETRY: Duration = Duration::from_secs(5);

/// A Data frame's bytes before its body bytes: tag, attempt, offset.
const DATA_HEAD_BYTES: usize = 1 + 16 + 8;

/// An address's bytes after its window key: entity, two digests, length.
const ADDRESS_TAIL_BYTES: usize = 16 + 32 + 32 + 8;

/// The exact reference a transfer moves: the window whose `asset_body_refs`
/// entry names it, its owner, the BLAKE3 of the carrier it binds, and the
/// body's BLAKE3 and length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBodyAddress {
    pub window: String,
    pub entity: EntityId,
    pub carrier_blake3: [u8; 32],
    pub body_blake3: [u8; 32],
    pub len: u64,
}

/// A receiver's ask for one body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBodyWant {
    /// The attempt the receiver picked: every frame of the transfer names it.
    pub attempt: [u8; 16],
    pub body: AssetBodyAddress,
    /// The most body bytes one Data frame may carry to this receiver.
    pub max_frame_bytes: u32,
}

/// One frame of a body: `bytes` from `offset`.
#[derive(Debug, PartialEq, Eq)]
pub struct AssetBodyData<'a> {
    pub attempt: [u8; 16],
    pub offset: u64,
    pub bytes: &'a [u8],
}

/// The sender's close of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetBodyEnd {
    pub attempt: [u8; 16],
    /// Every byte was sent and the sender's read of the body checked. When
    /// `false` the sender stopped, and the receiver discards what it holds.
    pub complete: bool,
}

/// The receiver's answer for one body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBodyReceipt {
    pub attempt: [u8; 16],
    pub body: AssetBodyAddress,
    /// The receiver committed exactly this body. When `false` it refused it.
    pub committed: bool,
}

/// The body bytes one Data frame carries to a receiver whose Want asked for
/// at most `wanted`, on a socket whose frames hold at most `socket_max`
/// bytes: the least of the two and [`ASSET_BODY_FRAME_BYTES`], under the
/// transport's own frame ceiling once the Data head is counted, and at
/// least one.
pub fn asset_body_frame_bytes(wanted: u32, socket_max: usize) -> usize {
    let ceiling = MAX_ENCODED_FRAME_BYTES
        .min(socket_max)
        .saturating_sub(DATA_HEAD_BYTES);
    usize::try_from(wanted)
        .unwrap_or(usize::MAX)
        .min(ASSET_BODY_FRAME_BYTES)
        .min(ceiling)
        .max(1)
}

/// Encodes a Want frame.
pub fn encode_asset_body_want(want: &AssetBodyWant) -> EncodedFrame {
    let result = (|| {
        if want.max_frame_bytes == 0 {
            return Err(TransportError::InvalidPayload(
                "asset body Want without frame bytes",
            ));
        }
        let key = validate_window_key(&want.body.window)?;
        let size = checked_encoded_frame_len(18 + key.len() + ADDRESS_TAIL_BYTES, 4)?;
        let mut frame = Vec::with_capacity(size);
        frame.push(TAG_ASSET_BODY_WANT);
        frame.extend_from_slice(&want.attempt);
        push_address(&mut frame, key, &want.body);
        frame.extend_from_slice(&want.max_frame_bytes.to_be_bytes());
        Ok(frame)
    })();
    EncodedFrame(result)
}

/// Decodes bytes after the Want tag, exactly.
pub fn decode_asset_body_want(data: &[u8]) -> Result<AssetBodyWant, TransportError> {
    let (attempt, rest) = read_attempt(data)?;
    let (body, rest) = read_address(rest)?;
    let max_frame_bytes = <[u8; 4]>::try_from(rest)
        .map(u32::from_be_bytes)
        .map_err(|_| TransportError::InvalidPayload("asset body Want length"))?;
    if max_frame_bytes == 0 {
        return Err(TransportError::InvalidPayload(
            "asset body Want without frame bytes",
        ));
    }
    Ok(AssetBodyWant {
        attempt,
        body,
        max_frame_bytes,
    })
}

/// Encodes a Data frame of at least one byte.
pub fn encode_asset_body_data(data: &AssetBodyData<'_>) -> EncodedFrame {
    let result = (|| {
        if data.bytes.is_empty() {
            return Err(TransportError::InvalidPayload("empty asset body Data"));
        }
        let size = checked_encoded_frame_len(DATA_HEAD_BYTES, data.bytes.len())?;
        let mut frame = Vec::with_capacity(size);
        frame.push(TAG_ASSET_BODY_DATA);
        frame.extend_from_slice(&data.attempt);
        frame.extend_from_slice(&data.offset.to_be_bytes());
        frame.extend_from_slice(data.bytes);
        Ok(frame)
    })();
    EncodedFrame(result)
}

/// Decodes bytes after the Data tag: a frame of at least one byte, whose
/// end fits in a u64.
pub fn decode_asset_body_data(data: &[u8]) -> Result<AssetBodyData<'_>, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    let (attempt, rest) = read_attempt(data)?;
    let (offset, bytes) = rest.split_first_chunk::<8>().ok_or_else(short)?;
    let offset = u64::from_be_bytes(*offset);
    if bytes.is_empty() || offset.checked_add(bytes.len() as u64).is_none() {
        return Err(TransportError::InvalidPayload("asset body Data range"));
    }
    Ok(AssetBodyData {
        attempt,
        offset,
        bytes,
    })
}

/// Encodes an End frame.
pub fn encode_asset_body_end(end: AssetBodyEnd) -> EncodedFrame {
    let mut frame = Vec::with_capacity(18);
    frame.push(TAG_ASSET_BODY_END);
    frame.extend_from_slice(&end.attempt);
    frame.push(u8::from(end.complete));
    EncodedFrame(Ok(frame))
}

/// Decodes bytes after the End tag, exactly.
pub fn decode_asset_body_end(data: &[u8]) -> Result<AssetBodyEnd, TransportError> {
    let (attempt, rest) = read_attempt(data)?;
    Ok(AssetBodyEnd {
        attempt,
        complete: read_flag(rest)?,
    })
}

/// Encodes a Receipt frame.
pub fn encode_asset_body_receipt(receipt: &AssetBodyReceipt) -> EncodedFrame {
    let result = (|| {
        let key = validate_window_key(&receipt.body.window)?;
        let size = checked_encoded_frame_len(18 + key.len() + ADDRESS_TAIL_BYTES, 1)?;
        let mut frame = Vec::with_capacity(size);
        frame.push(TAG_ASSET_BODY_RECEIPT);
        frame.extend_from_slice(&receipt.attempt);
        push_address(&mut frame, key, &receipt.body);
        frame.push(u8::from(receipt.committed));
        Ok(frame)
    })();
    EncodedFrame(result)
}

/// Decodes bytes after the Receipt tag, exactly.
pub fn decode_asset_body_receipt(data: &[u8]) -> Result<AssetBodyReceipt, TransportError> {
    let (attempt, rest) = read_attempt(data)?;
    let (body, rest) = read_address(rest)?;
    Ok(AssetBodyReceipt {
        attempt,
        body,
        committed: read_flag(rest)?,
    })
}

/// Appends `body`'s address, `key` being its checked window key.
fn push_address(frame: &mut Vec<u8>, key: &[u8], body: &AssetBodyAddress) {
    frame.push(key.len() as u8);
    frame.extend_from_slice(key);
    frame.extend_from_slice(body.entity.as_bytes());
    frame.extend_from_slice(&body.carrier_blake3);
    frame.extend_from_slice(&body.body_blake3);
    frame.extend_from_slice(&body.len.to_be_bytes());
}

fn read_attempt(data: &[u8]) -> Result<([u8; 16], &[u8]), TransportError> {
    data.split_first_chunk::<16>()
        .map(|(attempt, rest)| (*attempt, rest))
        .ok_or_else(short)
}

fn read_address(data: &[u8]) -> Result<(AssetBodyAddress, &[u8]), TransportError> {
    let (&key_len, rest) = data.split_first().ok_or_else(short)?;
    let key_len = usize::from(key_len);
    if key_len == 0 || key_len > MAX_WINDOW_KEY_LEN {
        return Err(TransportError::InvalidWindowKey);
    }
    let (key, rest) = rest.split_at_checked(key_len).ok_or_else(short)?;
    let window = std::str::from_utf8(key).map_err(|_| TransportError::InvalidWindowKey)?;
    if parse_window_key_str(window).is_none() {
        return Err(TransportError::InvalidWindowKey);
    }
    let (entity, rest) = rest.split_first_chunk::<16>().ok_or_else(short)?;
    let (carrier_blake3, rest) = rest.split_first_chunk::<32>().ok_or_else(short)?;
    let (body_blake3, rest) = rest.split_first_chunk::<32>().ok_or_else(short)?;
    let (len, rest) = rest.split_first_chunk::<8>().ok_or_else(short)?;
    let entity = EntityId::from_bytes(*entity)
        .map_err(|_| TransportError::InvalidPayload("invalid asset body entity"))?;
    Ok((
        AssetBodyAddress {
            window: window.to_owned(),
            entity,
            carrier_blake3: *carrier_blake3,
            body_blake3: *body_blake3,
            len: u64::from_be_bytes(*len),
        },
        rest,
    ))
}

/// A frame that ends before its fields do.
const fn short() -> TransportError {
    TransportError::InvalidPayload("short asset body frame")
}

/// The one-byte flag that ends an End or a Receipt: 0 or 1, nothing after.
fn read_flag(rest: &[u8]) -> Result<bool, TransportError> {
    match rest {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(TransportError::InvalidPayload("asset body frame flag")),
    }
}
