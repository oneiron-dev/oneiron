//! Custody carrier leaf-key frames (FIX 11785, FIX 7402).
//!
//! An executor asks for the leaf key of a carrier another machine holds
//! (Request), the holder answers with the key sealed to the executor's
//! machine key (Answer), or the request fails with a named cause (Failure).
//! The home relays them in memory between two live sockets of the owner's
//! machines and keeps none of them. A Request and an Answer carry exactly
//! the bytes secret custody encodes; this module reads nothing inside them.

use std::time::Duration;

use super::{EncodedFrame, TransportError, checked_encoded_frame_len};
use crate::secret_custody::{LeafKeyAnswer, LeafKeyFailureCause, LeafKeyRequest};

/// Request: `[tag][the request's own bytes]`.
pub const TAG_LEAF_KEY_REQUEST: u8 = 27;
/// Answer: `[tag][the answer's own bytes]`.
pub const TAG_LEAF_KEY_ANSWER: u8 = 28;
/// Failure: `[tag][request_id:32][cause:1][reason_len:4BE][reason UTF-8]`.
/// The reason is empty except for a holder's refusal.
pub const TAG_LEAF_KEY_FAILURE: u8 = 29;

/// How long an executor waits after a request failed before it sends it
/// again, while secret custody still lists it pending (a call, FIX 11785).
pub const LEAF_KEY_RETRY: Duration = Duration::from_secs(5);

/// A Failure frame's bytes before its reason: tag, request id, cause, length.
const FAILURE_HEAD_BYTES: usize = 1 + 32 + 1 + 4;

/// Encodes a Request frame.
pub fn encode_leaf_key_request(request: &LeafKeyRequest) -> EncodedFrame {
    tagged(TAG_LEAF_KEY_REQUEST, &request.encode())
}

/// Decodes bytes after the Request tag.
pub fn decode_leaf_key_request(data: &[u8]) -> Result<LeafKeyRequest, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    LeafKeyRequest::decode(data)
        .map_err(|_| TransportError::InvalidPayload("leaf key request does not decode"))
}

/// Encodes an Answer frame.
pub fn encode_leaf_key_answer(answer: &LeafKeyAnswer) -> EncodedFrame {
    tagged(TAG_LEAF_KEY_ANSWER, &answer.encode())
}

/// Decodes bytes after the Answer tag.
pub fn decode_leaf_key_answer(data: &[u8]) -> Result<LeafKeyAnswer, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    LeafKeyAnswer::decode(data)
        .map_err(|_| TransportError::InvalidPayload("leaf key answer does not decode"))
}

/// Encodes a Failure frame for request `request_id`.
pub fn encode_leaf_key_failure(request_id: &[u8; 32], cause: &LeafKeyFailureCause) -> EncodedFrame {
    let (code, reason) = cause_code(cause);
    let result = (|| {
        let size = checked_encoded_frame_len(FAILURE_HEAD_BYTES, reason.len())?;
        let reason_len = u32::try_from(reason.len())
            .map_err(|_| TransportError::InvalidPayload("leaf key failure reason length"))?;
        let mut frame = Vec::with_capacity(size);
        frame.push(TAG_LEAF_KEY_FAILURE);
        frame.extend_from_slice(request_id);
        frame.push(code);
        frame.extend_from_slice(&reason_len.to_be_bytes());
        frame.extend_from_slice(reason.as_bytes());
        Ok(frame)
    })();
    EncodedFrame(result)
}

/// Decodes bytes after the Failure tag, exactly: the request id and its
/// cause.
pub fn decode_leaf_key_failure(
    data: &[u8],
) -> Result<([u8; 32], LeafKeyFailureCause), TransportError> {
    let (request_id, rest) = data.split_first_chunk::<32>().ok_or_else(short)?;
    let (&code, rest) = rest.split_first().ok_or_else(short)?;
    let (reason_len, reason) = rest.split_first_chunk::<4>().ok_or_else(short)?;
    if usize::try_from(u32::from_be_bytes(*reason_len)).ok() != Some(reason.len()) {
        return Err(TransportError::InvalidPayload(
            "leaf key failure reason length",
        ));
    }
    let reason = std::str::from_utf8(reason)
        .map_err(|_| TransportError::InvalidPayload("leaf key failure reason is not UTF-8"))?;
    Ok((*request_id, cause_from_code(code, reason)?))
}

/// A leaf-key request id as the logs name it: lowercase hex.
pub fn leaf_key_request_hex(request_id: &[u8; 32]) -> String {
    request_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The cause byte a Failure frame carries for `cause`, and its reason.
fn cause_code(cause: &LeafKeyFailureCause) -> (u8, &str) {
    match cause {
        LeafKeyFailureCause::HolderOffline => (0, ""),
        LeafKeyFailureCause::ExecutorOffline => (1, ""),
        LeafKeyFailureCause::Expired => (2, ""),
        LeafKeyFailureCause::Replayed => (3, ""),
        LeafKeyFailureCause::HolderRefused(reason) => (4, reason),
    }
}

/// The cause a Failure frame's cause byte and reason name. Only a holder's
/// refusal carries a reason.
fn cause_from_code(code: u8, reason: &str) -> Result<LeafKeyFailureCause, TransportError> {
    let cause = match code {
        0 => LeafKeyFailureCause::HolderOffline,
        1 => LeafKeyFailureCause::ExecutorOffline,
        2 => LeafKeyFailureCause::Expired,
        3 => LeafKeyFailureCause::Replayed,
        4 => return Ok(LeafKeyFailureCause::HolderRefused(reason.to_owned())),
        _ => {
            return Err(TransportError::InvalidPayload(
                "unknown leaf key failure cause",
            ));
        }
    };
    if !reason.is_empty() {
        return Err(TransportError::InvalidPayload(
            "leaf key failure reason on a cause without one",
        ));
    }
    Ok(cause)
}

/// `bytes` after `tag`, under the transport's frame ceiling.
fn tagged(tag: u8, bytes: &[u8]) -> EncodedFrame {
    let result = checked_encoded_frame_len(1, bytes.len()).map(|size| {
        let mut frame = Vec::with_capacity(size);
        frame.push(tag);
        frame.extend_from_slice(bytes);
        frame
    });
    EncodedFrame(result)
}

/// A frame that ends before its fields do.
const fn short() -> TransportError {
    TransportError::InvalidPayload("short leaf key frame")
}
