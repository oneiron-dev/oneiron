//! A window frame made whole before the release door splits it (FIX 8247).
//!
//! A replacement snapshot or a catch-up delta may hold more than one frame's
//! payload: a window whose pieces together pass the frame floor, or a row
//! larger than one frame, such as an authority entry (FIX 8087, 8246). The
//! home makes it as one unsplit `WindowSync` frame that never leaves as it
//! is: the socket's release door puts it in its window pad envelope, which
//! goes as a first frame and `WINDOW_PAD_PART` frames, each within the frame
//! floor ([`super::MAX_DECODED_PAYLOAD_BYTES`]). The receiver joins them on
//! its socket and checks the payload whole against the digest in the
//! envelope's header before any admission reads it.

use super::{TAG_WINDOW_SYNC, TransportError, validate_window_key, window_sub_tags};

/// The longest payload one window pad envelope carries: its header's 32-bit
/// payload length. A payload joined from its parts is bounded by this, never
/// by one frame.
pub const MAX_WINDOW_PAD_PAYLOAD_BYTES: usize = u32::MAX as usize;

/// `[TAG_WINDOW_SYNC][key length][key][sub_tag][payload]` for an `UPDATE` or
/// a `REPLACEMENT` of any length up to [`MAX_WINDOW_PAD_PAYLOAD_BYTES`]: only
/// for a frame the release door envelopes and splits before it is sent.
///
/// # Errors
///
/// An invalid key, a sub-tag that carries no window bytes, or a payload past
/// what an envelope holds.
pub fn encode_unsplit_window_sync(
    window_key: &str,
    sub_tag: u8,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let key = validate_window_key(window_key)?;
    if !matches!(
        sub_tag,
        window_sub_tags::UPDATE | window_sub_tags::REPLACEMENT
    ) {
        return Err(TransportError::InvalidPayload(
            "unsplit window frame carries no window bytes",
        ));
    }
    if payload.len() > MAX_WINDOW_PAD_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size: payload.len(),
            max: MAX_WINDOW_PAD_PAYLOAD_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(3 + key.len() + payload.len());
    frame.push(TAG_WINDOW_SYNC);
    frame.push(key.len() as u8);
    frame.extend_from_slice(key);
    frame.push(sub_tag);
    frame.extend_from_slice(payload);
    Ok(frame)
}
