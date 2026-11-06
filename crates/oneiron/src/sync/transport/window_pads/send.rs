//! Required prefixes of the exact frames an envelope encoded.

use super::{Header, PART_LEAD, WINDOW_PAD_HEADER_BYTES, WindowPadEnvelope, invalid};
use crate::sync::transport::{TransportError, decode_window_sync, window_sub_tags};

impl WindowPadEnvelope {
    /// Each original frame's prefix through the last required byte, or zero
    /// for an optional-only part. Truncating to these lengths leaves the
    /// header, envelope id and every required part offset unchanged.
    pub(crate) fn required_frame_prefixes(
        &self,
        frames: &[Vec<u8>],
    ) -> Result<Vec<usize>, TransportError> {
        let header = self.header()?;
        let required = Header::read(&header)?
            .required()
            .ok_or_else(|| invalid("window pad envelope length"))?;
        let body_required = required - WINDOW_PAD_HEADER_BYTES;
        let id = *blake3::hash(&header).as_bytes();
        frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                let (_, sub_tag, payload) = decode_window_sync(
                    frame
                        .get(1..)
                        .ok_or_else(|| invalid("short window frame"))?,
                )?;
                let lead = frame.len() - payload.len();
                if index == 0 {
                    if !payload.starts_with(&header) {
                        return Err(invalid("window pad first frame differs"));
                    }
                    return Ok(lead + payload.len().min(required));
                }
                if sub_tag != window_sub_tags::WINDOW_PAD_PART
                    || payload.get(..32) != Some(id.as_slice())
                {
                    return Err(invalid("window pad part differs"));
                }
                let offset = payload
                    .get(32..PART_LEAD)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or_else(|| invalid("short window pad part"))?;
                if offset >= body_required as u64 {
                    return Ok(0);
                }
                let needed = body_required - offset as usize;
                Ok(lead + PART_LEAD + (payload.len() - PART_LEAD).min(needed))
            })
            .collect()
    }
}
