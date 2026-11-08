//! Physical frames of one server-authoritative root update. Small updates keep
//! their existing TAG_SYNC_UPDATE encoding; large ones arrive as one digest-bound
//! image and import only once every part is present.

use super::{MAX_DECODED_PAYLOAD_BYTES, TAG_SYNC_UPDATE, TransportError};

/// A part of one root snapshot or delta, server to client only.
pub const TAG_ROOT_PART: u8 = 6;
/// BLAKE3 image digest, total length and offset, before a part's bytes.
pub const ROOT_PART_HEADER_BYTES: usize = 32 + 8 + 8;

/// A borrowed part, bounded by the existing physical payload limit.
pub struct RootUpdatePart<'a> {
    pub digest: [u8; 32],
    pub total: usize,
    pub offset: usize,
    pub bytes: &'a [u8],
}

/// Decodes one physical part without allocating its advertised image.
pub fn decode_root_update_part(payload: &[u8]) -> Result<RootUpdatePart<'_>, TransportError> {
    if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size: payload.len(),
            max: MAX_DECODED_PAYLOAD_BYTES,
        });
    }
    if payload.len() <= ROOT_PART_HEADER_BYTES {
        return Err(TransportError::InvalidPayload("short root update part"));
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&payload[..32]);
    let mut total = [0; 8];
    total.copy_from_slice(&payload[32..40]);
    let total = usize::try_from(u64::from_be_bytes(total))
        .map_err(|_| TransportError::InvalidPayload("root update length is not addressable"))?;
    let mut offset = [0; 8];
    offset.copy_from_slice(&payload[40..ROOT_PART_HEADER_BYTES]);
    let offset = usize::try_from(u64::from_be_bytes(offset))
        .map_err(|_| TransportError::InvalidPayload("root update offset is not addressable"))?;
    let bytes = &payload[ROOT_PART_HEADER_BYTES..];
    if total <= MAX_DECODED_PAYLOAD_BYTES || offset >= total || bytes.len() > total - offset {
        return Err(TransportError::InvalidPayload("root update part geometry"));
    }
    Ok(RootUpdatePart {
        digest,
        total,
        offset,
        bytes,
    })
}

/// Makes only the next physical frame, rather than retaining all encoded parts.
pub struct RootUpdateFrames<'a> {
    bytes: &'a [u8],
    offset: usize,
    digest: Option<[u8; 32]>,
    sent: bool,
}

pub fn root_update_frames(bytes: &[u8]) -> RootUpdateFrames<'_> {
    RootUpdateFrames {
        bytes,
        offset: 0,
        digest: (bytes.len() > MAX_DECODED_PAYLOAD_BYTES).then(|| *blake3::hash(bytes).as_bytes()),
        sent: false,
    }
}

impl Iterator for RootUpdateFrames<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(digest) = self.digest else {
            if self.sent {
                return None;
            }
            self.sent = true;
            let mut frame = Vec::with_capacity(1 + self.bytes.len());
            frame.push(TAG_SYNC_UPDATE);
            frame.extend_from_slice(self.bytes);
            return Some(frame);
        };
        if self.offset == self.bytes.len() {
            return None;
        }
        let count = (self.bytes.len() - self.offset)
            .min(MAX_DECODED_PAYLOAD_BYTES - ROOT_PART_HEADER_BYTES);
        let end = self.offset + count;
        let mut frame = Vec::with_capacity(1 + ROOT_PART_HEADER_BYTES + count);
        frame.push(TAG_ROOT_PART);
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(&(self.bytes.len() as u64).to_be_bytes());
        frame.extend_from_slice(&(self.offset as u64).to_be_bytes());
        frame.extend_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Some(frame)
    }
}
