//! Entity-key frames and bounded, non-nesting document batches.

use super::{EncodedFrame, TransportError, checked_encoded_frame_len};
use crate::EntityId;

/// Entity text-plane frame: `[tag][entity:16][kind:1][payload]`.
pub const TAG_DOCUMENT: u8 = 11;
/// Document batch: `[tag][len:4BE][document frame]...`. Nesting is forbidden.
pub const TAG_BATCH: u8 = 12;

const MAX_BATCH_DOCUMENTS: usize = 256;

/// Document payload kinds. A state copy replaces the receiver's document.
pub mod document_sub_tags {
    pub const UPDATE: u8 = 0;
    pub const STATE: u8 = 1;
    /// Payload is a selector request envelope, with the peer's document VV.
    pub const REQUEST: u8 = 2;
    /// Receiver VV after a durable import.
    pub const ACK: u8 = 3;
    /// Authenticated semantic NOTE command. Actor is bound out of band.
    pub const NOTE_OPS: u8 = 4;
    /// Idempotent NOTE command result, sent only to the requesting connection.
    pub const NOTE_RECEIPT: u8 = 5;
}

/// Borrowed, validated entity-document frame.
#[derive(Debug, PartialEq, Eq)]
pub struct DocumentFrame<'a> {
    pub entity: EntityId,
    pub kind: u8,
    pub payload: &'a [u8],
}

pub fn encode_document(entity: EntityId, kind: u8, payload: &[u8]) -> EncodedFrame {
    let result = (|| {
        checked_encoded_frame_len(18, payload.len())?;
        validate_kind(kind)?;
        let mut frame = Vec::with_capacity(18 + payload.len());
        frame.push(TAG_DOCUMENT);
        frame.extend_from_slice(entity.as_bytes());
        frame.push(kind);
        frame.extend_from_slice(payload);
        Ok(frame)
    })();
    EncodedFrame(result)
}

/// Decodes bytes after the document tag, including size and kind checks.
pub fn decode_document(data: &[u8]) -> Result<DocumentFrame<'_>, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    if data.len() < 17 {
        return Err(TransportError::InvalidPayload("short document frame"));
    }
    validate_kind(data[16])?;
    Ok(DocumentFrame {
        entity: EntityId::from_bytes(data[..16].try_into().expect("length checked"))
            .map_err(|_| TransportError::InvalidPayload("invalid document entity"))?,
        kind: data[16],
        payload: &data[17..],
    })
}

fn validate_kind(kind: u8) -> Result<(), TransportError> {
    match kind {
        document_sub_tags::UPDATE
        | document_sub_tags::STATE
        | document_sub_tags::REQUEST
        | document_sub_tags::ACK
        | document_sub_tags::NOTE_OPS
        | document_sub_tags::NOTE_RECEIPT => Ok(()),
        _ => Err(TransportError::InvalidPayload("unknown document kind")),
    }
}

pub fn encode_document_batch(frames: &[Vec<u8>]) -> EncodedFrame {
    let result = (|| {
        if frames.len() > MAX_BATCH_DOCUMENTS {
            return Err(TransportError::InvalidPayload("too many batch documents"));
        }
        let mut size = 1;
        for frame in frames {
            validate_member(frame)?;
            size = checked_encoded_frame_len(size, 4 + frame.len())?;
        }
        let mut out = Vec::with_capacity(size);
        out.push(TAG_BATCH);
        for frame in frames {
            out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            out.extend_from_slice(frame);
        }
        Ok(out)
    })();
    EncodedFrame(result)
}

/// Decodes the entire batch before a caller can apply any member.
pub fn decode_document_batch(mut data: &[u8]) -> Result<Vec<DocumentFrame<'_>>, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    let mut frames = Vec::new();
    while !data.is_empty() {
        if frames.len() == MAX_BATCH_DOCUMENTS {
            return Err(TransportError::InvalidPayload("too many batch documents"));
        }
        if data.len() < 4 {
            return Err(TransportError::InvalidPayload("short batch length"));
        }
        let len = u32::from_be_bytes(data[..4].try_into().expect("length checked")) as usize;
        data = &data[4..];
        if len > data.len() {
            return Err(TransportError::InvalidPayload("truncated batch member"));
        }
        frames.push(validate_member(&data[..len])?);
        data = &data[len..];
    }
    Ok(frames)
}

fn validate_member(frame: &[u8]) -> Result<DocumentFrame<'_>, TransportError> {
    if frame.first() != Some(&TAG_DOCUMENT) {
        return Err(TransportError::InvalidPayload(
            "batch requires document frames",
        ));
    }
    decode_document(&frame[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_and_batch_roundtrip_are_bounded_and_non_nesting() {
        let id = EntityId::from_bytes([7; 16]).unwrap();
        let frame = encode_document(id, document_sub_tags::UPDATE, b"delta")
            .into_result()
            .unwrap();
        let doc = decode_document(&frame[1..]).unwrap();
        assert_eq!(doc.entity, id);
        assert_eq!(doc.payload, b"delta");
        let batch = encode_document_batch(&[frame.clone(), frame.clone()])
            .into_result()
            .unwrap();
        assert_eq!(
            decode_document_batch(&batch[1..]).unwrap(),
            vec![
                doc,
                DocumentFrame {
                    entity: id,
                    kind: 0,
                    payload: b"delta"
                }
            ]
        );
        assert!(
            encode_document_batch(std::slice::from_ref(&batch))
                .into_result()
                .is_err()
        );
        assert!(decode_document_batch(&batch[1..batch.len() - 1]).is_err());
        assert!(decode_document(&[0; 16]).is_err());
        let member = encode_document(id, 0, b"x").into_result().unwrap();
        assert!(
            encode_document_batch(&vec![member; MAX_BATCH_DOCUMENTS + 1])
                .into_result()
                .is_err()
        );
        assert!(
            encode_document(id, 0, &vec![0; super::super::MAX_DECODED_PAYLOAD_BYTES])
                .into_result()
                .is_err()
        );
    }
}
