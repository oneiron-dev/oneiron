//! Entity-key frames and bounded, non-nesting document batches.

use super::{EncodedFrame, TransportError, checked_encoded_frame_len};
use crate::EntityId;
use crate::store::framing::validate_document_kind as validate_kind;

pub use crate::store::document_frame_tags::{TAG_BATCH, TAG_DOCUMENT};

/// The members one batch this node sends carries at most: a sender's
/// processing quantum, never a receiver's refusal. A receiver takes every
/// member a batch carries within the frame's byte bound (FIX 10163).
const MAX_BATCH_DOCUMENTS: usize = 256;
/// Maximum proposals carried by one node tick. Excess waits for its next tick.
pub const MAX_NODE_BATCH_MEMBERS: usize = MAX_BATCH_DOCUMENTS;

pub use crate::store::document_frame_tags::document_sub_tags;

/// Borrowed, validated entity-document frame.
#[derive(Debug, PartialEq, Eq)]
pub struct DocumentFrame<'a> {
    pub entity: EntityId,
    pub kind: u8,
    pub payload: &'a [u8],
}

/// The initiating operation of a nonterminal document open wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DocumentWaitedOut {
    Update = document_sub_tags::UPDATE,
    Request = document_sub_tags::REQUEST,
}

impl TryFrom<u8> for DocumentWaitedOut {
    type Error = TransportError;

    fn try_from(kind: u8) -> Result<Self, Self::Error> {
        match kind {
            document_sub_tags::UPDATE => Ok(Self::Update),
            document_sub_tags::REQUEST => Ok(Self::Request),
            _ => Err(TransportError::InvalidPayload(
                "invalid document wait initiator",
            )),
        }
    }
}

/// No body, vector, acknowledgement or settlement accompanies this answer.
pub fn encode_document_waited_out(entity: EntityId, waited: DocumentWaitedOut) -> EncodedFrame {
    encode_document(entity, document_sub_tags::WAITED_OUT, &[waited as u8])
}

/// Exactly one initiating-kind byte; all other payload shapes are invalid.
pub fn decode_document_waited_out(payload: &[u8]) -> Result<DocumentWaitedOut, TransportError> {
    let [kind] = payload else {
        return Err(TransportError::InvalidPayload(
            "invalid document wait payload",
        ));
    };
    DocumentWaitedOut::try_from(*kind)
}

pub fn encode_document(entity: EntityId, kind: u8, payload: &[u8]) -> EncodedFrame {
    EncodedFrame(crate::store::framing::encode_document(
        entity, kind, payload,
    ))
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

/// Decodes the entire batch before a caller can apply any member. Every
/// member the frame's byte bound holds is taken, however many (FIX 10163):
/// each costs at least its length and its document header, so the bound on
/// bytes bounds the members and their memory.
pub fn decode_document_batch(mut data: &[u8]) -> Result<Vec<DocumentFrame<'_>>, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    let mut frames = Vec::new();
    while !data.is_empty() {
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

/// One node tick's proposals: document traffic and ledger writes share one
/// non-nesting BATCH. Each member still passes its ordinary admission door.
pub fn encode_node_batch(frames: &[Vec<u8>]) -> EncodedFrame {
    let result = (|| {
        if frames.is_empty() || frames.len() > MAX_BATCH_DOCUMENTS {
            return Err(TransportError::InvalidPayload("invalid node batch size"));
        }
        let mut size = 1;
        for frame in frames {
            validate_node_member(frame)?;
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

/// Validate the whole node batch before dispatching any member. Root writes,
/// RPCs, subscription controls and nested batches cannot ride this lane.
/// Every member within the frame's byte bound is taken, however many (FIX
/// 10163); the receiver dispatches them in order.
pub fn decode_node_batch(mut data: &[u8]) -> Result<Vec<&[u8]>, TransportError> {
    checked_encoded_frame_len(1, data.len())?;
    let mut frames = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(TransportError::InvalidPayload("invalid node batch length"));
        }
        let len = u32::from_be_bytes(data[..4].try_into().expect("length checked")) as usize;
        data = &data[4..];
        let frame = data.get(..len).ok_or(TransportError::InvalidPayload(
            "truncated node batch member",
        ))?;
        validate_node_member(frame)?;
        frames.push(frame);
        data = &data[len..];
    }
    if frames.is_empty() {
        return Err(TransportError::InvalidPayload("empty node batch"));
    }
    Ok(frames)
}

fn validate_node_member(frame: &[u8]) -> Result<(), TransportError> {
    match frame.first() {
        Some(&TAG_DOCUMENT) => decode_document(&frame[1..]).map(|_| ()),
        Some(&super::TAG_WINDOW_SYNC) => {
            let (_, kind, payload) = super::decode_window_sync(&frame[1..])?;
            // A window write's envelope is read before any member dispatches;
            // its parts may follow it in the same batch.
            match kind {
                super::window_sub_tags::UPDATE
                | super::window_sub_tags::RESIDENCE_UPDATE
                | super::window_sub_tags::WINDOW_PAD_PART => {
                    super::validate_window_pad_member(kind, payload)
                }
                _ => Err(TransportError::InvalidPayload(
                    "batch requires window writes",
                )),
            }
        }
        _ => Err(TransportError::InvalidPayload("invalid node batch member")),
    }
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
