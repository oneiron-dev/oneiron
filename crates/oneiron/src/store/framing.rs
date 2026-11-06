//! Document wire encoding shared by persisted consumers and sync transport.

use super::document_frame_tags::{TAG_DOCUMENT, document_sub_tags};
use super::window_protocol::MAX_DECODED_PAYLOAD_BYTES;
use crate::EntityId;

pub fn encode_document(
    entity: EntityId,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    checked_encoded_frame_len(18, payload.len())?;
    validate_document_kind(kind)?;
    let mut frame = Vec::with_capacity(18 + payload.len());
    frame.push(TAG_DOCUMENT);
    frame.extend_from_slice(entity.as_bytes());
    frame.push(kind);
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub(crate) fn validate_document_kind(kind: u8) -> Result<(), TransportError> {
    match kind {
        document_sub_tags::UPDATE
        | document_sub_tags::STATE
        | document_sub_tags::REQUEST
        | document_sub_tags::ACK
        | document_sub_tags::NOTE_OPS
        | document_sub_tags::NOTE_RECEIPT
        | document_sub_tags::ARTIFACT_PUBLICATION
        | document_sub_tags::ARTIFACT_RECEIPT
        | document_sub_tags::WAITED_OUT
        | document_sub_tags::NOTE_FORK_UPLOAD
        | document_sub_tags::NOTE_FORK_RECEIPT
        | document_sub_tags::NOTE_FORK_STATE
        | document_sub_tags::NOTE_FORK_SET
        | document_sub_tags::PART => Ok(()),
        _ => Err(TransportError::InvalidPayload("unknown document kind")),
    }
}

pub(crate) fn checked_encoded_frame_len(
    prefix_len: usize,
    payload_len: usize,
) -> Result<usize, TransportError> {
    let size = prefix_len
        .checked_add(payload_len)
        .ok_or(TransportError::FrameTooLarge {
            size: usize::MAX,
            max: MAX_DECODED_PAYLOAD_BYTES,
        })?;
    if size > MAX_DECODED_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size,
            max: MAX_DECODED_PAYLOAD_BYTES,
        });
    }
    Ok(size)
}

/// Transport-level errors for the sync wire protocol.
#[derive(Debug)]
pub enum TransportError {
    InvalidWindowKey,
    InvalidPayload(&'static str),
    /// A paged, grant-scoped metadata projection changed; restart at page one.
    IndexRevisionChanged,
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
    /// A Gate door refused the inbound bytes on policy grounds, carrying the
    /// door's own typed taxonomy. Distinct from [`Self::Storage`] on purpose:
    /// a denial needs owner approval and is never retried, while a storage
    /// failure is retriable, and a caller must be able to tell them apart
    /// without reading a message.
    AdmissionDenied(crate::error::GateDenial),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWindowKey => write!(f, "invalid window key"),
            Self::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            Self::IndexRevisionChanged => write!(f, "window index revision changed"),
            Self::UnknownTag(tag) => write!(f, "unknown tag: {tag}"),
            Self::FrameTooLarge { size, max } => write!(f, "frame too large: {size} (max {max})"),
            Self::VersionVectorDecode => write!(f, "version vector decode failure"),
            Self::WebSocket(msg) => write!(f, "websocket error: {msg}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::AdmissionDenied(denial) => {
                write!(
                    f,
                    "admission denied: outcome={}, reasons=",
                    denial.outcome()
                )?;
                for (index, reason) in denial.reason_codes().iter().enumerate() {
                    if index > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{reason}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for TransportError {}
