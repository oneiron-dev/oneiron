//! Logical documents released as bounded frames and joined before admission.

use super::{
    DocumentFrame, MAX_DECODED_PAYLOAD_BYTES, TAG_DOCUMENT, TransportError,
    checked_encoded_frame_len,
};
use super::{decode_document, document_sub_tags, encode_document};
use crate::EntityId;
use oneiron_contracts::host_memory::{MachineMemory, MemoryLease};

// Original kind, total bytes, offset, and the complete payload's digest.
const PART_HEADER_BYTES: usize = 1 + 8 + 8 + 32;
const PART_BYTES: usize = MAX_DECODED_PAYLOAD_BYTES - 18 - PART_HEADER_BYTES;

/// A local logical document, not a wire frame. The socket's release door must
/// split it before sending it. Neither this nor a joined document proves
/// authority: the ordinary complete-document admission still runs.
pub fn encode_unsplit_document(
    entity: EntityId,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    validate_logical_kind(kind)?;
    let mut out = Vec::with_capacity(18 + payload.len());
    out.push(TAG_DOCUMENT);
    out.extend_from_slice(entity.as_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reads a trusted local logical document after its tag. Network frames must
/// first use `decode_document`, including its ordinary frame-size check.
pub fn decode_unsplit_document(data: &[u8]) -> Result<DocumentFrame<'_>, TransportError> {
    if data.len() < MAX_DECODED_PAYLOAD_BYTES {
        return decode_document(data);
    }
    let Some((header, payload)) = data.split_at_checked(17) else {
        return Err(TransportError::InvalidPayload("short logical document"));
    };
    validate_logical_kind(header[16])?;
    Ok(DocumentFrame {
        entity: EntityId::from_bytes(header[..16].try_into().expect("length checked"))
            .map_err(|_| TransportError::InvalidPayload("invalid document entity"))?,
        kind: header[16],
        payload,
    })
}

fn validate_logical_kind(kind: u8) -> Result<(), TransportError> {
    match kind {
        document_sub_tags::STATE
        | document_sub_tags::UPDATE
        | document_sub_tags::NOTE_OPS
        | document_sub_tags::NOTE_RECEIPT => Ok(()),
        _ => Err(TransportError::InvalidPayload(
            "invalid logical document kind",
        )),
    }
}

/// An oversized logical document's ordered run on one socket. Each yielded
/// frame satisfies the unchanged wire bound; the sender keeps its transport
/// borrow for the whole run.
pub struct DocumentPartFrames<'a> {
    document: DocumentFrame<'a>,
    digest: blake3::Hash,
    offset: usize,
}

impl<'a> DocumentPartFrames<'a> {
    pub fn new(frame: &'a [u8]) -> Result<Self, TransportError> {
        if frame.first() != Some(&TAG_DOCUMENT) {
            return Err(TransportError::InvalidPayload("not a logical document"));
        }
        let document = decode_unsplit_document(&frame[1..])?;
        Ok(Self {
            digest: blake3::hash(document.payload),
            document,
            offset: 0,
        })
    }
}

impl Iterator for DocumentPartFrames<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.document.payload.len() {
            return None;
        }
        let rest = &self.document.payload[self.offset..];
        let bytes = &rest[..rest.len().min(PART_BYTES)];
        let mut payload = Vec::with_capacity(PART_HEADER_BYTES + bytes.len());
        payload.push(self.document.kind);
        payload.extend_from_slice(&(self.document.payload.len() as u64).to_be_bytes());
        payload.extend_from_slice(&(self.offset as u64).to_be_bytes());
        payload.extend_from_slice(self.digest.as_bytes());
        payload.extend_from_slice(bytes);
        self.offset += bytes.len();
        Some(
            encode_document(self.document.entity, document_sub_tags::PART, &payload)
                .into_result()
                .expect("document part header and chunk fit the wire bound"),
        )
    }
}

/// A verified complete logical document, ready for its original admission.
pub struct JoinedDocument {
    entity: EntityId,
    kind: u8,
    payload: Vec<u8>,
    _memory: MemoryLease,
}

impl JoinedDocument {
    pub fn frame(&self) -> DocumentFrame<'_> {
        DocumentFrame {
            entity: self.entity,
            kind: self.kind,
            payload: &self.payload,
        }
    }
}

struct PendingDocument {
    entity: EntityId,
    kind: u8,
    total: u64,
    digest: [u8; 32],
    hash: blake3::Hasher,
    bytes: Vec<u8>,
    memory: MemoryLease,
}

/// One ordered transfer on a connection. An interrupted connection drops its
/// partial bytes; it has imported nothing and has acknowledged nothing.
#[derive(Default)]
pub struct DocumentAssembly {
    pending: Option<PendingDocument>,
}

impl DocumentAssembly {
    pub fn clear(&mut self) {
        self.pending = None;
    }

    /// Accepts only a size-checked wire part. No allocation follows a peer's
    /// claimed total: the buffer grows only with bytes actually received.
    /// Its lease observes actual retained capacity without a new memory wait
    /// or policy refusal; decoded-document allocations remain the importer's.
    pub fn accept(
        &mut self,
        part: DocumentFrame<'_>,
    ) -> Result<Option<JoinedDocument>, TransportError> {
        checked_encoded_frame_len(18, part.payload.len())?;
        let pending = self.pending.take();
        if part.kind != document_sub_tags::PART || part.payload.len() <= PART_HEADER_BYTES {
            return Err(TransportError::InvalidPayload("invalid document part"));
        }
        let kind = part.payload[0];
        validate_logical_kind(kind)?;
        let total = u64::from_be_bytes(part.payload[1..9].try_into().expect("length checked"));
        let offset = u64::from_be_bytes(part.payload[9..17].try_into().expect("length checked"));
        let digest: [u8; 32] = part.payload[17..49].try_into().expect("length checked");
        let bytes = &part.payload[PART_HEADER_BYTES..];
        if offset > total || bytes.len() as u64 > total - offset {
            return Err(TransportError::InvalidPayload(
                "document part exceeds total",
            ));
        }
        let mut pending = if offset == 0 {
            PendingDocument {
                entity: part.entity,
                kind,
                total,
                digest,
                hash: blake3::Hasher::new(),
                bytes: Vec::new(),
                memory: MachineMemory::process().empty_lease(),
            }
        } else {
            pending.ok_or(TransportError::InvalidPayload(
                "document part has no first part",
            ))?
        };
        if pending.entity != part.entity
            || pending.kind != kind
            || pending.total != total
            || pending.digest != digest
            || pending.bytes.len() as u64 != offset
        {
            return Err(TransportError::InvalidPayload("document part continuity"));
        }
        let old_capacity = pending.bytes.capacity();
        pending
            .bytes
            .try_reserve_exact(bytes.len())
            .map_err(|error| {
                TransportError::Storage(format!("document part allocation: {error}"))
            })?;
        pending.memory.materialized(
            0,
            pending.bytes.capacity().saturating_sub(old_capacity) as u64,
        );
        pending.hash.update(bytes);
        pending.bytes.extend_from_slice(bytes);
        if pending.bytes.len() as u64 != total {
            self.pending = Some(pending);
            return Ok(None);
        }
        if pending.hash.finalize().as_bytes() != &digest {
            return Err(TransportError::InvalidPayload("document payload digest"));
        }
        Ok(Some(JoinedDocument {
            entity: pending.entity,
            kind: pending.kind,
            payload: pending.bytes,
            _memory: pending.memory,
        }))
    }
}
