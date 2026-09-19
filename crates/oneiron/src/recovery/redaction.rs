//! Cursor-independent redaction of a resolved, hash-bound canonical text span.

use super::{CanonicalSnapshot, canonical::invalid};
use crate::{EntityId, error::Result};

impl CanonicalSnapshot {
    /// Excludes a resolved Unicode-scalar span, bound to its expected quote hash.
    /// Cursor/frontier resolution belongs to the document door before capture.
    /// Copies in another source carrier must be scrubbed first; this refuses an
    /// incomplete redaction rather than claiming erasure while copies survive.
    pub fn excluding_document_span(
        &self,
        entity: EntityId,
        head: EntityId,
        start: usize,
        end: usize,
        quote_blake3: [u8; 32],
    ) -> Result<Self> {
        self.validate()?;
        let mut next = self.clone();
        let doc = next
            .doc_snapshots
            .iter_mut()
            .find(|doc| doc.entity_id == *entity.as_bytes() && doc.head == *head.as_bytes())
            .ok_or(invalid("redaction document absent"))?;
        let boundaries: Vec<_> = doc
            .text
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(doc.text.len()))
            .collect();
        if start >= end || end >= boundaries.len() {
            return Err(invalid("redaction span"));
        }
        let span = doc.text[boundaries[start]..boundaries[end]].to_owned();
        if *blake3::hash(span.as_bytes()).as_bytes() != quote_blake3 {
            return Err(invalid("redaction quote hash"));
        }
        doc.text
            .replace_range(boundaries[start]..boundaries[end], "");
        let copied = |bytes: &[u8]| {
            bytes
                .windows(span.len())
                .any(|part| part == span.as_bytes())
        };
        if next
            .doc_snapshots
            .iter()
            .any(|row| row.text.contains(&span))
            || next.base_edges.iter().any(|row| copied(&row.value))
            || next.tombstones.iter().any(|row| copied(&row.value))
            || next.entity_blobs.iter().any(|row| copied(&row.blob))
            || next
                .head_move_receipts
                .iter()
                .any(|row| copied(&row.receipt))
        {
            return Err(invalid("redacted span remains in another source carrier"));
        }
        next.validate()?;
        Ok(next)
    }
}
