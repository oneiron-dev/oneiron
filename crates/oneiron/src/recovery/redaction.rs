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
        let mut entity_copy = false;
        for row in &next.entity_documents {
            if row.text.contains(&span)
                || row.metadata.values().any(|value| copied(value))
                || row.summary_meta.values().any(|value| copied(value))
            {
                entity_copy = true;
                break;
            }
            let Some(history) = &row.history else {
                continue;
            };
            if history.texts()?.iter().any(|text| text.contains(&span))
                || history.versions.iter().any(|version| {
                    version.metadata.values().any(|value| copied(value))
                        || version.summary_meta.values().any(|value| copied(value))
                })
                || history.pins.iter().any(|pin| pin.quote.contains(&span))
                || history.forks.iter().any(|fork| {
                    fork.output
                        .as_deref()
                        .is_some_and(|output| output.contains(&span))
                        || fork
                            .output_metadata
                            .as_ref()
                            .is_some_and(|metadata| metadata.values().any(|value| copied(value)))
                        || fork
                            .keep
                            .as_deref()
                            .is_some_and(|keep| keep.contains(&span))
                })
            {
                entity_copy = true;
                break;
            }
        }
        let pin_rows: std::collections::BTreeMap<_, _> = next
            .document_pins
            .iter()
            .map(|row| (row.key.as_str(), row.row.as_slice()))
            .collect();
        for row in &next.document_pins {
            if crate::room_codec::carrier_parts::is_part_key(&row.key) {
                continue;
            }
            let pin =
                crate::room_codec::document_pins::carried_pin_from(&row.key, &row.row, |key| {
                    pin_rows.get(key).copied()
                })?
                .ok_or(invalid("redaction citation unresolved"))?;
            if pin.anchor.quote().contains(&span) {
                entity_copy = true;
                break;
            }
        }
        if entity_copy
            || next.doc_snapshots.iter().any(|row| {
                row.text.contains(&span)
                    || row
                        .title
                        .as_deref()
                        .is_some_and(|title| title.contains(&span))
            })
            || next.base_edges.iter().any(|row| copied(&row.value))
            || next.tombstones.iter().any(|row| copied(&row.value))
            || next.entity_blobs.iter().any(|row| copied(&row.blob))
            || next
                .head_move_receipts
                .iter()
                .any(|row| copied(&row.receipt))
            || next.note_forks.iter().any(|row| {
                row.recovery_merge
                    .as_ref()
                    .is_some_and(|(base, merged)| base.contains(&span) || merged.contains(&span))
            })
            || next
                .note_proposals
                .iter()
                .any(|row| row.explainer.contains(&span))
        {
            return Err(invalid("redacted span remains in another source carrier"));
        }
        next.validate()?;
        Ok(next)
    }
}
