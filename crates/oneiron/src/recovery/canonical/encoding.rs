//! The validated snapshot's named MessagePack map, one field or source row per unit.

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer as _};

use super::{
    BoundedWriter, ByteBudget, CANONICAL_SNAPSHOT_MAX_BYTES, CanonicalEntity, CanonicalSnapshot,
};
use crate::error::Result;

/// Owns only the output and cursor; every page borrows the same immutable source.
pub(crate) struct CanonicalEncoding {
    out: BoundedWriter,
    started: bool,
    field: usize,
    row: Option<RowCursor>,
}

#[derive(Debug, Default)]
struct RowCursor {
    next: usize,
    blob: Option<usize>,
}

impl CanonicalEncoding {
    pub(crate) fn new(limit: usize) -> Result<Self> {
        let mut out = BoundedWriter {
            bytes: Vec::new(),
            budget: ByteBudget::new(limit.min(CANONICAL_SNAPSHOT_MAX_BYTES)),
            refused: None,
        };
        std::io::Write::write_all(&mut out, &[0; super::super::HEADER_LEN])
            .map_err(|_| out.refusal())?;
        Ok(Self {
            out,
            started: false,
            field: 0,
            row: None,
        })
    }

    pub(crate) fn position(&self) -> String {
        format!("encode {}:{:?}", self.field, self.row)
    }

    pub(crate) fn advance(&mut self, source: &CanonicalSnapshot, units: usize) -> Result<bool> {
        // Keep the native Serialize declaration's order and empty-row omissions.
        // The exhaustive binding makes a newly added source field require a decision here.
        let CanonicalSnapshot {
            window,
            entity_blobs,
            retained_claim_worlds,
            base_edges,
            tombstones,
            doc_snapshots,
            entity_documents,
            document_heads,
            head_move_receipts,
            note_forks,
            note_proposals,
            container_manifests,
            schema_manifest,
            suppressed_tasks,
            custody_transitions,
            room_turns,
            room_facts,
            document_pins,
            peer_origins,
            row_births,
            withdrawn_cutoffs,
            asset_body_refs,
        } = source;
        let fields: &[(&str, &dyn Field)] = &[
            ("window", &Scalar(window)),
            ("entity_blobs", &Entities(entity_blobs)),
            ("retained_claim_worlds", &Rows(retained_claim_worlds, false)),
            ("base_edges", &Rows(base_edges, false)),
            ("tombstones", &Rows(tombstones, false)),
            ("doc_snapshots", &Rows(doc_snapshots, false)),
            ("entity_documents", &Rows(entity_documents, false)),
            ("document_heads", &Rows(document_heads, false)),
            ("head_move_receipts", &Rows(head_move_receipts, false)),
            ("note_forks", &Rows(note_forks, false)),
            ("note_proposals", &Rows(note_proposals, false)),
            ("container_manifests", &Rows(container_manifests, false)),
            ("schema_manifest", &Scalar(schema_manifest)),
            ("suppressed_tasks", &Rows(suppressed_tasks, true)),
            ("custody_transitions", &Rows(custody_transitions, true)),
            ("room_turns", &Rows(room_turns, true)),
            ("room_facts", &Rows(room_facts, true)),
            ("document_pins", &Rows(document_pins, true)),
            ("peer_origins", &Rows(peer_origins, true)),
            ("row_births", &Rows(row_births, true)),
            ("withdrawn_cutoffs", &Rows(withdrawn_cutoffs, true)),
            ("asset_body_refs", &Rows(asset_body_refs, true)),
        ];
        for _ in 0..units.max(1) {
            if !self.started {
                let count = fields.iter().filter(|(_, field)| field.present()).count();
                let result = {
                    let mut serializer =
                        rmp_serde::Serializer::new(&mut self.out).with_struct_map();
                    serializer
                        .serialize_struct("CanonicalSnapshot", count)
                        .and_then(SerializeStruct::end)
                };
                result.map_err(|_| self.out.refusal())?;
                self.started = true;
                continue;
            }
            let Some((name, field)) = fields.get(self.field) else {
                return Ok(true);
            };
            if field.present() {
                if self.row.is_none() {
                    write_named(&mut self.out, name)?;
                }
                if !field.write(&mut self.out, &mut self.row)? {
                    continue;
                }
            }
            self.row = None;
            self.field += 1;
        }
        Ok(self.field == fields.len())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.out.bytes
    }
}

/// Scalar and ordinary row serializers stay native; entity blobs also yield within bytes.
trait Field {
    fn present(&self) -> bool;
    fn write(&self, out: &mut BoundedWriter, row: &mut Option<RowCursor>) -> Result<bool>;
}

struct Scalar<'a, T>(&'a T);

impl<T: Serialize> Field for Scalar<'_, T> {
    fn present(&self) -> bool {
        true
    }

    fn write(&self, out: &mut BoundedWriter, _row: &mut Option<RowCursor>) -> Result<bool> {
        write_named(out, self.0)?;
        Ok(true)
    }
}

struct Rows<'a, T>(&'a [T], bool);

impl<T: Serialize> Field for Rows<'_, T> {
    fn present(&self) -> bool {
        !self.1 || !self.0.is_empty()
    }

    fn write(&self, out: &mut BoundedWriter, row: &mut Option<RowCursor>) -> Result<bool> {
        if let Some(next) = row {
            write_named(out, &self.0[next.next])?;
            next.next += 1;
            return Ok(next.next == self.0.len());
        }
        write_array_header(out, self.0.len())?;
        *row = Some(RowCursor::default());
        Ok(self.0.is_empty())
    }
}

struct Entities<'a>(&'a [CanonicalEntity]);

impl Field for Entities<'_> {
    fn present(&self) -> bool {
        true
    }

    fn write(&self, out: &mut BoundedWriter, row: &mut Option<RowCursor>) -> Result<bool> {
        let Some(cursor) = row else {
            write_array_header(out, self.0.len())?;
            *row = Some(RowCursor::default());
            return Ok(self.0.is_empty());
        };
        let CanonicalEntity { id, blob } = &self.0[cursor.next];
        if let Some(next) = cursor.blob {
            let end = next.saturating_add(blake3::CHUNK_LEN).min(blob.len());
            // Vec<u8> uses the native normal-mode array of compact integers, not bin.
            for byte in &blob[next..end] {
                write_named(out, byte)?;
            }
            cursor.blob = Some(end);
            if end != blob.len() {
                return Ok(false);
            }
        } else {
            let result = {
                let mut serializer = rmp_serde::Serializer::new(&mut *out).with_struct_map();
                serializer
                    .serialize_struct("CanonicalEntity", 2)
                    .and_then(SerializeStruct::end)
            };
            result.map_err(|_| out.refusal())?;
            write_named(out, "id")?;
            write_named(out, id)?;
            write_named(out, "blob")?;
            write_array_header(out, blob.len())?;
            cursor.blob = Some(0);
            if !blob.is_empty() {
                return Ok(false);
            }
        }
        cursor.next += 1;
        cursor.blob = None;
        Ok(cursor.next == self.0.len())
    }
}

fn write_array_header(out: &mut BoundedWriter, len: usize) -> Result<()> {
    let result = {
        let mut serializer = rmp_serde::Serializer::new(&mut *out).with_struct_map();
        serializer
            .serialize_seq(Some(len))
            .and_then(SerializeSeq::end)
    };
    result.map_err(|_| out.refusal())
}

fn write_named<T: Serialize + ?Sized>(out: &mut BoundedWriter, value: &T) -> Result<()> {
    rmp_serde::encode::write_named(out, value).map_err(|_| out.refusal())
}
