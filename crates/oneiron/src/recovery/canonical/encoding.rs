//! The validated snapshot's named MessagePack map, one field or source row per unit.

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer as _};

use super::{
    BoundedWriter, ByteBudget, CANONICAL_SNAPSHOT_MAX_BYTES, CanonicalAssetBodyRef,
    CanonicalBaseEdge, CanonicalCustodyTransition, CanonicalDocument, CanonicalEntity,
    CanonicalEntityDocument, CanonicalHeadMove, CanonicalPinCarrier, CanonicalRoomFact,
    CanonicalRoomTurn, CanonicalRowBirth, CanonicalSnapshot, CanonicalTombstone,
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
    bytes: Option<usize>,
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
            ("entity_blobs", &ByteRows(entity_blobs, false)),
            ("retained_claim_worlds", &Rows(retained_claim_worlds, false)),
            ("base_edges", &ByteRows(base_edges, false)),
            ("tombstones", &ByteRows(tombstones, false)),
            ("doc_snapshots", &TextRows(doc_snapshots)),
            ("entity_documents", &TextRows(entity_documents)),
            ("document_heads", &Rows(document_heads, false)),
            ("head_move_receipts", &ByteRows(head_move_receipts, false)),
            ("note_forks", &Rows(note_forks, false)),
            ("note_proposals", &Rows(note_proposals, false)),
            ("container_manifests", &Rows(container_manifests, false)),
            ("schema_manifest", &Scalar(schema_manifest)),
            ("suppressed_tasks", &Rows(suppressed_tasks, true)),
            ("custody_transitions", &ByteRows(custody_transitions, true)),
            ("room_turns", &ByteRows(room_turns, true)),
            ("room_facts", &ByteRows(room_facts, true)),
            ("document_pins", &ByteRows(document_pins, true)),
            ("peer_origins", &Rows(peer_origins, true)),
            ("row_births", &ByteRows(row_births, true)),
            ("withdrawn_cutoffs", &Rows(withdrawn_cutoffs, true)),
            ("asset_body_refs", &ByteRows(asset_body_refs, true)),
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

/// Scalar and ordinary row serializers stay native; selected byte rows also yield within bytes.
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

trait TextRow {
    fn text(&self) -> &str;
    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()>;
    fn write_suffix(&self, out: &mut BoundedWriter) -> Result<()>;
}

impl TextRow for CanonicalDocument {
    fn text(&self) -> &str {
        &self.text
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalDocument {
            entity_id,
            head,
            text: _,
            title: _,
            birth_actor: _,
            birth_at: _,
            authorship: _,
        } = self;
        write_struct_header(out, "CanonicalDocument", 7)?;
        write_named(out, "entity_id")?;
        write_named(out, entity_id)?;
        write_named(out, "head")?;
        write_named(out, head)?;
        write_named(out, "text")
    }

    fn write_suffix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalDocument {
            entity_id: _,
            head: _,
            text: _,
            title,
            birth_actor,
            birth_at,
            authorship,
        } = self;
        write_named(out, "title")?;
        write_named(out, title)?;
        write_named(out, "birth_actor")?;
        write_named(out, birth_actor)?;
        write_named(out, "birth_at")?;
        write_named(out, birth_at)?;
        write_named(out, "authorship")?;
        write_named(out, authorship)
    }
}

impl TextRow for CanonicalEntityDocument {
    fn text(&self) -> &str {
        &self.text
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalEntityDocument {
            entity_id,
            document_id,
            field,
            text: _,
            native_skill_state: _,
            metadata: _,
            summary_meta,
            record_fields: _,
            birth_actor: _,
            birth_at: _,
            history,
        } = self;
        let fields = 9 + usize::from(!summary_meta.is_empty()) + usize::from(history.is_some());
        write_struct_header(out, "CanonicalEntityDocument", fields)?;
        write_named(out, "entity_id")?;
        write_named(out, entity_id)?;
        write_named(out, "document_id")?;
        write_named(out, document_id)?;
        write_named(out, "field")?;
        write_named(out, field)?;
        write_named(out, "text")
    }

    fn write_suffix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalEntityDocument {
            entity_id: _,
            document_id: _,
            field: _,
            text: _,
            native_skill_state,
            metadata,
            summary_meta,
            record_fields,
            birth_actor,
            birth_at,
            history,
        } = self;
        write_named(out, "native_skill_state")?;
        write_named(out, native_skill_state)?;
        write_named(out, "metadata")?;
        write_named(out, metadata)?;
        if !summary_meta.is_empty() {
            write_named(out, "summary_meta")?;
            write_named(out, summary_meta)?;
        }
        write_named(out, "record_fields")?;
        write_named(out, record_fields)?;
        write_named(out, "birth_actor")?;
        write_named(out, birth_actor)?;
        write_named(out, "birth_at")?;
        write_named(out, birth_at)?;
        if history.is_some() {
            write_named(out, "history")?;
            write_named(out, history)?;
        }
        Ok(())
    }
}

struct TextRows<'a, T>(&'a [T]);

impl<T: TextRow> Field for TextRows<'_, T> {
    fn present(&self) -> bool {
        true
    }

    fn write(&self, out: &mut BoundedWriter, row: &mut Option<RowCursor>) -> Result<bool> {
        let Some(cursor) = row else {
            write_array_header(out, self.0.len())?;
            *row = Some(RowCursor::default());
            return Ok(self.0.is_empty());
        };
        let value = &self.0[cursor.next];
        let text = value.text();
        if let Some(next) = cursor.bytes.as_mut() {
            if *next < text.len() {
                let end = next.saturating_add(blake3::CHUNK_LEN).min(text.len());
                // The prefix reserved this complete string's output capacity.
                out.bytes.extend_from_slice(&text.as_bytes()[*next..end]);
                *next = end;
                return Ok(false);
            }
            value.write_suffix(out)?;
            cursor.next += 1;
            cursor.bytes = None;
            return Ok(cursor.next == self.0.len());
        }
        value.write_prefix(out)?;
        rmp::encode::write_str_len(&mut *out, text.len() as u32).map_err(|_| out.refusal())?;
        if !text.is_empty() {
            out.reserve_write(text.len()).map_err(|_| out.refusal())?;
        }
        cursor.bytes = Some(0);
        Ok(false)
    }
}

trait ByteRow {
    fn bytes(&self) -> &[u8];
    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()>;
}

impl ByteRow for CanonicalEntity {
    fn bytes(&self) -> &[u8] {
        &self.blob
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalEntity { id, blob: _ } = self;
        write_struct_header(out, "CanonicalEntity", 2)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "blob")
    }
}

impl ByteRow for CanonicalBaseEdge {
    fn bytes(&self) -> &[u8] {
        &self.value
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalBaseEdge {
            source,
            kind,
            target,
            value: _,
        } = self;
        write_struct_header(out, "CanonicalBaseEdge", 4)?;
        write_named(out, "source")?;
        write_named(out, source)?;
        write_named(out, "kind")?;
        write_named(out, kind)?;
        write_named(out, "target")?;
        write_named(out, target)?;
        write_named(out, "value")
    }
}

impl ByteRow for CanonicalTombstone {
    fn bytes(&self) -> &[u8] {
        &self.value
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalTombstone {
            id,
            deleted_at,
            value: _,
        } = self;
        write_struct_header(out, "CanonicalTombstone", 3)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "deleted_at")?;
        write_named(out, deleted_at)?;
        write_named(out, "value")
    }
}

impl ByteRow for CanonicalCustodyTransition {
    fn bytes(&self) -> &[u8] {
        &self.carrier
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalCustodyTransition {
            id,
            piece,
            carrier: _,
        } = self;
        write_struct_header(out, "CanonicalCustodyTransition", 3)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "piece")?;
        write_named(out, piece)?;
        write_named(out, "carrier")
    }
}

impl ByteRow for CanonicalHeadMove {
    fn bytes(&self) -> &[u8] {
        &self.receipt
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalHeadMove {
            id,
            entity_id,
            receipt: _,
        } = self;
        write_struct_header(out, "CanonicalHeadMove", 3)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "entity_id")?;
        write_named(out, entity_id)?;
        write_named(out, "receipt")
    }
}

impl ByteRow for CanonicalRoomTurn {
    fn bytes(&self) -> &[u8] {
        &self.row
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalRoomTurn { key, row: _ } = self;
        write_struct_header(out, "CanonicalRoomTurn", 2)?;
        write_named(out, "key")?;
        write_named(out, key)?;
        write_named(out, "row")
    }
}

impl ByteRow for CanonicalRoomFact {
    fn bytes(&self) -> &[u8] {
        &self.row
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalRoomFact { key, row: _ } = self;
        write_struct_header(out, "CanonicalRoomFact", 2)?;
        write_named(out, "key")?;
        write_named(out, key)?;
        write_named(out, "row")
    }
}

impl ByteRow for CanonicalPinCarrier {
    fn bytes(&self) -> &[u8] {
        &self.row
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalPinCarrier { key, row: _ } = self;
        write_struct_header(out, "CanonicalPinCarrier", 2)?;
        write_named(out, "key")?;
        write_named(out, key)?;
        write_named(out, "row")
    }
}

impl ByteRow for CanonicalRowBirth {
    fn bytes(&self) -> &[u8] {
        &self.value
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalRowBirth { id, value: _ } = self;
        write_struct_header(out, "CanonicalRowBirth", 2)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "value")
    }
}

impl ByteRow for CanonicalAssetBodyRef {
    fn bytes(&self) -> &[u8] {
        &self.value
    }

    fn write_prefix(&self, out: &mut BoundedWriter) -> Result<()> {
        let CanonicalAssetBodyRef { id, value: _ } = self;
        write_struct_header(out, "CanonicalAssetBodyRef", 2)?;
        write_named(out, "id")?;
        write_named(out, id)?;
        write_named(out, "value")
    }
}

struct ByteRows<'a, T>(&'a [T], bool);

impl<T: ByteRow> Field for ByteRows<'_, T> {
    fn present(&self) -> bool {
        !self.1 || !self.0.is_empty()
    }

    fn write(&self, out: &mut BoundedWriter, row: &mut Option<RowCursor>) -> Result<bool> {
        let Some(cursor) = row else {
            write_array_header(out, self.0.len())?;
            *row = Some(RowCursor::default());
            return Ok(self.0.is_empty());
        };
        let value = &self.0[cursor.next];
        let bytes = value.bytes();
        if let Some(next) = cursor.bytes.as_mut() {
            if !write_byte_page(out, bytes, next)? {
                return Ok(false);
            }
        } else {
            value.write_prefix(out)?;
            write_array_header(out, bytes.len())?;
            cursor.bytes = Some(0);
            if !bytes.is_empty() {
                return Ok(false);
            }
        }
        cursor.next += 1;
        cursor.bytes = None;
        Ok(cursor.next == self.0.len())
    }
}

fn write_struct_header(out: &mut BoundedWriter, name: &'static str, len: usize) -> Result<()> {
    let result = {
        let mut serializer = rmp_serde::Serializer::new(&mut *out).with_struct_map();
        serializer
            .serialize_struct(name, len)
            .and_then(SerializeStruct::end)
    };
    result.map_err(|_| out.refusal())
}

fn write_byte_page(out: &mut BoundedWriter, bytes: &[u8], next: &mut usize) -> Result<bool> {
    let end = next.saturating_add(blake3::CHUNK_LEN).min(bytes.len());
    // Vec<u8> uses the native normal-mode array of compact integers, not bin.
    for byte in &bytes[*next..end] {
        write_named(out, byte)?;
    }
    *next = end;
    Ok(end == bytes.len())
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
