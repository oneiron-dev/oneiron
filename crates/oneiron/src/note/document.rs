//! NOTE entity-document operations, stable cursors and citation provenance.

use crate::error::{Error, RecordError, Result};
use crate::memory::CommitReceipt;
use crate::{EntityId, WriteActor};
use loro::cursor::{Cursor, Side};
use loro::{CommitOptions, ExportMode, Frontiers, LoroDoc};
use serde::{Deserialize, Serialize};

const BODY: &str = "body";
const META: &str = "note";
pub(super) const MAX_NOTE_BYTES: usize = 1024 * 1024;

/// Positions use Unicode scalar indices in the named base frontier. Batches
/// are ordered, so each operation sees the preceding operations in its batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteEdit {
    pub start: usize,
    pub delete: usize,
    pub insert: String,
}

/// A citation is data, not a rendered view. Its cursors are bound to one
/// document and frontier. The original quote is retained even after drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotePin {
    #[serde(with = "super::id_codec")]
    pub claim: EntityId,
    #[serde(with = "super::id_codec")]
    pub document: EntityId,
    pub frontier: Vec<u8>,
    pub start_cursor: Vec<u8>,
    pub end_cursor: Vec<u8>,
    pub quote_hash: [u8; 32],
    pub quote_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteSpanResolution {
    Mapped {
        start: usize,
        end: usize,
        claim: EntityId,
        quote: String,
    },
    Drifted {
        claim: EntityId,
        quote: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteDocumentView {
    pub document: EntityId,
    pub frontier: Vec<u8>,
    pub markdown: String,
    pub pins: Vec<NotePin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteEditOutcome {
    Applied(NoteDocumentView),
    Proposed(CommitReceipt),
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}

pub(super) fn frontier(bytes: &[u8]) -> Result<Frontiers> {
    if bytes.len() > 4096 {
        return Err(invalid("NOTE frontier exceeds bound"));
    }
    Frontiers::decode(bytes).map_err(|_| invalid("invalid NOTE frontier"))
}

impl NotePin {
    pub fn validate(&self) -> Result<()> {
        if self.quote_text.len() > MAX_NOTE_BYTES
            || self.start_cursor.len() > 4096
            || self.end_cursor.len() > 4096
        {
            return Err(invalid("NOTE citation exceeds bound"));
        }
        frontier(&self.frontier)?;
        for bytes in [&self.start_cursor, &self.end_cursor] {
            let cursor = Cursor::decode(bytes).map_err(|_| invalid("invalid NOTE cursor"))?;
            if cursor.container != loro::ContainerID::new_root(BODY, loro::ContainerType::Text) {
                return Err(invalid("NOTE cursor is not in the body"));
            }
        }
        if self.quote_hash != *blake3::hash(self.quote_text.as_bytes()).as_bytes() {
            return Err(invalid("NOTE quote hash mismatch"));
        }
        Ok(())
    }
}

pub(super) struct NoteDocument {
    pub(super) doc: LoroDoc,
    pub(super) id: EntityId,
}

impl NoteDocument {
    pub(super) fn birth(id: EntityId, body: &str, actor: &WriteActor) -> Result<Self> {
        if body.len() > MAX_NOTE_BYTES {
            return Err(invalid("NOTE body exceeds bound"));
        }
        let doc = LoroDoc::new();
        // The birth record is immutable, so lazy creation on different peers
        // must give its initial operations the same identity.
        let seed = blake3::hash(id.as_bytes());
        let mut peer = [0; 8];
        peer.copy_from_slice(&seed.as_bytes()[..8]);
        doc.set_peer_id(u64::from_le_bytes(peer))
            .map_err(|_| invalid("NOTE birth peer"))?;
        doc.get_map(META)
            .insert("id", id.to_hex())
            .map_err(|_| invalid("NOTE identity insert"))?;
        doc.get_text(BODY)
            .insert(0, body)
            .map_err(|_| invalid("NOTE birth insert"))?;
        stamp(&doc, actor);
        Ok(Self { doc, id })
    }

    pub(super) fn load(id: EntityId, bytes: &[u8]) -> Result<Self> {
        let doc = LoroDoc::new();
        doc.import(bytes)
            .map_err(|_| invalid("invalid NOTE document snapshot"))?;
        let found = doc.get_map(META).get("id").and_then(|v| match v {
            loro::ValueOrContainer::Value(loro::LoroValue::String(value)) => {
                Some(value.to_string())
            }
            _ => None,
        });
        if found.as_deref() != Some(&id.to_hex()) {
            return Err(invalid("NOTE document identity mismatch"));
        }
        Ok(Self { doc, id })
    }

    pub(super) fn snapshot(&self) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::Snapshot)
            .map_err(|_| invalid("NOTE snapshot export"))
    }

    pub(super) fn view(&self) -> Result<NoteDocumentView> {
        Ok(NoteDocumentView {
            document: self.id,
            frontier: self.doc.oplog_frontiers().encode(),
            markdown: self.doc.get_text(BODY).to_string(),
            pins: self.pins()?,
        })
    }

    pub(super) fn pins(&self) -> Result<Vec<NotePin>> {
        let mut pins = Vec::new();
        for value in self.doc.get_map("pins").values() {
            let loro::ValueOrContainer::Value(loro::LoroValue::String(value)) = value else {
                return Err(invalid("invalid NOTE pin value"));
            };
            let pin: NotePin =
                serde_json::from_str(&value).map_err(|_| invalid("invalid NOTE pin"))?;
            pin.validate()?;
            pins.push(pin);
        }
        pins.sort_by_key(|pin| (pin.document, pin.claim, pin.quote_hash));
        Ok(pins)
    }

    pub(super) fn add_pin(&self, pin: &NotePin, actor: &WriteActor) -> Result<()> {
        pin.validate()?;
        if self.pins()?.len() >= 256 {
            return Err(invalid("NOTE citation cap reached"));
        }
        let value = serde_json::to_string(pin).map_err(|_| invalid("NOTE pin encode"))?;
        let key = blake3::hash(value.as_bytes()).to_hex().to_string();
        self.doc
            .get_map("pins")
            .insert(&key, value)
            .map_err(|_| invalid("NOTE pin insert"))?;
        stamp(&self.doc, actor);
        Ok(())
    }

    pub(super) fn pin(&self, claim: EntityId, start: usize, end: usize) -> Result<NotePin> {
        let text = self.doc.get_text(BODY);
        if end <= start || end > text.len_unicode() {
            return Err(invalid("invalid NOTE citation range"));
        }
        let quote_text = text
            .slice(start, end)
            .map_err(|_| invalid("NOTE quote slice"))?;
        let start_cursor = text
            .get_cursor(start, Side::Right)
            .ok_or_else(|| invalid("NOTE start cursor"))?
            .encode();
        let end_cursor = text
            .get_cursor(end, Side::Left)
            .ok_or_else(|| invalid("NOTE end cursor"))?
            .encode();
        Ok(NotePin {
            claim,
            document: self.id,
            frontier: self.doc.oplog_frontiers().encode(),
            start_cursor,
            end_cursor,
            quote_hash: *blake3::hash(quote_text.as_bytes()).as_bytes(),
            quote_text,
        })
    }

    pub(super) fn resolve(&self, pin: &NotePin) -> Result<NoteSpanResolution> {
        pin.validate()?;
        if pin.document != self.id {
            return Err(invalid("NOTE cursor names another document"));
        }
        let start = Cursor::decode(&pin.start_cursor).map_err(|_| invalid("NOTE start cursor"))?;
        let end = Cursor::decode(&pin.end_cursor).map_err(|_| invalid("NOTE end cursor"))?;
        let positions = self
            .doc
            .get_cursor_pos(&start)
            .ok()
            .zip(self.doc.get_cursor_pos(&end).ok());
        if let Some((start, end)) = positions {
            let (start, end) = (start.current.pos, end.current.pos);
            if start <= end
                && let Ok(quote) = self.doc.get_text(BODY).slice(start, end)
                && blake3::hash(quote.as_bytes()).as_bytes() == &pin.quote_hash
            {
                return Ok(NoteSpanResolution::Mapped {
                    start,
                    end,
                    claim: pin.claim,
                    quote,
                });
            }
        }
        Ok(NoteSpanResolution::Drifted {
            claim: pin.claim,
            quote: pin.quote_text.clone(),
        })
    }

    /// Edit a fork of the client's actual base; merge its stamped operations
    /// into the live document. Concurrent batches therefore never overwrite a
    /// whole markdown body or use offsets against the wrong frontier.
    pub(super) fn edit(
        &self,
        base: &[u8],
        edits: &[NoteEdit],
        actor: &WriteActor,
        cited_by: &[NotePin],
    ) -> Result<bool> {
        if edits.len() > 256 {
            return Err(invalid("NOTE operation cap exceeded"));
        }
        let branch = self
            .doc
            .fork_at(&frontier(base)?)
            .map_err(|_| invalid("NOTE base frontier unavailable"))?;
        let base_doc = Self {
            doc: branch,
            id: self.id,
        };
        let pins = self.pins()?;
        let text = base_doc.doc.get_text(BODY);
        for edit in edits {
            let end = edit
                .start
                .checked_add(edit.delete)
                .ok_or_else(|| invalid("NOTE range overflow"))?;
            if end > text.len_unicode() || edit.insert.len() > MAX_NOTE_BYTES {
                return Err(invalid("NOTE operation out of bounds"));
            }
            for pin in pins.iter().chain(cited_by) {
                if pin.document != self.id {
                    continue;
                }
                match base_doc.resolve(pin)? {
                    NoteSpanResolution::Mapped {
                        start, end: stop, ..
                    } => {
                        if (edit.start < stop && end > start)
                            || (edit.delete == 0 && edit.start > start && edit.start < stop)
                        {
                            return Ok(false);
                        }
                    }
                    NoteSpanResolution::Drifted { .. } => return Ok(false),
                }
            }
            text.delete(edit.start, edit.delete)
                .map_err(|_| invalid("NOTE delete operation"))?;
            text.insert(edit.start, &edit.insert)
                .map_err(|_| invalid("NOTE insert operation"))?;
            if text.len_utf8() > MAX_NOTE_BYTES {
                return Err(invalid("NOTE body exceeds bound"));
            }
            stamp(&base_doc.doc, actor);
        }
        stamp(&base_doc.doc, actor);
        let updates = base_doc
            .doc
            .export(ExportMode::updates(&self.doc.oplog_vv()))
            .map_err(|_| invalid("NOTE operation export"))?;
        self.doc
            .import(&updates)
            .map_err(|_| invalid("NOTE operation merge"))?;
        Ok(true)
    }
}

fn stamp(doc: &LoroDoc, actor: &WriteActor) {
    doc.commit_with(CommitOptions::new().commit_msg(&format!(
        "oneiron.note/v1 actor={}",
        actor.entity_ref().to_hex()
    )));
}
