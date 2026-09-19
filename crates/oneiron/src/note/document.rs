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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteDocumentView {
    #[serde(with = "super::id_codec")]
    pub document: EntityId,
    pub frontier: Vec<u8>,
    pub markdown: String,
    pub pins: Vec<NotePin>,
    pub authorship: Vec<super::NoteAuthorship>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        for (bytes, side) in [
            (&self.start_cursor, Side::Left),
            (&self.end_cursor, Side::Right),
        ] {
            let cursor = Cursor::decode(bytes).map_err(|_| invalid("invalid NOTE cursor"))?;
            if cursor.container != loro::ContainerID::new_root(BODY, loro::ContainerType::Text) {
                return Err(invalid("NOTE cursor is not in the body"));
            }
            // Both endpoints name quoted characters, never a moving document
            // boundary. The sides describe the edges of those characters.
            if cursor.id.is_none() || cursor.side != side {
                return Err(invalid("NOTE cursor is not a quoted character boundary"));
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
        let born = Self { doc, id };
        super::operations::record_authorship(
            &born,
            &super::NoteAuthorship {
                operation: id,
                actor: actor.entity_ref(),
                // Birth ABI carries an author, not an authenticated actor class.
                // Keep the seed identical on every replica; later admissions carry
                // the credential's verified class in their own records.
                actor_class: "ledger".to_owned(),
                grant: None,
                command_hash: *blake3::hash(body.as_bytes()).as_bytes(),
            },
        )?;
        Ok(born)
    }

    pub(super) fn load(id: EntityId, bytes: &[u8]) -> Result<Self> {
        let doc = LoroDoc::new();
        crate::sync::documents::storage::import_complete(&doc, bytes)
            .map_err(|_| invalid("invalid NOTE document snapshot"))?;
        Self::from_loro(id, doc)
    }

    pub(super) fn from_loro(id: EntityId, doc: LoroDoc) -> Result<Self> {
        let loro::LoroValue::Map(root) = doc.get_deep_value() else {
            return Err(invalid("NOTE root map"));
        };
        if root
            .keys()
            .any(|name| !matches!(name.as_str(), "note" | "body" | "pins" | "authorship"))
        {
            return Err(invalid("unknown NOTE container"));
        }
        if doc.get_text(BODY).len_utf8() > MAX_NOTE_BYTES
            || doc.get_map("pins").len() > 256
            || doc.get_map("authorship").len() > 4096
        {
            return Err(invalid("NOTE document exceeds bounds"));
        }
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

    pub(super) fn fork_at(&self, base: &[u8]) -> Result<Self> {
        let base = frontier(base)?;
        // Loro's historical SnapshotAt path does not support shallow docs.
        // Its live fork preserves their state, operation IDs and shallow floor.
        // Only an exact current frontier can use it: old offsets must never be
        // silently applied to the current body after their history was erased.
        let doc = if base == self.doc.oplog_frontiers() {
            self.doc.fork()
        } else {
            self.doc
                .fork_at(&base)
                .map_err(|_| invalid("NOTE base frontier unavailable"))?
        };
        Ok(Self { doc, id: self.id })
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
            authorship: super::operations::authorship(&self.doc)?,
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
            .get_cursor(start, Side::Left)
            .ok_or_else(|| invalid("NOTE start cursor"))?
            .encode();
        // get_cursor(len, _) is Loro's moving end-of-document sentinel.
        // Anchor to the last quoted character instead, including for an
        // interior span: insertions just after the quote must stay outside it.
        let end_cursor = text
            .get_cursor(end - 1, Side::Right)
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
        // Resolve only live character IDs. get_cursor_pos falls back to
        // historical replay for deleted anchors, which cannot run safely on
        // StateOnly documents whose dependencies have been erased (Loro 1.13).
        // Its remapped neighbor would be drift anyway, even if the text matched.
        // `false` selects Unicode scalar indices regardless of Loro's features.
        // Keep the public with_state closure non-reentrant and read-only.
        let positions = self.doc.with_state(|state| {
            state
                .get_relative_position(&start, false)
                .zip(state.get_relative_position(&end, false))
        });
        if let Some((start, end)) = positions
            && let Some(end) = end.checked_add(1)
            && start < end
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
        let base_doc = self.fork_at(base)?;
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
        // The base guard is not enough when other concurrent batches already
        // landed. Recheck the merged state before the caller persists it.
        for pin in pins
            .iter()
            .chain(cited_by)
            .filter(|pin| pin.document == self.id)
        {
            if !matches!(self.resolve(pin)?, NoteSpanResolution::Mapped { .. }) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn stamp(doc: &LoroDoc, actor: &WriteActor) {
    doc.commit_with(CommitOptions::new().commit_msg(&format!(
        "oneiron.note/v1 actor={}",
        actor.entity_ref().to_hex()
    )));
}
