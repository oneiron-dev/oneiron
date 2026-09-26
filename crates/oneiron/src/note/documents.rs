//! Entity-local text CRDT with stamped birth, stable cursors and isolated rewrites.

use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, HexId, Raw, RawValue, SideTable};
use crate::{EntityId, Vault};
use loro::cursor::{Cursor, Side};
use loro::{ExportMode, Frontiers, LoroDoc, UpdateOptions};
use serde::{Deserialize, Serialize};

use super::side_keys::HexPair;

const TEXT: &str = "body";

/// A NOTE's current head document id and head-move sequence number
/// (`note_head:v1:`): 16 raw id bytes then an 8-byte big-endian sequence,
/// unchanged from the pre-typed layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NoteHeadRow {
    head: EntityId,
    seq: u64,
}

impl RawValue for NoteHeadRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok([self.head.as_bytes().as_slice(), &self.seq.to_be_bytes()].concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let (head, seq) = bytes
            .split_at_checked(crate::entity_id::ENTITY_ID_LEN)
            .ok_or_else(|| invalid("NOTE head row"))?;
        let head = EntityId::from_bytes(head.try_into().map_err(|_| invalid("NOTE head row"))?)
            .map_err(|_| invalid("NOTE head row"))?;
        let seq = u64::from_be_bytes(seq.try_into().map_err(|_| invalid("NOTE head row"))?);
        Ok(Self { head, seq })
    }
}

pub(super) const NOTE_HEAD: SideTable<EntityId, NoteHeadRow, Raw> =
    SideTable::new(&side_table::NOTE_HEAD);

/// Marker: one row per head document a NOTE's text plane ever held. Key: the
/// note id then the head id, raw-concatenated with no separator.
pub(super) const NOTE_HEAD_DOC: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::NOTE_HEAD_DOC);

/// Loro snapshot bytes of a proposal (non-live) NOTE document head.
pub(super) const NOTE_PROPOSAL_DOC: SideTable<HexPair, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PROPOSAL_DOC);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteAnchor {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub(super) note: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub(super) head: EntityId,
    pub(super) cursor: Vec<u8>,
}

/// The version against which a writer prepared whole-text output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteVersion {
    #[serde(with = "crate::entity_id::serde_hex")]
    note: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    head: EntityId,
    frontier: Vec<u8>,
}

pub enum NoteEdit {
    ReplaceSpan {
        start: NoteAnchor,
        end: NoteAnchor,
        text: String,
    },
    InsertAfter {
        anchor: NoteAnchor,
        text: String,
    },
    AppendToSection {
        end: NoteAnchor,
        text: String,
    },
    WholeText {
        text: String,
        timeout_ms: u32,
        base: Option<NoteVersion>,
    },
    Rewrite {
        text: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteEditOutcome {
    Edited {
        head: EntityId,
    },
    RewriteFork {
        fork: EntityId,
    },
    ProposedFork {
        fork: EntityId,
    },
    ReviewRequired {
        receipt: crate::memory::CommitReceipt,
    },
}

pub struct NoteDocument {
    pub(super) note: EntityId,
    pub(super) head: EntityId,
    pub(super) doc: LoroDoc,
}
impl NoteDocument {
    pub fn version(&self) -> NoteVersion {
        NoteVersion {
            note: self.note,
            head: self.head,
            frontier: self.doc.state_frontiers().encode(),
        }
    }
    pub fn head(&self) -> EntityId {
        self.head
    }
    pub fn text(&self) -> String {
        self.doc.get_text(TEXT).to_string()
    }
    /// Offsets are Unicode scalar indices. The returned cursor survives other edits.
    pub fn anchor(&self, offset: usize) -> Result<NoteAnchor> {
        let cursor = self
            .doc
            .get_text(TEXT)
            .get_cursor(offset, Side::Right)
            .ok_or(invalid("anchor outside text"))?;
        Ok(NoteAnchor {
            note: self.note,
            head: self.head,
            cursor: cursor.encode(),
        })
    }
    pub(super) fn position(&self, anchor: &NoteAnchor) -> Result<usize> {
        if anchor.note != self.note || anchor.head != self.head {
            return Err(invalid("anchor belongs to another document head"));
        }
        if anchor.cursor.len() > 4096 {
            return Err(invalid("anchor exceeds bound"));
        }
        let cursor = Cursor::decode(&anchor.cursor).map_err(|_| invalid("invalid cursor"))?;
        if cursor.container != loro::ContainerID::new_root(TEXT, loro::ContainerType::Text) {
            return Err(invalid("anchor is not in NOTE body"));
        }
        self.doc
            .get_cursor_pos(&cursor)
            .map(|p| p.current.pos)
            .map_err(|_| invalid("unresolvable cursor"))
    }
    /// Translate intent against its actual read frontier. Only the canonical
    /// operation door may admit these edits; proposal documents are disposable.
    pub(super) fn semantic_edit(
        &self,
        edit: &NoteEdit,
    ) -> Result<Option<(Vec<u8>, Vec<super::NoteEdit>)>> {
        let mut base = self.doc.oplog_frontiers().encode();
        let change = match edit {
            NoteEdit::ReplaceSpan { start, end, text } => {
                let start = self.position(start)?;
                let end = self.position(end)?;
                if end < start {
                    return Err(invalid("reversed span"));
                }
                super::NoteEdit {
                    start,
                    delete: end - start,
                    insert: text.clone(),
                }
            }
            NoteEdit::InsertAfter { anchor, text }
            | NoteEdit::AppendToSection { end: anchor, text } => super::NoteEdit {
                start: self.position(anchor)?,
                delete: 0,
                insert: text.clone(),
            },
            NoteEdit::WholeText {
                text,
                timeout_ms,
                base: version,
            } => {
                if let Some(version) = version {
                    if version.note != self.note || version.head != self.head {
                        return Err(invalid("whole-text base belongs to another head"));
                    }
                    base = version.frontier.clone();
                }
                let canonical =
                    super::document::NoteDocument::from_loro(self.note, self.doc.fork())?;
                let candidate = canonical.fork_at(&base)?;
                let original = candidate.doc.get_text(TEXT).to_string();
                if candidate
                    .doc
                    .get_text(TEXT)
                    .update(
                        text,
                        UpdateOptions {
                            timeout_ms: Some(f64::from(*timeout_ms)),
                            use_refined_diff: true,
                        },
                    )
                    .is_err()
                {
                    return Ok(None);
                }
                text_change(&original, text)
            }
            NoteEdit::Rewrite { .. } => return Ok(None),
        };
        Ok(Some((base, vec![change])))
    }
    pub(super) fn apply(
        &self,
        clock: &crate::ports::StoreClock,
        edit: &NoteEdit,
        actor: EntityId,
        at: u64,
    ) -> Result<Option<Self>> {
        let text = self.doc.get_text(TEXT);
        match edit {
            NoteEdit::ReplaceSpan {
                start,
                end,
                text: replacement,
            } => {
                let start = self.position(start)?;
                let end = self.position(end)?;
                if end < start {
                    return Err(invalid("reversed span"));
                }
                text.delete(start, end - start)
                    .map_err(|_| invalid("replace span"))?;
                text.insert(start, replacement)
                    .map_err(|_| invalid("replace text"))?;
            }
            NoteEdit::InsertAfter {
                anchor,
                text: insertion,
            }
            | NoteEdit::AppendToSection {
                end: anchor,
                text: insertion,
            } => {
                text.insert(self.position(anchor)?, insertion)
                    .map_err(|_| invalid("insert text"))?;
            }
            NoteEdit::WholeText {
                text: replacement,
                timeout_ms,
                base,
            } => {
                // Diff on a disposable copy. A timed-out update cannot leak partial ops.
                let frontier = match base {
                    Some(base) => {
                        if base.note != self.note || base.head != self.head {
                            return Err(invalid("whole-text base belongs to another head"));
                        }
                        Frontiers::decode(&base.frontier)
                            .map_err(|_| invalid("invalid base frontier"))?
                    }
                    None => self.doc.state_frontiers(),
                };
                let candidate = self
                    .doc
                    .fork_at(&frontier)
                    .map_err(|_| invalid("unknown base frontier"))?;
                if candidate
                    .get_text(TEXT)
                    .update(
                        replacement,
                        UpdateOptions {
                            timeout_ms: Some(f64::from(*timeout_ms)),
                            use_refined_diff: true,
                        },
                    )
                    .is_err()
                {
                    return self
                        .rewrite(clock.entity_id()?, replacement, actor, at)
                        .map(Some);
                }
                stamp(&candidate, actor, at, "edit");
                self.doc
                    .import(&snapshot(&candidate)?)
                    .map_err(|_| invalid("diff import"))?;
                return Ok(None);
            }
            NoteEdit::Rewrite { text } => {
                return self.rewrite(clock.entity_id()?, text, actor, at).map(Some);
            }
        }
        stamp(&self.doc, actor, at, "edit");
        Ok(None)
    }
    fn rewrite(&self, head: EntityId, text: &str, actor: EntityId, at: u64) -> Result<Self> {
        let fork = self
            .doc
            .fork_at(&self.doc.state_frontiers())
            .map_err(|_| invalid("fork frontier"))?;
        let target = fork.get_text(TEXT);
        target
            .delete(0, target.len_unicode())
            .map_err(|_| invalid("rewrite delete"))?;
        target
            .insert(0, text)
            .map_err(|_| invalid("rewrite insert"))?;
        stamp(&fork, actor, at, "rewrite");
        Ok(Self {
            note: self.note,
            head,
            doc: fork,
        })
    }
}

pub(crate) fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}
pub(super) fn stamp(doc: &LoroDoc, actor: EntityId, at: u64, action: &str) {
    doc.set_next_commit_message(&format!("note:v1:{action}:actor={}", actor.to_hex()));
    doc.set_next_commit_timestamp(at.min(i64::MAX as u64) as i64);
    doc.commit();
}
/// The NOTE's current head and head sequence. A NOTE that never switched is
/// its own head at sequence 0.
pub(crate) fn head_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<(EntityId, u64)> {
    Ok(match NOTE_HEAD.get(store, txn, &note)? {
        Some(row) => (row.head, row.seq),
        None => (note, 0),
    })
}
pub(crate) fn set_head(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    head: EntityId,
    seq: u64,
) -> Result<()> {
    NOTE_HEAD.put(store, txn, &note, &NoteHeadRow { head, seq })?;
    NOTE_HEAD_DOC.put(store, txn, &(note, head), &())?;
    Ok(())
}
#[cfg(any(feature = "sync", test))]
pub(crate) fn doc_key(note: EntityId, head: EntityId) -> String {
    format!("note_proposal_doc:v1:{}:{}", note.to_hex(), head.to_hex())
}
pub(crate) fn snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|_| invalid("document snapshot"))
}
/// Proposal-only storage. No caller can advance canonical authority with bytes.
pub(crate) fn store_doc(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    if doc.head == doc.note {
        return Err(invalid("live NOTE requires canonical operation admission"));
    }
    super::ensure_citations_ready(&vault.store, txn, doc.note)?;
    super::verbs::note_core(vault, txn, doc.note)?;
    super::document::NoteDocument::from_loro(doc.note, doc.doc.fork())?;
    NOTE_PROPOSAL_DOC.put(
        &vault.store,
        txn,
        &HexPair(HexId(doc.note), HexId(doc.head)),
        &snapshot(&proposal_value(doc.note, &doc.text())?)?,
    )
}

pub(crate) fn load_doc(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<Option<NoteDocument>> {
    super::verbs::note_core(vault, txn, note)?;
    super::ensure_citations_ready(&vault.store, txn, note)?;
    let hex = head_in(&vault.store, txn, note)?.0.to_hex();
    if vault
        .store
        .sync_state
        .get(txn, &format!("d:e:{hex}"))?
        .is_none()
        && vault
            .store
            .sync_state
            .prefix_iter(txn, &format!("u:e:{hex}:"))?
            .next()
            .transpose()?
            .is_none()
    {
        return Ok(None);
    }
    live_doc(vault, txn, note).map(Some)
}

pub(crate) fn live_doc(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<NoteDocument> {
    let canonical = super::document_store::load(vault, txn, note)?;
    Ok(NoteDocument {
        note,
        head: head_in(&vault.store, txn, note)?.0,
        doc: canonical.doc,
    })
}

pub(crate) fn load_head(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    head: EntityId,
) -> Result<NoteDocument> {
    if head == head_in(&vault.store, txn, note)?.0 {
        return live_doc(vault, txn, note);
    }
    super::verbs::note_core(vault, txn, note)?;
    super::ensure_citations_ready(&vault.store, txn, note)?;
    let raw = NOTE_PROPOSAL_DOC
        .get(&vault.store, txn, &HexPair(HexId(note), HexId(head)))?
        .ok_or(invalid("missing proposal document"))?;
    let canonical = super::document::NoteDocument::load(note, &raw)?;
    super::citation_erase::validate_pins(vault, txn, &canonical.pins()?)?;
    Ok(NoteDocument {
        note,
        head,
        doc: canonical.doc,
    })
}

/// Conservative Unicode diff. A wide changed span is reviewed if it crosses
/// a citation; never use guessed CRDT IDs or drop intervening citation guards.
pub(super) fn text_change(before: &str, after: &str) -> super::NoteEdit {
    let before: Vec<_> = before.chars().collect();
    let after: Vec<_> = after.chars().collect();
    let start = before
        .iter()
        .zip(&after)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = before[start..]
        .iter()
        .rev()
        .zip(after[start..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    super::NoteEdit {
        start,
        delete: before.len() - start - suffix,
        insert: after[start..after.len() - suffix].iter().collect(),
    }
}
impl Vault {
    /// Current text from the canonical entity-document plane.
    pub fn note_text(&self, note: EntityId) -> Result<String> {
        let txn = self.store.env.read_txn()?;
        self.note_text_in_txn(&txn, note)
    }
    pub(crate) fn note_text_in_txn(&self, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<String> {
        Ok(super::document_store::load(self, txn, note)?
            .view()?
            .markdown)
    }
}
impl Vault {
    pub fn note_program_document(&self, note: EntityId) -> Result<Option<NoteDocument>> {
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &note)? != Some(crate::registry::ENTITY_TYPE_NOTE) {
            return Err(invalid("entity is not a NOTE"));
        }
        load_doc(self, &txn, note)
    }
}

/// Proposal content is a value, never an authenticated document snapshot.
/// Fresh IDs and no pins/authorship prevent it retaining erased quote history.
pub(crate) fn proposal_value(note: EntityId, text: &str) -> Result<LoroDoc> {
    super::validate_markdown(text)?;
    let doc = LoroDoc::new();
    doc.get_map("note")
        .insert("id", note.to_hex())
        .map_err(|_| invalid("proposal identity"))?;
    doc.get_text("body")
        .insert(0, text)
        .map_err(|_| invalid("proposal text"))?;
    doc.commit();
    super::document::NoteDocument::from_loro(note, doc.fork())?;
    Ok(doc)
}

#[cfg(feature = "sync")]
pub(crate) fn proposal_text(note: EntityId, bytes: &[u8]) -> Result<String> {
    let doc = super::document::NoteDocument::load(note, bytes)?;
    let view = doc.view()?;
    if !view.pins.is_empty() || !view.authorship.is_empty() {
        return Err(invalid("proposal cannot carry authority or citations"));
    }
    super::validate_markdown(&view.markdown)?;
    Ok(view.markdown)
}
