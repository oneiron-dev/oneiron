//! Entity-local text CRDT with stamped birth, stable cursors and isolated rewrites.

use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use loro::cursor::{Cursor, Side};
use loro::{ExportMode, Frontiers, LoroDoc, UpdateOptions};
use serde::{Deserialize, Serialize};

const TEXT: &str = "body";

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
    Edited { head: EntityId },
    RewriteFork { fork: EntityId },
    ProposedFork { fork: EntityId },
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
        let cursor = Cursor::decode(&anchor.cursor).map_err(|_| invalid("invalid cursor"))?;
        self.doc
            .get_cursor_pos(&cursor)
            .map(|p| p.current.pos)
            .map_err(|_| invalid("unresolvable cursor"))
    }
    pub(crate) fn born(note: EntityId, text: &str, actor: EntityId, at: u64) -> Result<Self> {
        let this = Self {
            note,
            head: EntityId::now(),
            doc: LoroDoc::new(),
        };
        let meta = this.doc.get_map("meta");
        meta.insert("birth_actor", actor.to_hex())
            .map_err(|_| invalid("birth actor"))?;
        meta.insert("birth_at", at.to_string())
            .map_err(|_| invalid("birth timestamp"))?;
        this.doc
            .get_text(TEXT)
            .insert(0, text)
            .map_err(|_| invalid("birth text"))?;
        stamp(&this.doc, actor, at, "birth");
        Ok(this)
    }
    pub(super) fn apply(&self, edit: &NoteEdit, actor: EntityId, at: u64) -> Result<Option<Self>> {
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
                    return self.rewrite(replacement, actor, at).map(Some);
                }
                stamp(&candidate, actor, at, "edit");
                self.doc
                    .import(&snapshot(&candidate)?)
                    .map_err(|_| invalid("diff import"))?;
                return Ok(None);
            }
            NoteEdit::Rewrite { text } => return self.rewrite(text, actor, at).map(Some),
        }
        stamp(&self.doc, actor, at, "edit");
        Ok(None)
    }
    fn rewrite(&self, text: &str, actor: EntityId, at: u64) -> Result<Self> {
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
            head: EntityId::now(),
            doc: fork,
        })
    }
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}
pub(super) fn stamp(doc: &LoroDoc, actor: EntityId, at: u64, action: &str) {
    doc.set_next_commit_message(&format!("note:v1:{action}:actor={}", actor.to_hex()));
    doc.set_next_commit_timestamp(at.min(i64::MAX as u64) as i64);
    doc.commit();
}
pub(super) fn head_key(note: EntityId) -> Vec<u8> {
    [b"note_head:v1:".as_slice(), note.as_bytes()].concat()
}
pub(super) fn doc_key(note: EntityId, head: EntityId) -> String {
    format!("note_doc:v1:{}:{}", note.to_hex(), head.to_hex())
}
pub(super) fn snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|_| invalid("document snapshot"))
}
pub(crate) fn store_doc(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
    advance: bool,
) -> Result<()> {
    vault
        .store
        .sync_state
        .put(txn, &doc_key(doc.note, doc.head), &snapshot(&doc.doc)?)?;
    if advance {
        let (header, mut core) = super::verbs::note_core(vault, txn, doc.note)?;
        if core.document_head != Some(doc.head) {
            core.markdown.clear();
            core.document_head = Some(doc.head);
            let body = super::encode_note_body(&core)?;
            vault
                .batch_in()
                .put_authored_note(
                    &doc.note,
                    &core.author_ref,
                    crate::temporal::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &body,
                )
                .apply(txn)?;
        }
        vault
            .store
            .vault_meta
            .put(txn, &head_key(doc.note), doc.head.as_bytes())?;
        vault
            .batch_in()
            .text(&doc.note, &[("markdown", &doc.text())])
            .apply(txn)?;
    }
    Ok(())
}
pub(super) fn load_doc(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<Option<NoteDocument>> {
    let (_, core) = super::verbs::note_core(vault, txn, note)?;
    let Some(head) = vault.store.vault_meta.get(txn, &head_key(note))? else {
        if core.document_head.is_some() {
            return Err(invalid("missing document head"));
        }
        return Ok(None);
    };
    let head = EntityId::from_bytes(
        head.as_ref()
            .try_into()
            .map_err(|_| invalid("document head"))?,
    )?;
    if core.document_head != Some(head) {
        return Err(invalid("document head differs from core"));
    }
    load_head(vault, txn, note, head).map(Some)
}
pub(super) fn load_head(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    head: EntityId,
) -> Result<NoteDocument> {
    let raw = vault
        .store
        .sync_state
        .get(txn, &doc_key(note, head))?
        .ok_or(invalid("missing document"))?;
    let doc = LoroDoc::from_snapshot(&raw).map_err(|_| invalid("corrupt document"))?;
    Ok(NoteDocument { note, head, doc })
}
impl Vault {
    /// Current text projection. The immutable core is still returned by `get`.
    pub fn note_text(&self, note: EntityId) -> Result<String> {
        let txn = self.store.env.read_txn()?;
        self.note_text_in_txn(&txn, note)
    }
    pub(crate) fn note_text_in_txn(&self, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<String> {
        Ok(match load_doc(self, txn, note)? {
            Some(doc) => doc.text(),
            None => super::verbs::note_core(self, txn, note)?.1.markdown,
        })
    }
}
impl Vault {
    pub fn note_document(&self, note: EntityId) -> Result<Option<NoteDocument>> {
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &note)? != Some(crate::registry::ENTITY_TYPE_NOTE) {
            return Err(invalid("entity is not a NOTE"));
        }
        load_doc(self, &txn, note)
    }
}
