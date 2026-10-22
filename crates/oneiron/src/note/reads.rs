//! Caller-scoped NOTE text, stable edit anchors and retained operation attribution.

use super::documents::{NoteDocument, invalid, live_doc_in};
use super::{NoteAnchor, NoteAuthorship, NoteKind, NoteVersion};
use crate::claim::{ClaimReadStatus, PointRead, ReadRow, ScopedReadResult};
use crate::memory::{DiaryEntryAdmission, DiaryReadGate, Memory, MemoryError, MemoryResult};
use crate::scan_check::PendingScanChecks;
use crate::store::ManifestDbs;
use crate::{EntityId, WriteActor};
use serde::{Deserialize, Serialize};

/// One explicit NOTE read. Private notes require the caller's stated reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteAccessRequest {
    pub note_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A half-open span in the selected text, measured in Unicode scalar indices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteReadSpan {
    pub start: usize,
    pub end: usize,
}

/// Live text by default, or the exact retained version a prior read returned.
/// Spans acquire stable anchors at that same version, never at a later head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteReadRequest {
    pub note_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub version: Option<NoteVersion>,
    #[serde(default)]
    pub spans: Vec<NoteReadSpan>,
}

/// The endpoints can be passed directly to `vault.notes.edit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteAnchoredSpan {
    pub start: NoteAnchor,
    pub end: NoteAnchor,
}

/// Where this read obtained the body. A local read never silently fetches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoteReadSource {
    Local,
    Home,
}

/// One coherent editor read, including the base for a whole-text diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteReadView {
    pub version: NoteVersion,
    pub markdown: String,
    pub title: Option<String>,
    pub spans: Vec<NoteAnchoredSpan>,
    pub source: NoteReadSource,
}

/// Only retained, authenticated operation records are history. A shallow
/// admission cannot turn inherited state-map bylines into disclosed history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteHistoryView {
    pub version: NoteVersion,
    pub operations: Vec<NoteAuthorship>,
    pub shallow_since: Vec<u8>,
    pub complete: bool,
}

/// An explicit live editor handle. Close it when the editor leaves; a server
/// restart drops all handles. Its id carries no authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteEditorBinding {
    pub binding: String,
    pub note: NoteReadView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteEditorCloseRequest {
    pub binding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteEditorClosed {
    pub closed: bool,
}

pub(super) fn read_view(
    doc: &NoteDocument,
    spans: &[NoteReadSpan],
    source: NoteReadSource,
) -> crate::Result<NoteReadView> {
    let title = super::document::NoteDocument::from_loro(doc.note, doc.doc.fork())?.title()?;
    let spans = spans
        .iter()
        .map(|span| {
            if span.start > span.end {
                return Err(invalid("reversed NOTE read span"));
            }
            Ok(NoteAnchoredSpan {
                start: doc.anchor(span.start)?,
                end: doc.anchor(span.end)?,
            })
        })
        .collect::<crate::Result<Vec<_>>>()?;
    Ok(NoteReadView {
        version: doc.version(),
        markdown: doc.text(),
        title,
        spans,
        source,
    })
}

/// Where one NOTE read reads its NOTE: its id, the content its read sees
/// (the vault's own, or a room's view of it, FIX 4280) and where the
/// document's size measurements wait.
pub(super) struct NoteReadAt<'a, S> {
    pub(super) note: EntityId,
    pub(super) store: &'a S,
    pub(super) pending: &'a PendingScanChecks,
}

impl Memory<'_> {
    /// A live editor is held by a serving host, not an embedded read handle.
    pub fn bind_note_editor(
        &self,
        _input: &NoteAccessRequest,
    ) -> MemoryResult<ScopedReadResult<Option<NoteEditorBinding>>> {
        Err(MemoryError::new(
            crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
            "a live NOTE editor requires a serving host",
            &[],
        ))
    }

    /// Embedded handles have no host-held editor to close.
    pub fn close_note_editor(
        &self,
        _input: &NoteEditorCloseRequest,
    ) -> MemoryResult<NoteEditorClosed> {
        Err(MemoryError::new(
            crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
            "a live NOTE editor requires a serving host",
            &[],
        ))
    }

    /// The same credential, policy and current row admission as `vault.get`;
    /// projection and document labels share that admission's read snapshot.
    pub fn read_note(
        &self,
        input: &NoteReadRequest,
    ) -> MemoryResult<ScopedReadResult<Option<NoteReadView>>> {
        let access = NoteAccessRequest {
            note_ref: input.note_ref.clone(),
            reason: input.reason.clone(),
        };
        self.project_note_read(&access, |_, doc| {
            let selected = match &input.version {
                Some(version) => doc.at_version(version)?,
                None => doc,
            };
            Ok(read_view(&selected, &input.spans, NoteReadSource::Local)?)
        })
    }

    /// Authorship comes from semantic-operation admission, not commit messages
    /// or a caller-supplied actor. Purged/admission-hidden history stays absent.
    pub fn note_history(
        &self,
        input: &NoteAccessRequest,
    ) -> MemoryResult<ScopedReadResult<Option<NoteHistoryView>>> {
        self.project_note_read(input, |_, doc| {
            let complete = !doc.doc.is_shallow();
            Ok(NoteHistoryView {
                version: doc.version(),
                operations: if complete {
                    super::operations::authorship(&doc.doc)?
                } else {
                    Vec::new()
                },
                shallow_since: doc.doc.shallow_since_vv().to_vv().encode(),
                complete,
            })
        })
    }

    pub(super) fn project_note_read<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        input: &NoteAccessRequest,
        project: impl FnOnce(&heed::RoTxn<'_>, NoteDocument) -> MemoryResult<T>,
    ) -> MemoryResult<ScopedReadResult<Option<T>>> {
        // A NOTE the room this surface binds holds reads in that room (FIX
        // 4280); every other read, a vault NOTE's in a bound session
        // included, is the vault's, as it was.
        if let Some(room) = self.room_note(&input.note_ref)? {
            return self.project_room_note_read(&room, input, project);
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let note = match crate::memory::resolve_entity_ref(self.vault(), &input.note_ref) {
            Ok(note) => note,
            Err(error) if error.code == crate::memory::MEMORY_CODE_NOT_FOUND => {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: lane.read_receipt(None, 0)?,
                });
            }
            Err(error) => return Err(error),
        };
        let store = &self.vault().store;
        let at = NoteReadAt {
            note,
            store,
            pending: &store.pending_scan_checks,
        };
        let result = lane.read_projected(&[PointRead::id(note)], None, |txn, rows| {
            self.project_admitted_note(txn, rows, &at, input, project)
        })?;
        self.finish_note_read(result)
    }

    /// The NOTE `at` names, admitted (or not) in `rows` by its read's
    /// snapshot `txn`, projected by `project` from its live document as
    /// `at.store` holds it, with the diary gate a private or diary NOTE
    /// needs. Kind policy, grants and the diary gate stay the vault's.
    pub(super) fn project_admitted_note<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        txn: &heed::RoTxn<'_>,
        rows: Vec<Option<ReadRow>>,
        at: &NoteReadAt<'_, impl ManifestDbs>,
        input: &NoteAccessRequest,
        project: impl FnOnce(&heed::RoTxn<'_>, NoteDocument) -> MemoryResult<T>,
    ) -> MemoryResult<(Option<T>, Option<DiaryReadGate>)> {
        let note = at.note;
        let Some(row) = rows
            .into_iter()
            .next()
            .flatten()
            .filter(|row| row.body.is_some())
        else {
            return Ok((None, None));
        };
        if row.entity_type != crate::registry::ENTITY_TYPE_NOTE {
            return Err(MemoryError::bad_request("entity is not a NOTE"));
        }
        let (_, core) = super::verbs::note_core_in(self.vault(), at.store, txn, note)?;
        let private = super::overrides::note_context_in_txn(
            &self.vault().store,
            txn,
            &note,
            core.kind.as_str().as_ref(),
        )? == super::ContextDefault::OwnerOnly;
        let mut gate = if private || core.kind == NoteKind::Diary {
            Some(DiaryReadGate::new(
                WriteActor::new(self.actor(), self.actor_class()),
                input.reason.as_deref().unwrap_or_default(),
            )?)
        } else {
            None
        };
        // An erased diary author is no agent, so no Grant covers the entry:
        // it stays held, never admitted through a stand-in author.
        if core.kind == NoteKind::Diary
            && let Some(diary) = &mut gate
            && match core.author_ref.id() {
                Some(author) => {
                    diary.admit(self.vault(), txn, author, note)? != DiaryEntryAdmission::Read
                }
                None => true,
            }
        {
            return Ok((None, gate));
        }
        let doc = live_doc_in(self.vault(), at.store, txn, note, at.pending)?;
        let view = project(txn, doc)?;
        let value = serde_json::to_value(&view).map_err(|_| invalid("NOTE read view encoding"))?;
        let keys = crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
            &self.vault().store,
            txn,
            &value,
        )?;
        let view = self.lifted_view_in_txn(txn, view, || Ok(keys))?;
        self.produced_from([note]);
        Ok((Some(view), gate))
    }

    /// A NOTE read's answer once its snapshot closed: its diary gate, if
    /// it took one, finishes after the read transaction.
    pub(super) fn finish_note_read<T>(
        &self,
        result: ScopedReadResult<(Option<T>, Option<DiaryReadGate>)>,
    ) -> MemoryResult<ScopedReadResult<Option<T>>> {
        let (value, gate) = result.value;
        if let Some(gate) = gate {
            gate.finish(self.vault())?;
        }
        Ok(ScopedReadResult {
            value,
            receipt: result.receipt,
        })
    }
}
