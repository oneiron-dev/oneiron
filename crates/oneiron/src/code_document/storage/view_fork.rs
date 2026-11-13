//! The writer of one working view's fork of a file (row 6 WORKING-VIEW-EDIT):
//! an operation's checks, admission, custody scan and stamped commit, as the
//! shared writer runs them, on a session forked from the view's own state.
//! It keeps the states before and after as content-addressed snapshots and
//! writes no head, ingress or path row, so the shared document, the tested
//! revision and every other view keep their text.

use heed::RwTxn;

use super::super::codec::{frontier, invalid};
use super::super::{CodeDocumentFrontier, CodeDocumentSession, CodeFileEdit};
use super::edit::{EditAdmission, StampedCandidate, stamped_candidate};
use super::{MAX_FILE_BYTES, lift, save_snapshot};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One operation on a view's fork of a file: the states it went from and to,
/// and the text it left.
pub(crate) struct ViewForkStep {
    pub(crate) before: CodeDocumentFrontier,
    pub(crate) after: CodeDocumentFrontier,
    pub(crate) text: String,
}

impl Vault {
    /// Applies `edit` as operation `operation` to `session`, a view's fork of
    /// one file, in the caller's writer. The caller owns the fork's single
    /// writer (the view's revision): no merge runs, because no other session
    /// writes this state. A text edit only: a rename or a metadata change of
    /// a view file refuses.
    ///
    /// # Errors
    /// The shared writer's refusals of the edit, a path outside the
    /// registered repository's whitelist, a secret the edit brings into a
    /// clean file, or a store failure.
    pub(crate) fn apply_view_fork_edit_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
    ) -> Result<ViewForkStep> {
        if edit.new_path.is_some() {
            return Err(invalid());
        }
        let (provenance, before, text) = Self::validate_code_file_edit(session, edit, None)?;
        // A native edit passes the registered repository's retained
        // whitelist, as on the shared writer (FIX 4299).
        self.require_registered_edit_in_txn(wtxn, None, &session.repo, [edit.path.as_str()])?;
        // A replacement that writes a secret the door can place lands its
        // handle, as on the shared writer (FIX 2372; OF-067).
        let admitted =
            self.admit_code_edit_in_txn(wtxn, &session.document_id, edit, EditAdmission::Land)?;
        let edit = admitted.as_ref().unwrap_or(edit);
        let StampedCandidate {
            doc: candidate,
            peer_id,
            ..
        } = stamped_candidate(operation, session, edit, None, &provenance)?;
        let after_text = candidate.get_text("body").to_string();
        if after_text.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        // The edited file, read whole by the write door before any snapshot
        // is written (OF-067): a file that read as secret before its edit and
        // still does has the text it leaves marked, by that text's hash, so a
        // masked reader of the fork reads its handles; another state's text
        // is not touched.
        let mut stood = false;
        crate::batch::secret_scan::scan_document_in_txn(
            &self.store,
            wtxn,
            after_text.as_bytes(),
            || {
                stood = true;
                Ok(Some(text.into_bytes()))
            },
        )?;
        if stood {
            lift::remark_code_document_in_txn(self, wtxn, &session.document_id, &after_text)?;
        }
        let after = frontier(&candidate, &session.repo, session.document_id)?;
        if after.path != before.path {
            return Err(invalid());
        }
        save_snapshot(&self.store, wtxn, &before, &session.doc)?;
        save_snapshot(&self.store, wtxn, &after, &candidate)?;
        candidate.set_peer_id(peer_id).map_err(|_| invalid())?;
        session.doc = candidate;
        Ok(ViewForkStep {
            before,
            after,
            text: after_text,
        })
    }

    /// A session on the stored state `state` of a view's fork, read in the
    /// caller's writer, for the next operation on it: unlike
    /// [`Vault::open_code_document_at`] it needs no live head, because a
    /// fork of an untouched blob has none. `base` is the state the fork grew
    /// from; with no head, it is the birth state, whose text is the initial.
    ///
    /// # Errors
    /// No stored snapshot of `state`, or one that does not check.
    pub(crate) fn open_view_fork_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        base: &CodeDocumentFrontier,
        state: &CodeDocumentFrontier,
        session_id: EntityId,
    ) -> Result<CodeDocumentSession> {
        if base.document_id != state.document_id || base.repo != state.repo {
            return Err(invalid());
        }
        let doc = super::load_frontier(&self.store, txn, state)?.fork();
        let initial_hash = super::load_head(&self.store, txn, &state.document_id)?
            .map_or(base.text_hash, |head| head.initial_hash);
        Ok(CodeDocumentSession {
            doc,
            repo: state.repo.clone(),
            document_id: state.document_id,
            session_id,
            initial_hash,
            provenance: crate::code_document::CodeOpProvenance::default(),
        })
    }
}
