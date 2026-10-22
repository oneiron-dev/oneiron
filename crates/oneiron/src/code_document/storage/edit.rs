//! The one shared writer of a code document operation (moved from
//! `storage.rs`, G4 PR2): the edit's span checks, the candidate merge, the
//! custody scan, the stamped commit, and the head, ingress, snapshot and
//! path rows, in the caller's writer.

use heed::RwTxn;
use loro::{CommitOptions, ExportMode};

use super::super::codec::{doc_from_snapshot, frontier, invalid, path_hash, validate_path};
use super::super::{CodeDocumentSession, CodeEditReceipt, CodeFileEdit, CodeFileMetadataEdit};
use super::{
    CODE_DOCUMENT_GENERATION, CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS, CODE_DOCUMENT_PATH,
    HeadRow, MAX_FILE_BYTES, ReceiptActor, ReceiptRow, SnapshotRow, checked_snapshot,
    generation_key, lift, load_head, op_stamp, path_generation, save_snapshot,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;

impl Vault {
    /// Applies one operation and writes its head and ingress receipts.
    pub(super) fn apply_code_file_edit_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        metadata: Option<&CodeFileMetadataEdit>,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        let (provenance, before, text) = Self::validate_code_file_edit(session, edit, metadata)?;
        let candidate = doc_from_snapshot(
            &session
                .doc
                .export(ExportMode::Snapshot)
                .map_err(|_| invalid())?,
        )?;
        let peer_id = session.doc.peer_id();
        candidate.set_peer_id(peer_id).map_err(|_| invalid())?;
        let counter_start = candidate.oplog_vv().get(&peer_id).copied().unwrap_or(0);
        if let Some(metadata) = metadata {
            super::super::file_metadata::apply_presence(&candidate.get_map("meta"), metadata)?;
        }
        if let Some(path) = &edit.new_path {
            candidate
                .get_map("meta")
                .insert("path", path.as_str())
                .map_err(|_| invalid())?;
        } else {
            let body = candidate.get_text("body");
            if edit.end > edit.start {
                body.delete(edit.start, edit.end - edit.start)
                    .map_err(|_| invalid())?;
            }
            if !edit.replacement.is_empty() {
                body.insert(edit.start, &edit.replacement)
                    .map_err(|_| invalid())?;
            }
        }
        let stamp = op_stamp(
            &operation.to_hex(),
            &session.session_id.to_hex(),
            peer_id,
            counter_start,
            edit,
            metadata,
            &provenance,
        )?;
        candidate.commit_with(CommitOptions::new().commit_msg(&stamp));
        let counter_end = candidate.oplog_vv().get(&peer_id).copied().unwrap_or(0);
        if counter_end <= counter_start {
            return Err(invalid());
        }
        let (merged, mut receipts) =
            self.merge_code_file_candidate_in_txn(wtxn, session, edit, &before, candidate)?;
        let merged_text = merged.get_text("body").to_string();
        if merged_text.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        // The edited file, read whole by the write door under the owner's
        // switch before any snapshot or receipt is written (OF-067). Its
        // receipt binds the edit's bytes, so a replay can prove it the same
        // edit: no handle can stand in a secret, and a hit refuses, unless
        // the file read the same way before the edit.
        let mut stood = false;
        crate::batch::secret_scan::scan_document_in_txn(
            &self.store,
            wtxn,
            merged_text.as_bytes(),
            || {
                stood = true;
                Ok(Some(text.into_bytes()))
            },
        )?;
        // A file that read as secret before its edit and still does: the
        // text it leaves is marked, a lifted value keeping its record
        // (OF-067).
        if stood {
            lift::remark_code_document_in_txn(self, wtxn, &session.document_id, &merged_text)?;
        }
        let after = frontier(&merged, &session.repo, session.document_id)?;
        if let Some(path) = &edit.new_path {
            if after.path != *path {
                return Err(invalid());
            }
            if CODE_DOCUMENT_PATH.contains(&self.store, &*wtxn, &path_hash(&session.repo, path))? {
                return Err(invalid());
            }
        }
        let sequence = u64::try_from(receipts.len())
            .map_err(|_| invalid())?
            .checked_add(1)
            .ok_or_else(invalid)?;
        let receipt = ReceiptRow {
            operation: operation.to_hex(),
            session: session.session_id.to_hex(),
            actor: ReceiptActor::Actor(actor.entity_ref()),
            actor_class: actor.actor_class() as u8,
            provenance,
            sequence,
            peer_id,
            counter_start,
            counter_end,
            edit: edit.clone(),
            metadata_edit: metadata.cloned(),
            before: before.clone(),
            after: after.clone(),
        };
        let result = receipt.receipt()?;
        CODE_DOCUMENT_INGRESS.put(&self.store, wtxn, &operation, &receipt)?;
        receipts.push(receipt);
        let snapshot = merged.export(ExportMode::Snapshot).map_err(|_| invalid())?;
        save_snapshot(&self.store, wtxn, &before, &session.doc)?;
        save_snapshot(&self.store, wtxn, &after, &merged)?;
        let row = HeadRow {
            initial_hash: session.initial_hash,
            state: SnapshotRow {
                frontier: after.clone(),
                snapshot,
            },
            receipts,
        };
        CODE_DOCUMENT_HEAD.put(&self.store, wtxn, &session.document_id, &row)?;
        self.update_code_file_path_rows_in_txn(wtxn, session, edit, metadata, &after)?;
        merged.set_peer_id(peer_id).map_err(|_| invalid())?;
        session.doc = merged;
        Ok(result)
    }

    /// The edit checked against its session before any write: its paths,
    /// provenance, span, metadata and rename; the provenance, the frontier
    /// before it and the text it edits, as they stood.
    fn validate_code_file_edit(
        session: &CodeDocumentSession,
        edit: &CodeFileEdit,
        metadata: Option<&CodeFileMetadataEdit>,
    ) -> Result<(
        super::super::CodeOpProvenance,
        super::super::CodeDocumentFrontier,
        String,
    )> {
        validate_path(&session.repo, &edit.path)?;
        session.provenance.validate()?;
        let provenance = session.provenance.clone();
        let before = session.frontier()?;
        // A removed document's path is free; recreation births a new one.
        if before.path != edit.path || before.file_presence.is_some_and(|state| !state.present) {
            return Err(invalid());
        }
        if let Some(metadata) = metadata {
            metadata.validate(&session.repo)?;
            if metadata.path != edit.path || metadata.new_path != edit.new_path {
                return Err(invalid());
            }
        }
        let text = session.text();
        if edit.start > edit.end
            || edit.end > text.chars().count()
            || text
                .chars()
                .skip(edit.start)
                .take(edit.end - edit.start)
                .collect::<String>()
                != edit.expected
            || edit.replacement.len() > MAX_FILE_BYTES
        {
            return Err(invalid());
        }
        if let Some(path) = &edit.new_path {
            validate_path(&session.repo, path)?;
            if path == &edit.path
                || edit.start != 0
                || edit.end != 0
                || !edit.expected.is_empty()
                || !edit.replacement.is_empty()
            {
                return Err(invalid());
            }
        } else if edit.expected == edit.replacement && metadata.is_none() {
            return Err(invalid());
        }
        Ok((provenance, before, text))
    }

    /// The edited candidate merged over the durable head in the writer, with
    /// the head receipts; with no head, the path still free for it.
    fn merge_code_file_candidate_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        session: &CodeDocumentSession,
        edit: &CodeFileEdit,
        before: &super::super::CodeDocumentFrontier,
        candidate: loro::LoroDoc,
    ) -> Result<(loro::LoroDoc, Vec<ReceiptRow>)> {
        let head = load_head(&self.store, &*wtxn, &session.document_id)?;
        let (merged, receipts) = if let Some(row) = head {
            if row.initial_hash != session.initial_hash
                || row.state.frontier.repo != session.repo
                || row.state.frontier.path != edit.path
            {
                return Err(invalid());
            }
            let persisted = checked_snapshot(&row.state)?;
            if row.state.frontier == *before {
                // The session already contains the complete durable head. It
                // needs no merge: importing its own history makes Loro rebuild
                // a rich-text diff tracker, quadratic for large insert runs.
                (candidate, row.receipts)
            } else {
                let merged = persisted;
                let update = candidate
                    .export(ExportMode::all_updates())
                    .map_err(|_| invalid())?;
                merged.import(&update).map_err(|_| invalid())?;
                (merged, row.receipts)
            }
        } else {
            // A rename may have claimed this path since the session opened.
            if let Some(id) = CODE_DOCUMENT_PATH.get(
                &self.store,
                &*wtxn,
                &path_hash(&session.repo, &edit.path),
            )? && id != session.document_id
            {
                return Err(invalid());
            }
            (candidate, Vec::new())
        };
        Ok((merged, receipts))
    }

    /// The path rows after the head is written: a rename or removal frees the
    /// old path, and a document that is not removed claims its path.
    fn update_code_file_path_rows_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        session: &CodeDocumentSession,
        edit: &CodeFileEdit,
        metadata: Option<&CodeFileMetadataEdit>,
        after: &super::super::CodeDocumentFrontier,
    ) -> Result<()> {
        // A removal frees its path as a rename does, and claims none.
        let removed = metadata.is_some_and(CodeFileMetadataEdit::removes);
        if edit.new_path.is_some() || removed {
            CODE_DOCUMENT_PATH.delete(&self.store, wtxn, &path_hash(&session.repo, &edit.path))?;
            let generation = path_generation(&self.store, &*wtxn, &session.repo, &edit.path)?
                .checked_add(1)
                .ok_or_else(invalid)?;
            CODE_DOCUMENT_GENERATION.put(
                &self.store,
                wtxn,
                &generation_key(&session.repo, &edit.path),
                &generation,
            )?;
        }
        if !removed {
            CODE_DOCUMENT_PATH.put(
                &self.store,
                wtxn,
                &path_hash(&session.repo, &after.path),
                &session.document_id,
            )?;
        }
        Ok(())
    }
}
