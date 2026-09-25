//! Atomic merge-before-persist of live file edits and immutable tested snapshots.

use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};

use super::codec::{
    decode, doc_from_snapshot, encode, frontier, hash, invalid, key, path_key, snapshot_key,
    validate_path,
};
use super::{CodeDocumentFrontier, CodeDocumentSession, CodeEditReceipt, CodeFileEdit};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::WriteActor;

const HEAD: &[u8] = b"code_document:head:v1:";
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRow {
    frontier: CodeDocumentFrontier,
    snapshot: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadRow {
    initial_hash: [u8; 32],
    state: SnapshotRow,
    receipts: Vec<ReceiptRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRow {
    session: String,
    actor: String,
    actor_class: u8,
    sequence: u64,
    peer_id: u64,
    counter_start: i32,
    counter_end: i32,
    edit: CodeFileEdit,
    before: CodeDocumentFrontier,
    after: CodeDocumentFrontier,
}

/// A host-approved exact-base ingress item. Cooperative editor sessions use
/// the merging primitive instead; pushes and reviewed file replacements cannot
/// silently incorporate operations they did not test.
pub(crate) struct CodeFileIngress {
    pub operation: EntityId,
    pub session: CodeDocumentSession,
    pub edit: CodeFileEdit,
    pub actor: WriteActor,
    pub expected_text: String,
}

impl ReceiptRow {
    fn receipt(&self) -> Result<CodeEditReceipt> {
        Ok(CodeEditReceipt {
            document_id: self.after.document_id,
            session_id: EntityId::from_hex(&self.session)?,
            actor: WriteActor::new(
                EntityId::from_hex(&self.actor)?,
                EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(invalid)?,
            ),
            sequence: self.sequence,
            peer_id: self.peer_id,
            counter_start: self.counter_start,
            counter_end: self.counter_end,
            edit: self.edit.clone(),
            before: self.before.clone(),
            after: self.after.clone(),
        })
    }
}

impl Vault {
    /// Opens a file on a private session fork. An untouched file creates no row.
    /// Once born, the stored document, not `initial`, supplies the current text.
    pub fn open_code_document(
        &self,
        repo: &str,
        path: &str,
        initial: &str,
        session_id: EntityId,
    ) -> Result<CodeDocumentSession> {
        validate_path(repo, path)?;
        if initial.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        let rtxn = self.store.env.read_txn()?;
        let lookup = path_key(repo, path);
        if let Some(id) = self.store.vault_meta.get(&rtxn, &lookup)? {
            let id: [u8; 32] = id.as_ref().try_into().map_err(|_| invalid())?;
            let row = load_head(&self.store, &rtxn, &id)?.ok_or_else(invalid)?;
            if row.state.frontier.repo != repo || row.state.frontier.path != path {
                return Err(invalid());
            }
            let doc = checked_snapshot(&row.state)?.fork();
            return Ok(CodeDocumentSession {
                doc,
                repo: repo.to_owned(),
                document_id: id,
                session_id,
                initial_hash: row.initial_hash,
            });
        }
        // Every not-yet-born session uses identical genesis operations. Peer 0
        // is reserved for this immutable seed, never an editing session.
        let generation = path_generation(&self.store, &rtxn, repo, path)?;
        let document_id = hash(&[lookup.as_slice(), &generation.to_be_bytes()].concat());
        let doc = LoroDoc::new();
        doc.set_peer_id(0).map_err(|_| invalid())?;
        doc.get_map("meta")
            .insert("path", path)
            .map_err(|_| invalid())?;
        doc.get_text("body")
            .insert(0, initial)
            .map_err(|_| invalid())?;
        doc.commit_with(CommitOptions::new().commit_msg("oneiron.code_document.birth.v1"));
        Ok(CodeDocumentSession {
            doc: doc.fork(),
            repo: repo.to_owned(),
            document_id,
            session_id,
            initial_hash: hash(initial.as_bytes()),
        })
    }

    /// Opens a proposal fork at a tested historical file frontier, not at the
    /// newer live document. Use this for a pushed tree's pinned base revision.
    pub fn open_code_document_at(
        &self,
        tested: &CodeDocumentFrontier,
        session_id: EntityId,
    ) -> Result<CodeDocumentSession> {
        let txn = self.store.env.read_txn()?;
        let doc = load_frontier(&self.store, &txn, tested)?.fork();
        let head = load_head(&self.store, &txn, &tested.document_id)?.ok_or_else(invalid)?;
        if head.state.frontier.repo != tested.repo {
            return Err(invalid());
        }
        Ok(CodeDocumentSession {
            doc,
            repo: tested.repo.clone(),
            document_id: tested.document_id,
            session_id,
            initial_hash: head.initial_hash,
        })
    }

    /// Applies exactly one approved operation. No bulk-write or ref-update path.
    /// Span checks use the session's text, so concurrent unseen characters are
    /// never deleted by a whole-file replacement against a newer head.
    pub fn apply_code_file_edit(
        &self,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        self.apply_code_file_edit_once(EntityId::now(), session, edit, actor)
    }
    pub fn code_file_edit_receipt(&self, operation: EntityId) -> Result<Option<CodeEditReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(
                &txn,
                &[
                    b"code_document:ingress:v1:".as_slice(),
                    operation.as_bytes(),
                ]
                .concat(),
            )?
            .map(|raw| {
                let row: ReceiptRow = decode(&raw)?;
                row.receipt()
            })
            .transpose()
    }
    /// A durable ingress identity prevents replay after a process death from
    /// appending the same edit twice. Reusing an identity with other bytes refuses.
    pub fn apply_code_file_edit_once(
        &self,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        let key = [
            b"code_document:ingress:v1:".as_slice(),
            operation.as_bytes(),
        ]
        .concat();
        let mut txn = self.store.env.write_txn()?;
        if let Some(raw) = self.store.vault_meta.get(&txn, &key)? {
            let row: ReceiptRow = decode(&raw)?;
            let receipt = row.receipt()?;
            if receipt.document_id != session.document_id
                || receipt.session_id != session.session_id
                || receipt.actor != actor
                || receipt.edit != *edit
            {
                return Err(invalid());
            }
            drop(txn);
            self.refresh_code_document(session)?;
            return Ok(receipt);
        }
        let old_doc = session.doc.clone();
        let result = (|| {
            let receipt = self.apply_code_file_edit_in_txn(&mut txn, session, edit, actor)?;
            let row = ReceiptRow {
                session: receipt.session_id.to_hex(),
                actor: actor.entity_ref().to_hex(),
                actor_class: actor.actor_class() as u8,
                sequence: receipt.sequence,
                peer_id: receipt.peer_id,
                counter_start: receipt.counter_start,
                counter_end: receipt.counter_end,
                edit: receipt.edit.clone(),
                before: receipt.before.clone(),
                after: receipt.after.clone(),
            };
            self.store.vault_meta.put(&mut txn, &key, &encode(&row)?)?;
            txn.commit()?;
            Ok(receipt)
        })();
        if result.is_err() {
            session.doc = old_doc;
        }
        result
    }
    /// Applies all file operations of one ref atomically, with base validation
    /// under the same writer transaction. Durable replays do not append edits.
    pub(crate) fn apply_code_file_ingress_exact(
        &self,
        items: &mut [CodeFileIngress],
    ) -> Result<Vec<CodeEditReceipt>> {
        let original: Vec<_> = items.iter().map(|item| item.session.doc.clone()).collect();
        let mut txn = self.store.env.write_txn()?;
        let result = (|| {
            let receipts = self.apply_code_file_ingress_exact_in_txn(&mut txn, items)?;
            txn.commit()?;
            Ok(receipts)
        })();
        if result.is_err() {
            for (item, doc) in items.iter_mut().zip(original) {
                item.session.doc = doc;
            }
        }
        result
    }

    /// Joins exact document ingress to its caller's durable receipt transaction.
    /// The caller must discard the transient sessions if the transaction aborts.
    pub(crate) fn apply_code_file_ingress_exact_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        items: &mut [CodeFileIngress],
    ) -> Result<Vec<CodeEditReceipt>> {
        let mut receipts = Vec::with_capacity(items.len());
        for item in items.iter_mut() {
            let key = [
                b"code_document:ingress:v1:".as_slice(),
                item.operation.as_bytes(),
            ]
            .concat();
            if let Some(raw) = self.store.vault_meta.get(txn, &key)? {
                let row: ReceiptRow = decode(&raw)?;
                let receipt = row.receipt()?;
                if receipt.document_id != item.session.document_id
                    || receipt.session_id != item.session.session_id
                    || receipt.actor != item.actor
                    || receipt.edit != item.edit
                    || receipt.before.text_hash != hash(item.expected_text.as_bytes())
                {
                    return Err(invalid());
                }
                let head =
                    load_head(&self.store, txn, &item.session.document_id)?.ok_or_else(invalid)?;
                if head.initial_hash != item.session.initial_hash
                    || head.state.frontier.repo != item.session.repo
                {
                    return Err(invalid());
                }
                let doc = checked_snapshot(&head.state)?;
                doc.set_peer_id(item.session.doc.peer_id())
                    .map_err(|_| invalid())?;
                item.session.doc = doc;
                receipts.push(receipt);
                continue;
            }
            let before = item.session.frontier()?;
            let head = load_head(&self.store, txn, &item.session.document_id)?;
            if item.session.text() != item.expected_text
                || head.is_some_and(|row| row.state.frontier != before)
            {
                return Err(crate::Error::ConcurrentWrite(
                    "document changed since ingress base; no automatic rebase",
                ));
            }
            let receipt =
                self.apply_code_file_edit_in_txn(txn, &mut item.session, &item.edit, item.actor)?;
            let row = ReceiptRow {
                session: receipt.session_id.to_hex(),
                actor: receipt.actor.entity_ref().to_hex(),
                actor_class: receipt.actor.actor_class() as u8,
                sequence: receipt.sequence,
                peer_id: receipt.peer_id,
                counter_start: receipt.counter_start,
                counter_end: receipt.counter_end,
                edit: receipt.edit.clone(),
                before: receipt.before.clone(),
                after: receipt.after.clone(),
            };
            self.store.vault_meta.put(txn, &key, &encode(&row)?)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn apply_code_file_edit_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        validate_path(&session.repo, &edit.path)?;
        let before = session.frontier()?;
        if before.path != edit.path {
            return Err(invalid());
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
        } else if edit.expected == edit.replacement {
            return Err(invalid());
        }
        let candidate = doc_from_snapshot(
            &session
                .doc
                .export(ExportMode::Snapshot)
                .map_err(|_| invalid())?,
        )?;
        let peer_id = session.doc.peer_id();
        candidate.set_peer_id(peer_id).map_err(|_| invalid())?;
        let counter_start = candidate.oplog_vv().get(&peer_id).copied().unwrap_or(0);
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
        let edit_hash = crate::entity_id::bytes_to_hex_lower(&hash(&encode(edit)?));
        let stamp = format!(
            "oneiron.code_document.v1:{}:{}:{}:{}:{}:{}",
            session.session_id.to_hex(),
            actor.entity_ref().to_hex(),
            actor.actor_class() as u8,
            peer_id,
            counter_start,
            edit_hash
        );
        candidate.commit_with(CommitOptions::new().commit_msg(&stamp));
        let counter_end = candidate.oplog_vv().get(&peer_id).copied().unwrap_or(0);
        if counter_end <= counter_start {
            return Err(invalid());
        }
        let head = load_head(&self.store, &*wtxn, &session.document_id)?;
        let (merged, mut receipts) = if let Some(row) = head {
            if row.initial_hash != session.initial_hash
                || row.state.frontier.repo != session.repo
                || row.state.frontier.path != edit.path
            {
                return Err(invalid());
            }
            let persisted = checked_snapshot(&row.state)?;
            if row.state.frontier == before {
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
            if let Some(id) = self
                .store
                .vault_meta
                .get(&*wtxn, &path_key(&session.repo, &edit.path))?
                && id.as_ref() != session.document_id
            {
                return Err(invalid());
            }
            (candidate, Vec::new())
        };
        if merged.get_text("body").to_string().len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        let after = frontier(&merged, &session.repo, session.document_id)?;
        if let Some(path) = &edit.new_path {
            if after.path != *path {
                return Err(invalid());
            }
            if self
                .store
                .vault_meta
                .get(&*wtxn, &path_key(&session.repo, path))?
                .is_some()
            {
                return Err(invalid());
            }
        }
        let sequence = u64::try_from(receipts.len())
            .map_err(|_| invalid())?
            .checked_add(1)
            .ok_or_else(invalid)?;
        let receipt = ReceiptRow {
            session: session.session_id.to_hex(),
            actor: actor.entity_ref().to_hex(),
            actor_class: actor.actor_class() as u8,
            sequence,
            peer_id,
            counter_start,
            counter_end,
            edit: edit.clone(),
            before: before.clone(),
            after: after.clone(),
        };
        let result = receipt.receipt()?;
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
        self.store
            .vault_meta
            .put(wtxn, &key(HEAD, &session.document_id), &encode(&row)?)?;
        if edit.new_path.is_some() {
            self.store
                .vault_meta
                .delete(wtxn, &path_key(&session.repo, &edit.path))?;
            let generation = path_generation(&self.store, &*wtxn, &session.repo, &edit.path)?
                .checked_add(1)
                .ok_or_else(invalid)?;
            self.store.vault_meta.put(
                wtxn,
                &generation_key(&session.repo, &edit.path),
                &generation.to_be_bytes(),
            )?;
        }
        self.store.vault_meta.put(
            wtxn,
            &path_key(&session.repo, &after.path),
            &session.document_id,
        )?;
        merged.set_peer_id(peer_id).map_err(|_| invalid())?;
        session.doc = merged;
        Ok(result)
    }

    /// Observes durable concurrent edits without creating an operation.
    pub fn refresh_code_document(&self, session: &mut CodeDocumentSession) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        if let Some(row) = load_head(&self.store, &rtxn, &session.document_id)? {
            if row.initial_hash != session.initial_hash || row.state.frontier.repo != session.repo {
                return Err(invalid());
            }
            let doc = checked_snapshot(&row.state)?;
            doc.set_peer_id(session.doc.peer_id())
                .map_err(|_| invalid())?;
            session.doc = doc;
        }
        Ok(())
    }

    pub fn code_document_frontier(
        &self,
        repo: &str,
        path: &str,
    ) -> Result<Option<CodeDocumentFrontier>> {
        validate_path(repo, path)?;
        let rtxn = self.store.env.read_txn()?;
        let Some(id) = self.store.vault_meta.get(&rtxn, &path_key(repo, path))? else {
            return Ok(None);
        };
        let id = id.as_ref().try_into().map_err(|_| invalid())?;
        let row = load_head(&self.store, &rtxn, &id)?.ok_or_else(invalid)?;
        checked_snapshot(&row.state)?;
        if row.state.frontier.repo != repo || row.state.frontier.path != path {
            return Err(invalid());
        }
        Ok(Some(row.state.frontier))
    }

    /// Regenerates the exact tested file, even after the live document advances.
    pub fn code_document_at(&self, tested: &CodeDocumentFrontier) -> Result<String> {
        let rtxn = self.store.env.read_txn()?;
        let doc = load_frontier(&self.store, &rtxn, tested)?;
        Ok(doc.get_text("body").to_string())
    }

    pub fn code_document_receipts(&self, document_id: &[u8; 32]) -> Result<Vec<CodeEditReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = load_head(&self.store, &rtxn, document_id)? else {
            return Ok(Vec::new());
        };
        let doc = checked_snapshot(&row.state)?;
        row.receipts
            .iter()
            .enumerate()
            .map(|(index, r)| {
                let receipt = r.receipt()?;
                let message = format!(
                    "oneiron.code_document.v1:{}:{}:{}:{}:{}:{}",
                    r.session,
                    r.actor,
                    r.actor_class,
                    r.peer_id,
                    r.counter_start,
                    crate::entity_id::bytes_to_hex_lower(&hash(&encode(&r.edit)?))
                );
                let change = doc
                    .get_change(loro::ID::new(r.peer_id, r.counter_start))
                    .ok_or_else(invalid)?;
                if r.sequence != index as u64 + 1
                    || change.message.as_deref() != Some(message.as_str())
                    || r.counter_end <= r.counter_start
                {
                    return Err(invalid());
                }
                verify_frontier_in_txn(&self.store, &rtxn, &r.before)?;
                verify_frontier_in_txn(&self.store, &rtxn, &r.after)?;
                Ok(receipt)
            })
            .collect()
    }
}

fn load_head(store: &Store, txn: &RoTxn<'_>, id: &[u8; 32]) -> Result<Option<HeadRow>> {
    let Some(raw) = store.vault_meta.get(txn, &key(HEAD, id))? else {
        return Ok(None);
    };
    let row: HeadRow = decode(&raw)?;
    if row.state.frontier.document_id != *id {
        return Err(invalid());
    }
    Ok(Some(row))
}

fn checked_snapshot(row: &SnapshotRow) -> Result<LoroDoc> {
    let doc = doc_from_snapshot(&row.snapshot)?;
    if frontier(&doc, &row.frontier.repo, row.frontier.document_id)? != row.frontier {
        return Err(invalid());
    }
    Ok(doc)
}

fn save_snapshot(
    store: &Store,
    txn: &mut RwTxn<'_>,
    state: &CodeDocumentFrontier,
    doc: &LoroDoc,
) -> Result<()> {
    let key = snapshot_key(state);
    if let Some(raw) = store.vault_meta.get(txn, &key)? {
        let existing: SnapshotRow = decode(&raw)?;
        checked_snapshot(&existing)?;
        if existing.frontier != *state {
            return Err(invalid());
        }
        return Ok(());
    }
    let row = SnapshotRow {
        frontier: state.clone(),
        snapshot: doc.export(ExportMode::Snapshot).map_err(|_| invalid())?,
    };
    store.vault_meta.put(txn, &key, &encode(&row)?)?;
    Ok(())
}

fn load_frontier(store: &Store, txn: &RoTxn<'_>, tested: &CodeDocumentFrontier) -> Result<LoroDoc> {
    let raw = store
        .vault_meta
        .get(txn, &snapshot_key(tested))?
        .ok_or_else(invalid)?;
    let row: SnapshotRow = decode(&raw)?;
    if row.frontier != *tested {
        return Err(invalid());
    }
    checked_snapshot(&row)
}

pub(crate) fn verify_frontier_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    tested: &CodeDocumentFrontier,
) -> Result<()> {
    load_frontier(store, txn, tested)?;
    Ok(())
}

fn generation_key(repo: &str, path: &str) -> Vec<u8> {
    key(
        b"code_document:generation:v1:",
        &hash(&path_key(repo, path)),
    )
}
fn path_generation(store: &Store, txn: &RoTxn<'_>, repo: &str, path: &str) -> Result<u64> {
    match store.vault_meta.get(txn, &generation_key(repo, path))? {
        None => Ok(0),
        Some(raw) => Ok(u64::from_be_bytes(
            raw.as_ref().try_into().map_err(|_| invalid())?,
        )),
    }
}
