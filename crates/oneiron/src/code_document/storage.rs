//! Atomic merge-before-persist of live file edits and immutable tested snapshots.

use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};

use super::codec::{
    doc_from_snapshot, encode, frontier, hash, invalid, path_hash, path_key, validate_path,
};
use super::{
    CodeDocumentFrontier, CodeDocumentSession, CodeEditReceipt, CodeFileEdit, CodeOpAttribution,
    CodeOpProvenance,
};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::write_envelope::WriteActor;

mod lift;
pub(crate) use self::lift::{CodeDocumentRows, code_document_texts_in_txn};

/// Immutable tested snapshot of a code document at one exact operation
/// frontier: key is the document id then the op-fold hash, raw-concatenated.
pub(super) const CODE_DOCUMENT_FRONTIER: SideTable<([u8; 32], [u8; 32]), SnapshotRow, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_FRONTIER);
/// Monotonic rename-generation counter for a (repo, path) pair.
const CODE_DOCUMENT_GENERATION: SideTable<[u8; 32], u64, Raw> =
    SideTable::new(&side_table::CODE_DOCUMENT_GENERATION);
/// Current durable head snapshot plus full receipt history for one code document.
const CODE_DOCUMENT_HEAD: SideTable<[u8; 32], HeadRow, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_HEAD);
/// Durable replay-guard receipt for one applied code-file-edit ingress operation.
const CODE_DOCUMENT_INGRESS: SideTable<EntityId, ReceiptRow, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_INGRESS);
/// Maps a (repo, path) pair (sha256-hashed) to the code-document id currently
/// living at that path.
const CODE_DOCUMENT_PATH: SideTable<[u8; 32], [u8; 32], Raw> =
    SideTable::new(&side_table::CODE_DOCUMENT_PATH);

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotRow {
    frontier: CodeDocumentFrontier,
    snapshot: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeadRow {
    initial_hash: [u8; 32],
    state: SnapshotRow,
    pub(super) receipts: Vec<ReceiptRow>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptRow {
    operation: String,
    session: String,
    actor: String,
    actor_class: u8,
    provenance: CodeOpProvenance,
    sequence: u64,
    pub(super) peer_id: u64,
    pub(super) counter_start: i32,
    pub(super) counter_end: i32,
    pub(super) edit: CodeFileEdit,
    pub(super) before: CodeDocumentFrontier,
    pub(super) after: CodeDocumentFrontier,
}

/// The Loro commit message of one operation. It binds the ingress identity,
/// actor, edit and provenance into the document's operation fold.
#[allow(clippy::too_many_arguments)]
fn op_stamp(
    operation: &str,
    session: &str,
    actor: &str,
    actor_class: u8,
    peer_id: u64,
    counter_start: i32,
    edit: &CodeFileEdit,
    provenance: &CodeOpProvenance,
) -> Result<String> {
    Ok(format!(
        "oneiron.code_document.v2:{operation}:{session}:{actor}:{actor_class}:{peer_id}:{counter_start}:{}:{}",
        crate::entity_id::bytes_to_hex_lower(&hash(&encode(edit)?)),
        crate::entity_id::bytes_to_hex_lower(&hash(&encode(provenance)?)),
    ))
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
    fn actor(&self) -> Result<WriteActor> {
        Ok(WriteActor::new(
            EntityId::from_hex(&self.actor)?,
            EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(invalid)?,
        ))
    }

    pub(super) fn attribution(&self) -> Result<CodeOpAttribution> {
        Ok(CodeOpAttribution {
            operation: EntityId::from_hex(&self.operation)?,
            session_id: EntityId::from_hex(&self.session)?,
            actor: self.actor()?,
            sequence: self.sequence,
            provenance: self.provenance.clone(),
        })
    }

    /// Whether every change of this operation lies in `version`.
    pub(super) fn within(&self, version: &[(u64, i32)]) -> bool {
        version
            .iter()
            .any(|(peer, counter)| *peer == self.peer_id && *counter >= self.counter_end)
    }

    /// Whether `version` holds none of this operation's changes.
    pub(super) fn after_version(&self, version: &[(u64, i32)]) -> bool {
        !version
            .iter()
            .any(|(peer, counter)| *peer == self.peer_id && *counter > self.counter_start)
    }

    pub(super) fn owns(&self, id: loro::ID) -> bool {
        id.peer == self.peer_id && self.counter_start <= id.counter && id.counter < self.counter_end
    }

    fn receipt(&self) -> Result<CodeEditReceipt> {
        Ok(CodeEditReceipt {
            document_id: self.after.document_id,
            operation: EntityId::from_hex(&self.operation)?,
            session_id: EntityId::from_hex(&self.session)?,
            actor: self.actor()?,
            provenance: self.provenance.clone(),
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
        if let Some(id) = CODE_DOCUMENT_PATH.get(&self.store, &rtxn, &path_hash(repo, path))? {
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
                provenance: CodeOpProvenance::default(),
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
            provenance: CodeOpProvenance::default(),
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
            provenance: CodeOpProvenance::default(),
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
        CODE_DOCUMENT_INGRESS
            .get(&self.store, &txn, &operation)?
            .map(|row| row.receipt())
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
        let mut txn = self.store.env.write_txn()?;
        if let Some(row) = CODE_DOCUMENT_INGRESS.get(&self.store, &txn, &operation)? {
            let receipt = row.receipt()?;
            if receipt.document_id != session.document_id
                || receipt.session_id != session.session_id
                || receipt.actor != actor
                || receipt.provenance != session.provenance
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
            let receipt =
                self.apply_code_file_edit_in_txn(&mut txn, operation, session, edit, actor)?;
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
            if let Some(row) = CODE_DOCUMENT_INGRESS.get(&self.store, txn, &item.operation)? {
                let receipt = row.receipt()?;
                if receipt.document_id != item.session.document_id
                    || receipt.session_id != item.session.session_id
                    || receipt.actor != item.actor
                    || receipt.provenance != item.session.provenance
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
            let receipt = self.apply_code_file_edit_in_txn(
                txn,
                item.operation,
                &mut item.session,
                &item.edit,
                item.actor,
            )?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// Applies one operation and writes its head and ingress receipts.
    fn apply_code_file_edit_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        validate_path(&session.repo, &edit.path)?;
        session.provenance.validate()?;
        let provenance = session.provenance.clone();
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
        let stamp = op_stamp(
            &operation.to_hex(),
            &session.session_id.to_hex(),
            &actor.entity_ref().to_hex(),
            actor.actor_class() as u8,
            peer_id,
            counter_start,
            edit,
            &provenance,
        )?;
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
            actor: actor.entity_ref().to_hex(),
            actor_class: actor.actor_class() as u8,
            provenance,
            sequence,
            peer_id,
            counter_start,
            counter_end,
            edit: edit.clone(),
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
        if edit.new_path.is_some() {
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
        CODE_DOCUMENT_PATH.put(
            &self.store,
            wtxn,
            &path_hash(&session.repo, &after.path),
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
        let Some(id) = CODE_DOCUMENT_PATH.get(&self.store, &rtxn, &path_hash(repo, path))? else {
            return Ok(None);
        };
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
                let message = op_stamp(
                    &r.operation,
                    &r.session,
                    &r.actor,
                    r.actor_class,
                    r.peer_id,
                    r.counter_start,
                    &r.edit,
                    &r.provenance,
                )?;
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

pub(super) fn load_head(store: &Store, txn: &RoTxn<'_>, id: &[u8; 32]) -> Result<Option<HeadRow>> {
    let Some(row) = CODE_DOCUMENT_HEAD.get(store, txn, id)? else {
        return Ok(None);
    };
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
    let key = (state.document_id, state.op_fold);
    if let Some(existing) = CODE_DOCUMENT_FRONTIER.get(store, txn, &key)? {
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
    CODE_DOCUMENT_FRONTIER.put(store, txn, &key, &row)?;
    Ok(())
}

pub(super) fn load_frontier(
    store: &Store,
    txn: &RoTxn<'_>,
    tested: &CodeDocumentFrontier,
) -> Result<LoroDoc> {
    let row = CODE_DOCUMENT_FRONTIER
        .get(store, txn, &(tested.document_id, tested.op_fold))?
        .ok_or_else(invalid)?;
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

fn generation_key(repo: &str, path: &str) -> [u8; 32] {
    hash(&path_key(repo, path))
}
fn path_generation(store: &Store, txn: &RoTxn<'_>, repo: &str, path: &str) -> Result<u64> {
    Ok(CODE_DOCUMENT_GENERATION
        .get(store, txn, &generation_key(repo, path))?
        .unwrap_or(0))
}
