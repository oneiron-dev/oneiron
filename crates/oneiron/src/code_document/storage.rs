//! Atomic merge-before-persist of live file edits and immutable tested snapshots.

use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};

use super::codec::{
    doc_from_snapshot, encode, frontier, hash, invalid, path_hash, path_hash_key, path_key,
    validate_path,
};
use super::{
    CodeDocumentFrontier, CodeDocumentSession, CodeEditReceipt, CodeFileEdit, CodeFileMetadataEdit,
    CodeOpAttribution, CodeOpProvenance,
};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::write_envelope::WriteActor;

pub(crate) mod checkpoint;
mod edit;
mod lift;
mod receipt_actor;
pub(crate) use self::lift::{CodeDocumentRows, code_document_texts_in_txn};
use self::receipt_actor::ReceiptActor;
pub(crate) use self::receipt_actor::{erase_head_actor_in_txn, erase_ingress_actor_in_txn};

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

impl HeadRow {
    /// The head state's document, checked against its frontier.
    pub(super) fn doc(&self) -> Result<LoroDoc> {
        checked_snapshot(&self.state)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptRow {
    operation: String,
    session: String,
    actor: ReceiptActor,
    actor_class: u8,
    provenance: CodeOpProvenance,
    sequence: u64,
    pub(super) peer_id: u64,
    pub(super) counter_start: i32,
    pub(super) counter_end: i32,
    pub(super) edit: CodeFileEdit,
    /// The metadata change made with the text (G4 PR2); an ordinary text
    /// receipt has none and encodes as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) metadata_edit: Option<CodeFileMetadataEdit>,
    pub(super) before: CodeDocumentFrontier,
    pub(super) after: CodeDocumentFrontier,
}

/// The Loro commit message a document's birth commits with.
const BIRTH_STAMP: &str = "oneiron.code_document.birth.v1";
/// How a text operation's Loro commit message begins ([`op_stamp`]).
const TEXT_OP_STAMP: &str = "oneiron.code_document.v3";
/// How the Loro commit message of an operation with a metadata change begins.
const METADATA_OP_STAMP: &str = "oneiron.code_document.metadata.v1";

/// The Loro commit message of one operation. It binds the ingress identity,
/// edit and provenance into the document's operation fold. The actor stays on
/// the receipts, so an actor's erase leaves every fold whole (FIX 3520). An
/// operation with a metadata change binds the text edit and that change
/// together under its own domain (G4 PR2); a text edit keeps its stamp.
fn op_stamp(
    operation: &str,
    session: &str,
    peer_id: u64,
    counter_start: i32,
    edit: &CodeFileEdit,
    metadata: Option<&CodeFileMetadataEdit>,
    provenance: &CodeOpProvenance,
) -> Result<String> {
    let provenance = crate::entity_id::bytes_to_hex_lower(&hash(&encode(provenance)?));
    Ok(match metadata {
        None => format!(
            "{TEXT_OP_STAMP}:{operation}:{session}:{peer_id}:{counter_start}:{}:{provenance}",
            crate::entity_id::bytes_to_hex_lower(&hash(&encode(edit)?)),
        ),
        Some(metadata) => format!(
            "{METADATA_OP_STAMP}:{operation}:{session}:{peer_id}:{counter_start}:{}:{provenance}",
            crate::entity_id::bytes_to_hex_lower(&hash(&encode(&(edit, metadata))?)),
        ),
    })
}

/// A host-approved exact-base ingress item. Cooperative editor sessions use
/// the merging primitive instead; pushes and reviewed file replacements cannot
/// silently incorporate operations they did not test.
pub(crate) struct CodeFileIngress {
    pub operation: EntityId,
    pub session: CodeDocumentSession,
    pub edit: CodeFileEdit,
    /// A reviewed metadata change made with the edit (G4 PR2); `None` on
    /// every ordinary text ingress.
    pub metadata_edit: Option<CodeFileMetadataEdit>,
    pub actor: WriteActor,
    pub expected_text: String,
}

impl ReceiptRow {
    /// The actor, or none once that actor was erased (FIX 3520).
    fn actor(&self) -> Result<Option<WriteActor>> {
        let class = EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(invalid)?;
        Ok(self.actor.id().map(|id| WriteActor::new(id, class)))
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
            metadata_edit: self.metadata_edit.clone(),
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
        let document_id = code_document_genesis_id(repo, path, generation);
        let doc = LoroDoc::new();
        doc.set_peer_id(0).map_err(|_| invalid())?;
        doc.get_map("meta")
            .insert("path", path)
            .map_err(|_| invalid())?;
        doc.get_text("body")
            .insert(0, initial)
            .map_err(|_| invalid())?;
        doc.commit_with(CommitOptions::new().commit_msg(BIRTH_STAMP));
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
        self.code_file_edit_receipt_in_txn(&txn, operation)
    }
    /// [`Vault::code_file_edit_receipt`] in the caller's snapshot.
    pub(crate) fn code_file_edit_receipt_in_txn(
        &self,
        txn: &RoTxn<'_>,
        operation: EntityId,
    ) -> Result<Option<CodeEditReceipt>> {
        CODE_DOCUMENT_INGRESS
            .get(&self.store, txn, &operation)?
            .map(|row| row.receipt())
            .transpose()
    }

    /// Retained operations authored by one session, including documents it created.
    pub(crate) fn code_document_receipts_for_session_in_txn(
        &self,
        txn: &RoTxn<'_>,
        session: EntityId,
    ) -> Result<Vec<CodeEditReceipt>> {
        let session = session.to_hex();
        let mut receipts = Vec::new();
        for item in CODE_DOCUMENT_INGRESS.iter_from(&self.store, txn, &[])? {
            let (_, row) = item?;
            if row.session == session {
                receipts.push(row.receipt()?);
            }
        }
        Ok(receipts)
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
        self.apply_code_file_edit_once_with(operation, session, edit, None, actor)
    }

    /// [`Vault::apply_code_file_edit_once`]'s one body, with the metadata
    /// change a reviewed file operation makes beside its text, if any.
    pub(super) fn apply_code_file_edit_once_with(
        &self,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileEdit,
        metadata: Option<&CodeFileMetadataEdit>,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        let mut txn = self.store.env.write_txn()?;
        if let Some(row) = CODE_DOCUMENT_INGRESS.get(&self.store, &txn, &operation)? {
            let receipt = row.receipt()?;
            if receipt.document_id != session.document_id
                || receipt.session_id != session.session_id
                || receipt.actor != Some(actor)
                || receipt.provenance != session.provenance
                // A masked edit's receipt holds its handles, never the
                // value: a replay offering the value again is not proved the
                // same edit (a rotated custody record names a new value
                // under the same handle), so it refuses (FIX 2372).
                || receipt.edit != *edit
                || receipt.metadata_edit.as_ref() != metadata
            {
                return Err(invalid());
            }
            drop(txn);
            self.refresh_code_document(session)?;
            return Ok(receipt);
        }
        let old_doc = session.doc.clone();
        let result = (|| {
            let receipt = self
                .apply_code_file_edit_in_txn(&mut txn, operation, session, edit, metadata, actor)?;
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
                    || receipt.actor != Some(item.actor)
                    || receipt.provenance != item.session.provenance
                    || receipt.edit != item.edit
                    || receipt.metadata_edit != item.metadata_edit
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
                item.metadata_edit.as_ref(),
                item.actor,
            )?;
            receipts.push(receipt);
        }
        Ok(receipts)
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

    /// The BLAKE3 of each exact text the document state `tested` grew from,
    /// as the document's own retained history proves them (FIX 8967): the
    /// state before and after every operation `tested` holds whole, birth
    /// text first, each read from its stored, checked snapshot. No caller
    /// names a source, and `tested`'s own text is the caller's to hash.
    ///
    /// # Errors
    /// A store failure, or a stored state that does not check.
    pub(crate) fn code_document_source_hashes_in_txn(
        &self,
        txn: &RoTxn<'_>,
        tested: &CodeDocumentFrontier,
    ) -> Result<Vec<[u8; 32]>> {
        let Some(head) = load_head(&self.store, txn, &tested.document_id)? else {
            return Ok(Vec::new());
        };
        let mut states = std::collections::BTreeSet::from([tested.op_fold]);
        let mut hashes = Vec::new();
        for receipt in head
            .receipts
            .iter()
            .filter(|receipt| receipt.within(&tested.version))
        {
            for state in [&receipt.before, &receipt.after] {
                if !states.insert(state.op_fold) {
                    continue;
                }
                let text = load_frontier(&self.store, txn, state)?
                    .get_text("body")
                    .to_string();
                hashes.push(*blake3::hash(text.as_bytes()).as_bytes());
            }
        }
        Ok(hashes)
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
                    r.peer_id,
                    r.counter_start,
                    &r.edit,
                    r.metadata_edit.as_ref(),
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
/// The id of the document a file at `path` of `repo` is born as at
/// `generation`: what every not-yet-born session of it mints, so a file
/// nobody has edited still names the document its first op will birth.
pub(crate) fn code_document_genesis_id(repo: &str, path: &str, generation: u64) -> [u8; 32] {
    hash(&[path_key(repo, path).as_slice(), &generation.to_be_bytes()].concat())
}

/// The document a file at `path` of `repo` is, read in `txn` (ARCH-0050,
/// FIX 7809): the one living at that path, or the one the path's current
/// generation births. A rename keeps it; a removal and a recreation do not.
///
/// # Errors
/// A store failure.
pub(crate) fn code_document_identity_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    repo: &str,
    path: &str,
) -> Result<[u8; 32]> {
    if let Some(id) = CODE_DOCUMENT_PATH.get(store, txn, &path_hash(repo, path))? {
        return Ok(id);
    }
    Ok(code_document_genesis_id(
        repo,
        path,
        path_generation(store, txn, repo, path)?,
    ))
}

fn path_generation(store: &Store, txn: &RoTxn<'_>, repo: &str, path: &str) -> Result<u64> {
    Ok(CODE_DOCUMENT_GENERATION
        .get(store, txn, &generation_key(repo, path))?
        .unwrap_or(0))
}

/// OF-222 (FIX 2768) archive seam: the code-document history tables a whole-vault archive
/// carries (ingress receipts, tested frontiers, path and generation rows, heads), lent with
/// their own key types and codec.
pub(crate) fn archive_document_tables() -> [crate::batch::export::LentSideTable; 5] {
    [
        &CODE_DOCUMENT_INGRESS,
        &CODE_DOCUMENT_FRONTIER,
        &CODE_DOCUMENT_PATH,
        &CODE_DOCUMENT_GENERATION,
        &CODE_DOCUMENT_HEAD,
    ]
}

/// One code-document history table an archive carries, as it reads a row
/// of it ([`archive_document_row`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchivedDocumentTable {
    Ingress,
    Frontier,
    Path,
    Generation,
    Head,
}

/// What one stored code-document history row is of and names (fix list row
/// 15416), read through its table's own key type and codec.
pub(crate) struct ArchivedDocumentRow {
    /// The document the row is of; `None` for a generation row, which counts
    /// the documents born at one repo path.
    pub(crate) document: Option<[u8; 32]>,
    /// The generation key of each repo path the row's states stand at, or
    /// the one a generation row counts.
    pub(crate) paths: Vec<[u8; 32]>,
    /// Each session, actor, turn, activity, intent and model its receipts
    /// name, and each session an operation stamp in a snapshot it keeps
    /// names. An operation id names no row.
    pub(crate) rows: Vec<EntityId>,
}

/// The stored row `key` and `value` of `table` as an archive reads it: the
/// document it is of, the repo paths it stands at and the rows its history
/// was written from. An ingress receipt is of the document its after-state
/// is; a tested frontier, a head and a path row of the document they name.
/// `None` when the row, a receipt in it, a snapshot it keeps or an operation
/// stamp in one does not read.
pub(crate) fn archive_document_row(
    table: ArchivedDocumentTable,
    key: &[u8],
    value: &[u8],
) -> Option<ArchivedDocumentRow> {
    let stands_at = |state: &CodeDocumentFrontier| generation_key(&state.repo, &state.path);
    Some(match table {
        ArchivedDocumentTable::Ingress => {
            <EntityId as SideKey>::decode_key(key)?;
            let row = CODE_DOCUMENT_INGRESS.decode_value(value).ok()?;
            ArchivedDocumentRow {
                document: Some(row.after.document_id),
                paths: vec![stands_at(&row.before), stands_at(&row.after)],
                rows: receipt_rows(&row)?,
            }
        }
        ArchivedDocumentTable::Frontier => {
            let (document, _) = <([u8; 32], [u8; 32]) as SideKey>::decode_key(key)?;
            let row = CODE_DOCUMENT_FRONTIER.decode_value(value).ok()?;
            ArchivedDocumentRow {
                document: Some(document),
                paths: vec![stands_at(&row.frontier)],
                rows: snapshot_sessions(&row.snapshot)?,
            }
        }
        ArchivedDocumentTable::Path => {
            let path = <[u8; 32] as SideKey>::decode_key(key)?;
            ArchivedDocumentRow {
                document: Some(CODE_DOCUMENT_PATH.decode_value(value).ok()?),
                paths: vec![hash(&path_hash_key(&path))],
                rows: Vec::new(),
            }
        }
        ArchivedDocumentTable::Generation => {
            let path = <[u8; 32] as SideKey>::decode_key(key)?;
            CODE_DOCUMENT_GENERATION.decode_value(value).ok()?;
            ArchivedDocumentRow {
                document: None,
                paths: vec![path],
                rows: Vec::new(),
            }
        }
        ArchivedDocumentTable::Head => {
            let document = <[u8; 32] as SideKey>::decode_key(key)?;
            let row = CODE_DOCUMENT_HEAD.decode_value(value).ok()?;
            let mut paths = vec![stands_at(&row.state.frontier)];
            let mut rows = snapshot_sessions(&row.state.snapshot)?;
            for receipt in &row.receipts {
                paths.extend([stands_at(&receipt.before), stands_at(&receipt.after)]);
                rows.extend(receipt_rows(receipt)?);
            }
            ArchivedDocumentRow {
                document: Some(document),
                paths,
                rows,
            }
        }
    })
}

/// The rows one operation's receipt names: its session, its actor while not
/// erased, and the turn, activity, intent and model its provenance names.
/// `None` when its session does not read as an id.
fn receipt_rows(receipt: &ReceiptRow) -> Option<Vec<EntityId>> {
    let mut rows = vec![EntityId::from_hex(&receipt.session).ok()?];
    rows.extend(receipt.actor.id());
    let provenance = &receipt.provenance;
    rows.extend(
        [
            provenance.turn,
            provenance.activity,
            provenance.intent,
            provenance.substrate_ref,
        ]
        .into_iter()
        .flatten(),
    );
    Some(rows)
}

/// Each session an operation stamp in the Loro snapshot `snapshot` names,
/// read change by change from its own history: a birth names none. `None`
/// when the snapshot does not load, or a change has no stamp this document
/// writes.
fn snapshot_sessions(snapshot: &[u8]) -> Option<Vec<EntityId>> {
    let doc = doc_from_snapshot(snapshot).ok()?;
    let version: Vec<(u64, i32)> = doc
        .oplog_vv()
        .iter()
        .map(|(peer, end)| (*peer, *end))
        .collect();
    let mut sessions = Vec::new();
    for (peer, end) in version {
        let mut counter = 0;
        while counter < end {
            let change = doc.get_change(loro::ID::new(peer, counter))?;
            let message = change.message.as_deref()?;
            if message != BIRTH_STAMP {
                let stamp = message
                    .strip_prefix(TEXT_OP_STAMP)
                    .or_else(|| message.strip_prefix(METADATA_OP_STAMP))?
                    .strip_prefix(':')?;
                let session = stamp.split(':').nth(1)?;
                sessions.push(EntityId::from_hex(session).ok()?);
            }
            let next = change
                .id
                .counter
                .checked_add(i32::try_from(change.len).ok()?)?;
            if next <= counter {
                return None;
            }
            counter = next;
        }
    }
    Some(sessions)
}
