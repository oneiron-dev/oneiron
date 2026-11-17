//! The checkpoint-pins door's code document writers (UC-10 PR 5): head,
//! tested-frontier, ingress and path rows put from fixed values. Compiled
//! only under `--cfg oneiron_test_support`; never API.

use super::*;

/// One receipt's fixed fields for the checkpoint-pins door: a [`ReceiptRow`]
/// as plain values, an erased actor as `None`.
pub(crate) struct PinsCodeDocumentReceipt {
    /// The operation's hex id, which names the head receipt's actor part.
    pub operation: String,
    /// The session's hex id.
    pub session: String,
    /// The receipt's actor; `None` names no one, as the erase leaves it.
    pub actor: Option<EntityId>,
    /// The actor's class byte.
    pub actor_class: u8,
    /// The operation's provenance.
    pub provenance: CodeOpProvenance,
    /// The receipt's sequence in its head.
    pub sequence: u64,
    /// The operation's Loro peer.
    pub peer_id: u64,
    /// The operation's starting counter.
    pub counter_start: i32,
    /// The operation's ending counter.
    pub counter_end: i32,
    /// The text edit the operation made.
    pub edit: CodeFileEdit,
    /// The metadata change made with the text, if any.
    pub metadata_edit: Option<CodeFileMetadataEdit>,
    /// The frontier before the operation.
    pub before: CodeDocumentFrontier,
    /// The frontier after the operation.
    pub after: CodeDocumentFrontier,
}

/// A pins receipt as the stored row, with no custody bindings.
fn pins_receipt_row(receipt: &PinsCodeDocumentReceipt) -> ReceiptRow {
    ReceiptRow {
        operation: receipt.operation.clone(),
        session: receipt.session.clone(),
        actor: receipt
            .actor
            .map_or(ReceiptActor::Erased, ReceiptActor::Actor),
        actor_class: receipt.actor_class,
        provenance: receipt.provenance.clone(),
        sequence: receipt.sequence,
        peer_id: receipt.peer_id,
        counter_start: receipt.counter_start,
        counter_end: receipt.counter_end,
        edit: receipt.edit.clone(),
        metadata_edit: receipt.metadata_edit.clone(),
        before: receipt.before.clone(),
        after: receipt.after.clone(),
        custody: Vec::new(),
    }
}

/// Puts a head row for the checkpoint-pins door: `key`'s document with
/// `frontier`'s state, `snapshot`'s bytes and `receipts`' history.
pub(crate) fn put_pins_code_document_head_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut RwTxn<'_>,
    key: &[u8; 32],
    initial_hash: &[u8; 32],
    frontier: &CodeDocumentFrontier,
    snapshot: &[u8],
    receipts: &[PinsCodeDocumentReceipt],
) -> Result<()> {
    CODE_DOCUMENT_HEAD.put(
        store,
        txn,
        key,
        &HeadRow {
            initial_hash: *initial_hash,
            state: SnapshotRow {
                frontier: frontier.clone(),
                snapshot: snapshot.to_vec(),
            },
            receipts: receipts.iter().map(pins_receipt_row).collect(),
        },
    )
}

/// Puts a tested-frontier row for the checkpoint-pins door: `key`'s
/// snapshot of `frontier`'s state in `snapshot`'s bytes.
pub(crate) fn put_pins_code_document_frontier_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut RwTxn<'_>,
    key: &([u8; 32], [u8; 32]),
    frontier: &CodeDocumentFrontier,
    snapshot: &[u8],
) -> Result<()> {
    CODE_DOCUMENT_FRONTIER.put(
        store,
        txn,
        key,
        &SnapshotRow {
            frontier: frontier.clone(),
            snapshot: snapshot.to_vec(),
        },
    )
}

/// Puts an ingress receipt for the checkpoint-pins door: `key`'s operation
/// as `receipt` reads it.
pub(crate) fn put_pins_code_document_ingress_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut RwTxn<'_>,
    key: &EntityId,
    receipt: &PinsCodeDocumentReceipt,
) -> Result<()> {
    CODE_DOCUMENT_INGRESS.put(store, txn, key, &pins_receipt_row(receipt))
}

/// Puts a path row for the checkpoint-pins door: `repo`'s `path` living as
/// `document`, keyed as the writer keys it.
pub(crate) fn put_pins_code_document_path_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut RwTxn<'_>,
    repo: &str,
    path: &str,
    document: &[u8; 32],
) -> Result<()> {
    CODE_DOCUMENT_PATH.put(store, txn, &path_hash(repo, path), document)
}
