//! Each stored code-document history row as an archive reads it (fix list
//! row 15416): the document it is of, the repo paths it stands at and the
//! rows its history was written from, through its table's own key type and
//! codec.

use super::{
    BIRTH_STAMP, CODE_DOCUMENT_FRONTIER, CODE_DOCUMENT_GENERATION, CODE_DOCUMENT_HEAD,
    CODE_DOCUMENT_INGRESS, CODE_DOCUMENT_PATH, METADATA_OP_STAMP, ReceiptRow, TEXT_OP_STAMP,
    generation_key,
};
use crate::code_document::CodeDocumentFrontier;
use crate::code_document::codec::{doc_from_snapshot, hash, path_hash_key};
use crate::entity_id::EntityId;
use crate::side_table::SideKey;

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
