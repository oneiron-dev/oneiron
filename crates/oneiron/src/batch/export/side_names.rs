//! What each side row an Owner's copy would carry names, read through its
//! family's own codec and the codec of every typed record inside it (fix list
//! row 15416), and how such a copy holds rows out by it: a row naming an
//! entity the copy leaves out goes nowhere, with its record's rows of its
//! group, and a code document's history goes whole or not at all
//! ([`super::archive_side_tables::archive_side_rows_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};

use super::archive_side_tables::{ArchiveSideFamily, Group, Travel, array_at, id_at, lent};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;

impl Travel {
    /// Whether a row that travels so can go: with a record in `included`, or
    /// as a vault-wide row where those go (`vault`).
    pub(super) fn goes(&self, included: &BTreeSet<EntityId>, vault: bool) -> bool {
        match self {
            Self::With(owner, _) => included.contains(owner),
            Self::Vault => vault,
            Self::Broken(_) | Self::Orphan => false,
        }
    }

    /// Where a row goes that names an entity an Owner's copy leaves out (fix
    /// list row 15416): nowhere, and its record's rows of its group with it.
    pub(super) fn left_out(self) -> Self {
        match self {
            Self::With(owner, _) | Self::Broken(owner) => Self::Broken(owner),
            Self::Vault | Self::Orphan => Self::Orphan,
        }
    }
}

/// What a stored row of one family names as an Owner's copy reads it (fix list
/// row 15416), through its table's own key type and codec and the codec of
/// every typed record inside it: never a value guessed to be an id.
pub(super) struct SideNames {
    /// The code document a code-document history row is of, as its key or
    /// value names it; `None` for every other row and for a generation row.
    document: Option<[u8; 32]>,
    /// The generation key of each repo path a code-document row's states
    /// stand at, or the one a generation row counts.
    paths: Vec<[u8; 32]>,
    /// Each entity row it names; `None` when the row, or a record inside it,
    /// does not read.
    pub(super) rows: Option<Vec<EntityId>>,
}

impl SideNames {
    fn of(rows: Option<Vec<EntityId>>) -> Self {
        Self {
            document: None,
            paths: Vec::new(),
            rows,
        }
    }
}

/// What the stored row `key` and `value` of `family` names (fix list row
/// 15416), read through its table's own key type and codec, then through the
/// codec of each typed record inside it:
///
/// - a blob version and head: the artifact, the version's ledger claim, each
///   made_by input, its process's actor and a task, ask or skill trigger; a
///   born-from row: the artifact and a task, ask or skill source; a
///   settlement: the artifact and the rows its record names
///   ([`crate::edit_settle::archive_settlement_rows`]); every other blob row:
///   its artifact;
/// - an LFS chunk mark, manifest row and object: their ASSET; an upload
///   owner, a repo key, an object id and a ref name are no rows;
/// - a codebase snapshot and its indexes: the snapshot's CODE_ARTIFACT; its
///   custody report names paths only;
/// - a code revision's record, integrity fold, stranded proposal (the
///   revision encoded inside it read through the revision's own codec),
///   promotion, fork and frontier: the rows
///   [`crate::code_revision::archive_revision_rows`] reads; its session,
///   parent and fork indexes: both ids of their key;
/// - a code document's ingress receipt, tested snapshot, path, generation and
///   head: the document, the repo paths it stands at, and the sessions,
///   actors, turns, activities, intents and models its receipts and the
///   operation stamps of its Loro snapshots name
///   ([`crate::code_document::archive_document_row`]);
/// - a code symbol's memory: the symbol, a binding's NOTE or CLAIM payload,
///   and each payload, actor, provenance claim and symbol its value's codec
///   holds.
pub(super) fn side_names(family: ArchiveSideFamily, key: &[u8], value: &[u8]) -> Result<SideNames> {
    use crate::code_document::ArchivedDocumentTable as D;
    use crate::code_revision::ArchivedRevisionTable as R;
    use ArchiveSideFamily as F;
    let canonical = lent(family)?.canonical(key, value);
    let ids =
        |at: &[usize]| -> Option<Vec<EntityId>> { at.iter().map(|at| id_at(key, *at)).collect() };
    let with = |at: &[usize], rows: Option<Vec<EntityId>>| -> Option<Vec<EntityId>> {
        let mut named = ids(at)?;
        named.extend(rows?);
        Some(named)
    };
    let tail = key.len().saturating_sub(ENTITY_ID_LEN);
    let document = |table: D| match crate::code_document::archive_document_row(table, key, value) {
        Some(row) if canonical => SideNames {
            document: row.document,
            paths: row.paths,
            rows: Some(row.rows),
        },
        // A history row that does not read is still of the document its key
        // names, where its key names one.
        Some(_) | None => SideNames {
            document: matches!(table, D::Frontier | D::Head)
                .then(|| array_at::<32>(key, 0))
                .flatten(),
            paths: Vec::new(),
            rows: None,
        },
    };
    if !canonical && !matches!(family.spec().group, Group::CodeDocument) {
        return Ok(SideNames::of(None));
    }
    Ok(match family {
        F::BlobVersion | F::BlobHead => SideNames::of(with(
            &[0],
            crate::blob_artifact::archive_version_rows(value),
        )),
        F::BlobBornFrom => SideNames::of(crate::blob_artifact::archive_born_from_rows(key, value)),
        F::BlobSettlement => SideNames::of(with(
            &[0],
            crate::edit_settle::archive_settlement_rows(value),
        )),
        F::BlobDeckMarks | F::BlobHighwater | F::BlobClaimedHash => SideNames::of(ids(&[0])),
        F::BlobAssetRef | F::BlobVersionClaim => SideNames::of(ids(&[32])),
        F::LfsChunkMark | F::LfsManifest | F::CodebaseSnapshot => SideNames::of(ids(&[0])),
        F::LfsObject => SideNames::of(id_at(value, 0).map(|asset| vec![asset])),
        F::LfsOwnerRef | F::LfsChunkRef | F::LfsRef | F::LfsDeleted | F::LfsCdc => {
            SideNames::of(Some(Vec::new()))
        }
        F::CodebaseCustody => SideNames::of(Some(Vec::new())),
        F::CodebaseRepo | F::CodebaseProject | F::CodebaseFork | F::CodebaseScope => {
            SideNames::of(ids(&[tail]))
        }
        F::CodeRevisionRecord => SideNames::of(crate::code_revision::archive_revision_rows(
            R::Record,
            value,
        )),
        F::CodeRevisionIntegrity => SideNames::of(crate::code_revision::archive_revision_rows(
            R::Integrity,
            value,
        )),
        F::CodeRevisionProposal => SideNames::of(with(
            &[0],
            crate::code_revision::archive_revision_rows(R::Proposal, value),
        )),
        F::CodeRevisionPromotion => SideNames::of(with(
            &[0],
            crate::code_revision::archive_revision_rows(R::Promotion, value),
        )),
        F::CodeRevisionFork => {
            SideNames::of(crate::code_revision::archive_revision_rows(R::Fork, value))
        }
        F::CodeRevisionFrontier => SideNames::of(crate::code_revision::archive_revision_rows(
            R::Frontier,
            value,
        )),
        F::CodeRevisionSession | F::CodeRevisionParent | F::CodeRevisionForkParent => {
            SideNames::of(ids(&[0, ENTITY_ID_LEN]))
        }
        F::CodeDocumentIngress => document(D::Ingress),
        F::CodeDocumentFrontier => document(D::Frontier),
        F::CodeDocumentPath => document(D::Path),
        F::CodeDocumentGeneration => document(D::Generation),
        F::CodeDocumentHead => document(D::Head),
        F::CodeMemorySlot => SideNames::of(with(&[0], code_memory_rows(family, value))),
        F::CodeMemoryAttachment | F::CodeMemoryAlwaysOn => {
            SideNames::of(with(&[0, tail], code_memory_rows(family, value)))
        }
        F::CodeMemoryTransfer => {
            SideNames::of(with(&[0, ENTITY_ID_LEN], code_memory_rows(family, value)))
        }
    })
}

/// Every entity a code-memory value names, read through its table's own codec:
/// a value's payload, actor and provenance claim, and a contract's or a
/// transfer's symbols. `None` when the value does not read.
fn code_memory_rows(family: ArchiveSideFamily, value: &[u8]) -> Option<Vec<EntityId>> {
    use crate::store::code_memory_values as memory;
    match family {
        ArchiveSideFamily::CodeMemorySlot => memory::decode_slot(value).ok().map(|slot| {
            slot.values
                .iter()
                .flat_map(|entry| {
                    [
                        entry.payload.entity_id(),
                        entry.actor_id,
                        entry.provenance_claim_id,
                    ]
                })
                .collect()
        }),
        ArchiveSideFamily::CodeMemoryAttachment => memory::decode_attachment_row(value)
            .ok()
            .map(|(_, claim)| vec![claim]),
        ArchiveSideFamily::CodeMemoryAlwaysOn => {
            memory::decode_always_on(value).ok().map(|contract| {
                vec![
                    contract.symbol_id,
                    contract.payload.entity_id(),
                    contract.actor_id,
                    contract.provenance_claim_id,
                ]
            })
        }
        ArchiveSideFamily::CodeMemoryTransfer => {
            memory::decode_transfer_record(value).ok().map(|record| {
                vec![
                    record.from_symbol_id,
                    record.to_symbol_id,
                    record.actor_id,
                    record.provenance_claim_id,
                ]
            })
        }
        _ => None,
    }
}

/// The code documents an Owner's copy holds out whole (fix list row 15416),
/// from what each of their rows names as its pass judged it.
#[derive(Default)]
pub(super) struct DocumentHistories {
    /// Each document one of whose rows names a row the copy leaves out, or
    /// does not read.
    broken: BTreeSet<[u8; 32]>,
    /// The documents that stood at each repo path, by its generation key.
    at_path: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
}

impl DocumentHistories {
    pub(super) fn of(judged: &[Option<(SideNames, bool)>]) -> Self {
        let mut histories = Self::default();
        for (names, carried) in judged.iter().flatten() {
            let Some(document) = names.document else {
                continue;
            };
            if !*carried {
                histories.broken.insert(document);
            }
            for path in &names.paths {
                histories.at_path.entry(*path).or_default().insert(document);
            }
        }
        histories
    }

    /// The documents held out whole that a row naming `names` belongs to:
    /// its own, or for a generation row each one that stood at its path.
    pub(super) fn held(&self, names: &SideNames) -> Vec<[u8; 32]> {
        match names.document {
            Some(document) => self
                .broken
                .contains(&document)
                .then_some(document)
                .into_iter()
                .collect(),
            None => names
                .paths
                .iter()
                .filter_map(|path| self.at_path.get(path))
                .flatten()
                .filter(|document| self.broken.contains(*document))
                .copied()
                .collect(),
        }
    }
}
