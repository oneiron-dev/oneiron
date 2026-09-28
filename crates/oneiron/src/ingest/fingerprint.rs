//! Entity-local four-rung birth fingerprints over the ingest pipeline's own segments.
use super::{DocsSegment, docs_semantic_segments};
use crate::error::Error;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintRung {
    Asset,
    TextRoot,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobBirthDecision {
    Unchanged(FingerprintRung),
    Changed {
        sections: Vec<String>,
        blocks: Vec<String>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFingerprintSnapshot {
    pub asset_hash: [u8; 32],
    pub text_hash: [u8; 32],
    pub sections: BTreeMap<String, [u8; 32]>,
    pub blocks: BTreeMap<String, [u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Block {
    hash: [u8; 32],
    text: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Section {
    hash: [u8; 32],
    blocks: BTreeMap<String, Block>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Tree {
    asset_hash: [u8; 32],
    text_hash: [u8; 32],
    sections: BTreeMap<String, Section>,
}
pub(crate) struct FingerprintUpdate {
    tree: Tree,
    pub(crate) decision: BlobBirthDecision,
}

/// Blob birth fingerprint tree. Key: the entity id.
const FINGERPRINT: SideTable<EntityId, Tree, LegacyJson> =
    SideTable::new(&side_table::INGEST_FINGERPRINT);

pub(crate) fn invalidate_blob_fingerprint(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    FINGERPRINT.delete(store, txn, id)?;
    Ok(())
}
fn load(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<Tree>> {
    FINGERPRINT.get(store, txn, id)
}
impl FingerprintUpdate {
    pub(crate) fn persist(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        let data = FINGERPRINT.encode_value(&self.tree)?;
        crate::batch::secret_scan::scan_metadata_field(
            std::str::from_utf8(&data)
                .map_err(|_| Error::InvariantViolation("fingerprint JSON encoding"))?,
        )?;
        FINGERPRINT.put(store, txn, id, &self.tree)?;
        Ok(())
    }
}
pub(super) fn prepare_blob_birth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
    text: &str,
) -> Result<FingerprintUpdate> {
    Ok(calculate(load(store, txn, id)?, bytes, text))
}
/// Binary blobs have no invented text segmentation. Their lower rungs stay
/// empty until a real text adapter supplies text; exact bytes still deduplicate.
pub(crate) fn prepare_blob_artifact_birth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) -> Result<FingerprintUpdate> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return prepare_blob_birth(store, txn, id, bytes, text);
    }
    let asset_hash = *blake3::hash(bytes).as_bytes();
    let decision = if load(store, txn, id)?.is_some_and(|tree| tree.asset_hash == asset_hash) {
        BlobBirthDecision::Unchanged(FingerprintRung::Asset)
    } else {
        BlobBirthDecision::Changed {
            sections: Vec::new(),
            blocks: Vec::new(),
        }
    };
    Ok(FingerprintUpdate {
        tree: Tree {
            asset_hash,
            text_hash: asset_hash,
            sections: BTreeMap::new(),
        },
        decision,
    })
}
pub(super) fn prepare_new_blob_birth(bytes: &[u8], text: &str) -> FingerprintUpdate {
    calculate(None, bytes, text)
}
fn calculate(previous: Option<Tree>, bytes: &[u8], text: &str) -> FingerprintUpdate {
    let asset_hash = *blake3::hash(bytes).as_bytes();
    if let Some(tree) = previous
        .as_ref()
        .filter(|tree| tree.asset_hash == asset_hash)
    {
        return FingerprintUpdate {
            tree: tree.clone(),
            decision: BlobBirthDecision::Unchanged(FingerprintRung::Asset),
        };
    }
    // Only transport changes collapse: BOM and CRLF. Never case, words or layout.
    let normalized = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let text_hash = *blake3::hash(normalized.as_bytes()).as_bytes();
    if let Some(tree) = previous.as_ref().filter(|tree| tree.text_hash == text_hash) {
        return FingerprintUpdate {
            tree: Tree {
                asset_hash,
                ..tree.clone()
            },
            decision: BlobBirthDecision::Unchanged(FingerprintRung::TextRoot),
        };
    }
    let mut grouped = BTreeMap::<String, Vec<DocsSegment>>::new();
    for segment in docs_semantic_segments(&normalized) {
        grouped
            .entry(segment.section.clone())
            .or_default()
            .push(segment);
    }
    let mut sections = BTreeMap::new();
    let mut changed_sections = Vec::new();
    let mut changed_blocks = Vec::new();
    for (number, segments) in grouped {
        let mut h = blake3::Hasher::new();
        for segment in &segments {
            h.update(&(segment.block.len() as u64).to_be_bytes());
            h.update(segment.block.as_bytes());
            h.update(&(segment.text.len() as u64).to_be_bytes());
            h.update(segment.text.as_bytes());
        }
        let hash = *h.finalize().as_bytes();
        let old = previous
            .as_ref()
            .and_then(|tree| tree.sections.get(&number));
        if let Some(section) = old.filter(|s| s.hash == hash) {
            sections.insert(number, section.clone());
            continue;
        }
        changed_sections.push(number.clone());
        let mut blocks = BTreeMap::new();
        for segment in segments {
            // Keep exact old segment bytes beside its hash. An unchanged block is
            // compared, not re-hashed, even within a changed section.
            let block = match old
                .and_then(|s| s.blocks.get(&segment.block))
                .filter(|b| b.text == segment.text)
            {
                Some(block) => block.clone(),
                None => {
                    changed_blocks.push(segment.block.clone());
                    Block {
                        hash: *blake3::hash(segment.text.as_bytes()).as_bytes(),
                        text: segment.text,
                    }
                }
            };
            blocks.insert(segment.block, block);
        }
        sections.insert(number, Section { hash, blocks });
    }
    FingerprintUpdate {
        tree: Tree {
            asset_hash,
            text_hash,
            sections,
        },
        decision: BlobBirthDecision::Changed {
            sections: changed_sections,
            blocks: changed_blocks,
        },
    }
}
impl Vault {
    /// The tree is scoped to one entity, not a vault-wide identity/dedup oracle.
    pub fn blob_fingerprint(&self, id: &EntityId) -> Result<Option<BlobFingerprintSnapshot>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            load(&self.store, &txn, id)?.map(|tree| BlobFingerprintSnapshot {
                asset_hash: tree.asset_hash,
                text_hash: tree.text_hash,
                sections: tree
                    .sections
                    .iter()
                    .map(|(id, s)| (id.clone(), s.hash))
                    .collect(),
                blocks: tree
                    .sections
                    .values()
                    .flat_map(|s| s.blocks.iter().map(|(id, b)| (id.clone(), b.hash)))
                    .collect(),
            }),
        )
    }
}
