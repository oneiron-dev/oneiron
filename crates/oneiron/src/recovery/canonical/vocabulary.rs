//! CRDT-independent canonical snapshot values and document history vocabulary.
//! The entry type is `CanonicalSnapshot`.
//! `super` owns scope-sensitive operations and forwards these definitions.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntity {
    pub id: [u8; 16],
    /// The exact 25-byte envelope followed by the original binary body.
    pub blob: Vec<u8>,
}

/// A source edge, never an edges_in row, vector or retrieval posting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBaseEdge {
    pub source: [u8; 16],
    pub kind: u8,
    pub target: [u8; 16],
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTombstone {
    pub id: [u8; 16],
    pub deleted_at: u64,
    /// Pinned Oneiron tombstone binary, independent of CRDT operation encoding.
    pub value: Vec<u8>,
}

/// Current generic EntityDoc value, independent of the document's Loro op log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocument {
    pub entity_id: [u8; 16],
    pub document_id: [u8; 16],
    /// None is a UTF-8 body; Some is the document's MessagePack body field.
    pub field: Option<String>,
    pub text: String,
    /// Editable fields, each encoded as one MessagePack value.
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// A scope summary's typed purpose and derivation, as its meta map holds
    /// them; never editable fields (FIX 756).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary_meta: BTreeMap<String, Vec<u8>>,
    /// Native record fields projected by the immutable adapter at birth.
    pub record_fields: Vec<String>,
    /// The stamp token the birth names, as stored (FIX 11964); None once the
    /// birth named no one (FIX 6072): it stays no one.
    pub birth_actor: Option<[u8; 16]>,
    pub birth_at: u64,
    /// The document's causal state, by value. Absent for a document with no
    /// fork, pin, receipt or purge: that one is its current value alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<CanonicalEntityDocumentHistory>,
}

/// The causal state of a generic EntityDoc, CRDT-independent: the retained
/// versions its citations, receipts, forks and purges name, never Loro
/// frontiers, cursors or exports. A restore replays the versions into fresh
/// history and binds every row to its replayed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocumentHistory {
    /// Retained versions in canonical causal order. Every version precedes
    /// the last, which is the live head.
    pub versions: Vec<CanonicalDocumentVersion>,
    /// An owner purge dropped the history before version 0: none is carried,
    /// and the restored document refuses every older version.
    pub shallow: bool,
    pub pins: Vec<CanonicalDocumentPin>,
    pub receipts: Vec<CanonicalDocumentReceipt>,
    pub forks: Vec<CanonicalDocumentFork>,
    pub purges: Vec<CanonicalDocumentPurge>,
}

/// One retained version: the earlier versions it directly follows, and its
/// text as one splice of its first parent's text (of the empty text for a
/// version with no parent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentVersion {
    pub parents: Vec<u32>,
    /// Characters kept from the start of the first parent's text.
    pub prefix: u32,
    /// Characters kept from its end.
    pub suffix: u32,
    pub middle: String,
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// A scope summary's purpose and derivation at this version (FIX 756).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary_meta: BTreeMap<String, Vec<u8>>,
}

/// An immutable citation pin: the quoted span of one version, in characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPin {
    pub citation: [u8; 16],
    pub document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub version: u32,
    pub start: u32,
    pub end: u32,
    pub quote: String,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalSettleVerb {
    Merge,
    Switch,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}

/// A settlement or direct-update receipt between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentReceipt {
    pub receipt: [u8; 16],
    pub proposal: [u8; 16],
    pub fork: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub verb: CanonicalSettleVerb,
    pub at: u64,
    pub before: u32,
    pub after: u32,
    pub read_refs: Vec<[u8; 16]>,
}

/// A fork and its place in its proposal bundle, which the snapshot carries
/// whole or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentFork {
    pub fork: [u8; 16],
    pub proposal: [u8; 16],
    pub parent_document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub opened_at: u64,
    pub rewrite: bool,
    pub status: CanonicalForkStatus,
    /// None only for a settled fork whose base a purge dropped.
    pub base: Option<u32>,
    /// The retained output text of a pending fork.
    pub output: Option<String>,
    pub output_metadata: Option<BTreeMap<String, Vec<u8>>>,
    /// Its place in its bundle, and the bundle's size: no count bounds a
    /// bundle (Rule 5, FIX 8822).
    pub proposal_index: u64,
    pub proposal_len: u64,
    pub proposal_settled: bool,
    /// The credential lineage its bundle froze as it opened (FIX 10931).
    pub proposal_opener_lineage: Vec<[u8; 32]>,
    pub read_refs: Vec<[u8; 16]>,
    pub keep: Option<String>,
}

/// Durable proof of one owner purge, bound to the versions it named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPurge {
    pub receipt: [u8; 16],
    pub document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub requested: u32,
    pub applied: u32,
    pub at: u64,
    pub live_text_hash: [u8; 32],
}

impl CanonicalEntityDocumentHistory {
    /// Every version's full text, rebuilt from its splice, in version order.
    pub fn texts(&self) -> Result<Vec<String>> {
        let mut texts: Vec<String> = Vec::with_capacity(self.versions.len());
        for (index, version) in self.versions.iter().enumerate() {
            let base: Vec<char> = match version.parents.first() {
                None => Vec::new(),
                Some(&parent) => {
                    let parent = parent as usize;
                    if parent >= index {
                        return Err(invalid("entity document version parent"));
                    }
                    texts[parent].chars().collect()
                }
            };
            let prefix = version.prefix as usize;
            let suffix = version.suffix as usize;
            if prefix
                .checked_add(suffix)
                .is_none_or(|kept| kept > base.len())
            {
                return Err(invalid("entity document version splice"));
            }
            let mut text: String = base[..prefix].iter().collect();
            text.push_str(&version.middle);
            text.extend(&base[base.len() - suffix..]);
            texts.push(text);
        }
        Ok(texts)
    }

    /// The splice that turns `parent` into `text`: the longest common prefix,
    /// then the longest common suffix of what remains.
    pub fn splice(parent: &str, text: &str) -> Result<CanonicalDocumentVersion> {
        let old: Vec<char> = parent.chars().collect();
        let new: Vec<char> = text.chars().collect();
        let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Ok(CanonicalDocumentVersion {
            parents: Vec::new(),
            prefix: u32::try_from(prefix).map_err(|_| invalid("entity document version size"))?,
            suffix: u32::try_from(suffix).map_err(|_| invalid("entity document version size"))?,
            middle: new[prefix..new.len() - suffix].iter().collect(),
            metadata: BTreeMap::new(),
            summary_meta: BTreeMap::new(),
        })
    }
}

/// World proof retained when a soft-deleted CLAIM has only its header left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalShellWorld {
    pub id: [u8; 16],
    pub world: [u8; 16],
}

/// One room turn row a base window carries (OF-522), kept as the window holds
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRoomTurn {
    pub id: [u8; 16],
    pub row: Vec<u8>,
}

/// One room side row a base window carries (FIX 1794), under its map key,
/// kept as the window holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRoomFact {
    pub key: String,
    pub row: Vec<u8>,
}

/// One document quote pin a base window carries (FIX 853), under its map
/// key, kept as the window holds it. A pin on a document the snapshot
/// captures rides in that document's history instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPinCarrier {
    pub key: String,
    pub row: Vec<u8>,
}

/// One owner-signed custody transition piece a base window carries
/// (OF-422): opaque signed and sealed bytes, kept as the window holds them,
/// with its place among its transition's pieces (Phase2 A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCustodyTransition {
    pub id: [u8; 16],
    #[serde(default)]
    pub piece: u32,
    pub carrier: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalContainerManifest {
    pub container_id: String,
    pub container_kind: String,
    pub schema_version: u16,
    pub source_entity_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSchemaManifest {
    pub oneiron_schema_version: u16,
    /// Informational producer version. Rebuild does not import its binary format.
    pub loro_version: String,
    pub container_schema_version: u16,
    pub analyzer_manifest_blake3: [u8; 32],
}

/// Ordered source state. No op IDs, Loro exports, or Layer-2 indexes are encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSnapshot {
    pub window: String,
    pub entity_blobs: Vec<CanonicalEntity>,
    pub retained_claim_worlds: Vec<CanonicalShellWorld>,
    pub base_edges: Vec<CanonicalBaseEdge>,
    pub tombstones: Vec<CanonicalTombstone>,
    pub doc_snapshots: Vec<CanonicalDocument>,
    pub entity_documents: Vec<CanonicalEntityDocument>,
    pub document_heads: Vec<CanonicalHead>,
    pub head_move_receipts: Vec<CanonicalHeadMove>,
    /// Durable workflows, with value-based merge bases instead of old frontiers.
    pub note_forks: Vec<crate::note::NoteFork>,
    pub note_proposals: Vec<crate::note::NoteReviewBundle>,
    pub container_manifests: Vec<CanonicalContainerManifest>,
    pub schema_manifest: CanonicalSchemaManifest,
    /// The window's TASKs one of whose authority facts the source refused,
    /// the fact's id having been deleted there first. The fact's body never
    /// reached the store, so this alone names the task, and its facts read
    /// as a refusal wherever the window is recovered. Absent when empty, so
    /// an artifact with none encodes as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed_tasks: Vec<[u8; 16]>,
    /// The base window's custody transitions (OF-422), by record id. Absent
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custody_transitions: Vec<CanonicalCustodyTransition>,
    /// The base window's room turn rows (OF-522), by turn id. Absent when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub room_turns: Vec<CanonicalRoomTurn>,
    /// The base window's room side rows (FIX 1794), by map key. Absent when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub room_facts: Vec<CanonicalRoomFact>,
    /// The base window's document quote pins (FIX 853) on documents it does
    /// not capture, by map key. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_pins: Vec<CanonicalPinCarrier>,
    /// The window's peer origins (FIX 4550), by row id, each naming its
    /// row's exact blob. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_origins: Vec<CanonicalPeerOrigin>,
    /// The final rows' births (FIX 3069), by row id: the window's carrier,
    /// else the birth stamped here. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_births: Vec<CanonicalRowBirth>,
    /// The window's withdrawal fences and session epoch floors (FIX 8820),
    /// by map key. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withdrawn_cutoffs: Vec<CanonicalCutoff>,
    /// The window's by-reference ASSET body references (FIX 5489), by owner
    /// id, each binding the exact carrier `entity_blobs` holds for it.
    /// Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_body_refs: Vec<CanonicalAssetBodyRef>,
}
