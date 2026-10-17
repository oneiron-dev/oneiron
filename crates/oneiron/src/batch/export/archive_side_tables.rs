//! OF-222 (FIX 2768): the side tables a whole-vault archive carries beside the
//! records they index. The binary carriers travel as files; without these rows
//! an import holds the bytes and no index resolves them: an LFS object, a blob
//! version, a codebase snapshot, a code revision or a code document's history.
//! One explicit allowlist names each table, its key layout and its value form.
//! No other row travels: the recovery classes grant nothing here, and the LFS
//! upload journal and GC queue are in-flight work that never leaves.
//!
//! A row goes out with the record it belongs to and every carrier it names, read
//! in the export's snapshot, and a record's rows of one family go together or
//! not at all. A vault-wide row (an LFS tombstone or boundary seed, a code
//! document's history) goes only to a caller on this device: no world scopes it.
//! Each value goes in its table's own codec, typed: ids and hashes as hex, text
//! as text for the document's credential pass, and a long binary value as an
//! archive file, byte for byte. An import reads each row back through its
//! table's own key type and codec, checks the record and carriers it names, and
//! restores it in the import's write transaction once the entities are in:
//! records first, then indexes, then heads. An identical live row is unchanged;
//! any other refuses the import.
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::document_import::parse_id;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::serialize::ExportBodyFile;
use crate::side_table::{self, SideCodec, SideKey, SideTable, SideTableDecl};
use crate::store::Store;

/// A binary value or byte array longer than this goes in the archive's `files/`
/// as it is stored; ids, hashes and folds stay inline as hex.
const SIDE_INLINE_BYTES: usize = 64;

/// A side table its owning module lends the archive.
pub(crate) type LentSideTable = &'static dyn PortableSideTable;

/// A stored side table as the archive reads and restores it. The owning module
/// lends its typed table; the key type and codec stay the table's own.
pub(crate) trait PortableSideTable: Sync {
    fn decl(&self) -> &'static SideTableDecl;

    /// Every row: the key after the table's prefix, and the stored value.
    fn stored_rows(&self, store: &Store, rtxn: &RoTxn<'_>) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Whether the key and value read through the table's key type and codec,
    /// and the codec writes these very bytes back.
    fn canonical(&self, key: &[u8], value: &[u8]) -> bool;

    /// The stored value under `key`, when one is.
    fn stored(&self, store: &Store, txn: &RoTxn<'_>, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Writes one row through the table.
    fn restore(&self, store: &Store, wtxn: &mut RwTxn<'_>, key: &[u8], value: &[u8]) -> Result<()>;
}

impl<K: SideKey, V, C: SideCodec<V>> PortableSideTable for SideTable<K, V, C> {
    fn decl(&self) -> &'static SideTableDecl {
        SideTable::decl(self)
    }

    fn stored_rows(&self, store: &Store, rtxn: &RoTxn<'_>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.iter_raw_from(store, rtxn, &[])?.collect()
    }

    fn canonical(&self, key: &[u8], value: &[u8]) -> bool {
        let prefix = SideTable::decl(self).prefix.len();
        K::decode_key(key).is_some_and(|typed| self.key_bytes(&typed).get(prefix..) == Some(key))
            && self
                .decode_value(value)
                .and_then(|typed| self.encode_value(&typed))
                .is_ok_and(|bytes| bytes == value)
    }

    fn stored(&self, store: &Store, txn: &RoTxn<'_>, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let typed = K::decode_key(key).ok_or_else(|| invalid("side row key"))?;
        self.get_bytes(store, txn, &typed)
    }

    fn restore(&self, store: &Store, wtxn: &mut RwTxn<'_>, key: &[u8], value: &[u8]) -> Result<()> {
        let typed = K::decode_key(key).ok_or_else(|| invalid("side row key"))?;
        let value = self.decode_value(value)?;
        self.put(store, wtxn, &typed, &value)
    }
}

/// Every table its owner lends the archive.
fn lent_tables() -> Vec<LentSideTable> {
    let mut tables: Vec<LentSideTable> = Vec::new();
    tables.extend(crate::blob_artifact::archive_version_tables());
    tables.push(crate::blob_artifact::archive_born_from_table());
    tables.extend(crate::origin::lfs::archive_lfs_tables());
    tables.extend(crate::codebase::archive_codebase_tables());
    tables.extend(crate::code_revision::archive_revision_tables());
    tables.push(crate::code_revision::archive_promotion_table());
    tables.push(crate::code_revision::archive_proposal_table());
    tables.extend(crate::code_document::archive_document_tables());
    tables
}

fn lent(family: ArchiveSideFamily) -> Result<LentSideTable> {
    let name = family.spec().decl.name;
    lent_tables()
        .into_iter()
        .find(|table| table.decl().name == name)
        .ok_or(Error::InvariantViolation(
            "archive side table not lent by its owner",
        ))
}

/// One allowlisted side table, in restore order: within each family its
/// records come first, then its indexes, then its heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveSideFamily {
    /// One version record of a blob artifact.
    BlobVersion,
    /// An artifact's refcount marker on the ASSET its content is.
    BlobAssetRef,
    /// The born-from projection of a version's trigger.
    BlobBornFrom,
    /// An artifact's last issued version.
    BlobHighwater,
    /// An artifact's head version.
    BlobHead,
    /// An ASSET marked as an LFS chunk, with its content hash.
    LfsChunkMark,
    /// A chunk an LFS upload owner references.
    LfsOwnerRef,
    /// An owner a chunk is referenced by.
    LfsChunkRef,
    /// A published LFS object: its manifest ASSET, size, time and ref owner.
    LfsObject,
    /// The object a manifest ASSET publishes.
    LfsManifest,
    /// An LFS object attached to a git ref.
    LfsRef,
    /// A deleted object's permanent tombstone.
    LfsDeleted,
    /// The vault's chunk-boundary seed.
    LfsCdc,
    /// A codebase snapshot's file manifest, keyed by its CODE_ARTIFACT.
    CodebaseSnapshot,
    /// The custody report of a snapshot fork hash.
    CodebaseCustody,
    /// The repo index of a snapshot.
    CodebaseRepo,
    /// The project index of a snapshot.
    CodebaseProject,
    /// The fork-hash index of a snapshot.
    CodebaseFork,
    /// The scope index of a snapshot or of an ASSET visible under it.
    CodebaseScope,
    /// A finalized code revision.
    CodeRevisionRecord,
    /// A revision's integrity fold.
    CodeRevisionIntegrity,
    /// A stranded revision proposal.
    CodeRevisionProposal,
    /// The review ids that promoted a revision.
    CodeRevisionPromotion,
    /// A revision under its session.
    CodeRevisionSession,
    /// A revision under its parent.
    CodeRevisionParent,
    /// A session's fork record.
    CodeRevisionFork,
    /// A fork under its parent session.
    CodeRevisionForkParent,
    /// A session's revision frontier.
    CodeRevisionFrontier,
    /// An applied code-edit operation's replay guard.
    CodeDocumentIngress,
    /// A code document's tested snapshot at one frontier.
    CodeDocumentFrontier,
    /// The document living at a repo path.
    CodeDocumentPath,
    /// A repo path's rename generation.
    CodeDocumentGeneration,
    /// A code document's head and receipt history.
    CodeDocumentHead,
}

/// One part of a stored key, in the order the key holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// An entity id: 16 bytes.
    Id,
    /// A big-endian u64.
    U64,
    /// A 32-byte hash or object id.
    Hash,
    /// A born-from source: a kind byte and 16 bytes.
    Source,
    /// The NUL that frames a text part.
    Nul,
    /// UTF-8 text: the one part whose length varies.
    Text,
}

impl Part {
    fn width(self) -> Option<usize> {
        match self {
            Self::Id => Some(ENTITY_ID_LEN),
            Self::U64 => Some(8),
            Self::Hash => Some(32),
            Self::Source => Some(ENTITY_ID_LEN + 1),
            Self::Nul => Some(1),
            Self::Text => None,
        }
    }
}

/// How a table's value is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Empty,
    U64Be,
    U64Le,
    Hash,
    /// `asset(16) ++ size u64 LE ++ created u64 LE ++ ref_owner(16)`.
    LfsObject,
    /// One MessagePack value: the table's Named, LegacyCompact or own codec.
    MessagePack,
}

/// The families a record's rows go out together within.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Blob,
    Lfs,
    Codebase,
    CodeRevision,
    CodeDocument,
}

#[derive(Clone, Copy)]
struct Spec {
    decl: &'static SideTableDecl,
    key: &'static [Part],
    value: Form,
    group: Group,
}

impl ArchiveSideFamily {
    const ALL: [Self; 33] = [
        Self::BlobVersion,
        Self::BlobAssetRef,
        Self::BlobBornFrom,
        Self::BlobHighwater,
        Self::BlobHead,
        Self::LfsChunkMark,
        Self::LfsOwnerRef,
        Self::LfsChunkRef,
        Self::LfsObject,
        Self::LfsManifest,
        Self::LfsRef,
        Self::LfsDeleted,
        Self::LfsCdc,
        Self::CodebaseSnapshot,
        Self::CodebaseCustody,
        Self::CodebaseRepo,
        Self::CodebaseProject,
        Self::CodebaseFork,
        Self::CodebaseScope,
        Self::CodeRevisionRecord,
        Self::CodeRevisionIntegrity,
        Self::CodeRevisionProposal,
        Self::CodeRevisionPromotion,
        Self::CodeRevisionSession,
        Self::CodeRevisionParent,
        Self::CodeRevisionFork,
        Self::CodeRevisionForkParent,
        Self::CodeRevisionFrontier,
        Self::CodeDocumentIngress,
        Self::CodeDocumentFrontier,
        Self::CodeDocumentPath,
        Self::CodeDocumentGeneration,
        Self::CodeDocumentHead,
    ];

    fn spec(self) -> Spec {
        use Form::{Empty, Hash, LfsObject, MessagePack, U64Be, U64Le};
        use Group::{Blob, CodeDocument, CodeRevision, Codebase, Lfs};
        use Part::{Hash as H, Id, Nul, Source, Text, U64};
        use side_table as t;
        match self {
            Self::BlobVersion => spec(&t::BLOB_ARTIFACT_VERSION, &[Id, U64], MessagePack, Blob),
            Self::BlobAssetRef => spec(&t::BLOB_ARTIFACT_ASSET_REF, &[H, Id], Empty, Blob),
            Self::BlobBornFrom => spec(
                &t::BLOB_ARTIFACT_BORN_FROM,
                &[Source, Id, U64],
                MessagePack,
                Blob,
            ),
            Self::BlobHighwater => spec(&t::BLOB_ARTIFACT_HIGHWATER, &[Id], U64Be, Blob),
            Self::BlobHead => spec(&t::BLOB_ARTIFACT_HEAD, &[Id], MessagePack, Blob),
            Self::LfsChunkMark => spec(&t::ORIGIN_LFS_CHUNK_MARK, &[Id], Hash, Lfs),
            Self::LfsOwnerRef => spec(&t::ORIGIN_LFS_OWNER_REF, &[Id, H], Empty, Lfs),
            Self::LfsChunkRef => spec(&t::ORIGIN_LFS_CHUNK_REF, &[H, Id], Empty, Lfs),
            Self::LfsObject => spec(&t::ORIGIN_LFS_OBJECT, &[H], LfsObject, Lfs),
            Self::LfsManifest => spec(&t::ORIGIN_LFS_MANIFEST_REVERSE, &[Id], Hash, Lfs),
            Self::LfsRef => spec(&t::ORIGIN_LFS_REF, &[Id, Nul, Text, Nul, H], U64Le, Lfs),
            Self::LfsDeleted => spec(&t::ORIGIN_LFS_DELETED, &[H], Empty, Lfs),
            Self::LfsCdc => spec(&t::ORIGIN_LFS_CDC_SEED, &[], U64Le, Lfs),
            Self::CodebaseSnapshot => spec(&t::CODEBASE_SNAPSHOT, &[Id], MessagePack, Codebase),
            Self::CodebaseCustody => spec(
                &t::SECRET_SNAPSHOT_CODEBASE_CUSTODY,
                &[Text],
                MessagePack,
                Codebase,
            ),
            Self::CodebaseRepo => spec(&t::CODEBASE_REPO_INDEX, &[Text, Nul, Id], Empty, Codebase),
            Self::CodebaseProject => spec(
                &t::CODEBASE_PROJECT_INDEX,
                &[Text, Nul, Id],
                Empty,
                Codebase,
            ),
            Self::CodebaseFork => spec(&t::CODEBASE_FORK_INDEX, &[H, Nul, Id], Empty, Codebase),
            Self::CodebaseScope => spec(&t::CODEBASE_SCOPE_INDEX, &[H, Nul, Id], Empty, Codebase),
            Self::CodeRevisionRecord => {
                spec(&t::CODE_REVISION_RECORD, &[Id], MessagePack, CodeRevision)
            }
            Self::CodeRevisionIntegrity => spec(
                &t::CODE_REVISION_INTEGRITY,
                &[Id],
                MessagePack,
                CodeRevision,
            ),
            Self::CodeRevisionProposal => {
                spec(&t::CODE_REVISION_PROPOSAL, &[Id], MessagePack, CodeRevision)
            }
            Self::CodeRevisionPromotion => spec(
                &t::CODE_REVISION_PROMOTION,
                &[Id],
                MessagePack,
                CodeRevision,
            ),
            Self::CodeRevisionSession => spec(
                &t::CODE_REVISION_SESSION_INDEX,
                &[Id, Id],
                Empty,
                CodeRevision,
            ),
            Self::CodeRevisionParent => spec(
                &t::CODE_REVISION_PARENT_INDEX,
                &[Id, Id],
                Empty,
                CodeRevision,
            ),
            Self::CodeRevisionFork => {
                spec(&t::CODE_REVISION_FORK, &[Id], MessagePack, CodeRevision)
            }
            Self::CodeRevisionForkParent => spec(
                &t::CODE_REVISION_FORK_PARENT_INDEX,
                &[Id, Id],
                Empty,
                CodeRevision,
            ),
            Self::CodeRevisionFrontier => {
                spec(&t::CODE_REVISION_FRONTIER, &[Id], MessagePack, CodeRevision)
            }
            Self::CodeDocumentIngress => {
                spec(&t::CODE_DOCUMENT_INGRESS, &[Id], MessagePack, CodeDocument)
            }
            Self::CodeDocumentFrontier => spec(
                &t::CODE_DOCUMENT_FRONTIER,
                &[H, H],
                MessagePack,
                CodeDocument,
            ),
            Self::CodeDocumentPath => spec(&t::CODE_DOCUMENT_PATH, &[H], Hash, CodeDocument),
            Self::CodeDocumentGeneration => {
                spec(&t::CODE_DOCUMENT_GENERATION, &[H], U64Be, CodeDocument)
            }
            Self::CodeDocumentHead => spec(&t::CODE_DOCUMENT_HEAD, &[H], MessagePack, CodeDocument),
        }
    }
}

fn spec(decl: &'static SideTableDecl, key: &'static [Part], value: Form, group: Group) -> Spec {
    Spec {
        decl,
        key,
        value,
        group,
    }
}

/// One part of a row's key, typed: ids and hashes as lowercase hex, text as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArchiveSideKeyPart {
    Id(String),
    Hash(String),
    /// A born-from source: its kind byte and 16 bytes.
    Source(String),
    U64(u64),
    Text(String),
}

/// One row's value in its table's codec, typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "form",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArchiveSideValue {
    /// An empty marker.
    Empty,
    /// A u64; the table names its byte order.
    U64(u64),
    /// A 32-byte hash or object id, lowercase hex.
    Hash(String),
    LfsObject(ArchiveLfsObject),
    /// One MessagePack value.
    MessagePack(ArchiveSideTree),
}

/// An LFS object record: its manifest ASSET, size, creation time and ref owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveLfsObject {
    pub asset: String,
    pub size_bytes: u64,
    pub created_at: u64,
    pub ref_owner: String,
}

/// A MessagePack value with nothing nulled or dropped: the export's credential
/// pass reads its text, and a long binary value is an archive file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArchiveSideTree {
    Boolean(bool),
    Integer(String),
    F32(u32),
    F64(u64),
    String(String),
    /// MessagePack binary, lowercase hex.
    Binary(String),
    /// An array of byte values, lowercase hex.
    Bytes(String),
    /// MessagePack binary stored as an archive file.
    BinaryFile(ExportBodyFile),
    /// An array of byte values stored as an archive file.
    BytesFile(ExportBodyFile),
    /// An extension value: its type and bytes, lowercase hex.
    Ext(i8, String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    #[serde(untagged)]
    Nil,
}

/// One side row as the archive carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSideRow {
    pub family: ArchiveSideFamily,
    /// The entity this row travels with; `None` for a vault-wide row.
    pub owner: Option<String>,
    pub key: Vec<ArchiveSideKeyPart>,
    pub value: ArchiveSideValue,
}

/// A side row the export holds out, and why. Its key is not named: a key can
/// hold text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSideWithheld {
    pub family: ArchiveSideFamily,
    pub owner: Option<String>,
    pub reason: ArchiveSideWithheldReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveSideWithheldReason {
    /// The credential pass would change the row: it carries a secret.
    Credential,
    /// The stored row does not read back through its table's key type and codec.
    NotPortable,
}

/// One stored row the archive carries: its table, its key after the table's
/// prefix, its stored value and the entity it travels with.
#[derive(Debug, Clone)]
pub(crate) struct SideRowBytes {
    pub(crate) family: ArchiveSideFamily,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) owner: Option<EntityId>,
}

impl SideRowBytes {
    /// The row as the archive carries it, and the bytes of each file it names;
    /// `None` when the stored row does not read back through its table.
    pub(crate) fn portable(&self) -> Result<Option<(ArchiveSideRow, Vec<Vec<u8>>)>> {
        let spec = self.family.spec();
        if !lent(self.family)?.canonical(&self.key, &self.value) {
            return Ok(None);
        }
        let Some(key) = key_parts(spec.key, &self.key) else {
            return Ok(None);
        };
        let mut files = Vec::new();
        let value = match (spec.value, self.value.as_slice()) {
            (Form::Empty, []) => Some(ArchiveSideValue::Empty),
            (Form::U64Be, bytes) => <[u8; 8]>::try_from(bytes)
                .ok()
                .map(|bytes| ArchiveSideValue::U64(u64::from_be_bytes(bytes))),
            (Form::U64Le, bytes) => <[u8; 8]>::try_from(bytes)
                .ok()
                .map(|bytes| ArchiveSideValue::U64(u64::from_le_bytes(bytes))),
            (Form::Hash, bytes) if bytes.len() == 32 => {
                Some(ArchiveSideValue::Hash(bytes_to_hex_lower(bytes)))
            }
            (Form::LfsObject, bytes) if bytes.len() == 2 * ENTITY_ID_LEN + 16 => {
                let word =
                    |at: usize| <[u8; 8]>::try_from(&bytes[at..at + 8]).map(u64::from_le_bytes);
                Some(ArchiveSideValue::LfsObject(ArchiveLfsObject {
                    asset: bytes_to_hex_lower(&bytes[..ENTITY_ID_LEN]),
                    size_bytes: word(ENTITY_ID_LEN).map_err(|_| invalid("lfs object"))?,
                    created_at: word(ENTITY_ID_LEN + 8).map_err(|_| invalid("lfs object"))?,
                    ref_owner: bytes_to_hex_lower(&bytes[ENTITY_ID_LEN + 16..]),
                }))
            }
            (Form::MessagePack, bytes) => {
                let mut cursor = std::io::Cursor::new(bytes);
                rmpv::decode::read_value(&mut cursor)
                    .ok()
                    .filter(|_| cursor.position() == bytes.len() as u64)
                    .and_then(|value| tree(&value, &mut files))
                    .map(ArchiveSideValue::MessagePack)
            }
            _ => None,
        };
        Ok(value.map(|value| {
            (
                ArchiveSideRow {
                    family: self.family,
                    owner: self.owner.as_ref().map(EntityId::to_hex),
                    key,
                    value,
                },
                files,
            )
        }))
    }

    /// The manifest entry of this row held out of the archive.
    pub(crate) fn withheld(&self, reason: ArchiveSideWithheldReason) -> ArchiveSideWithheld {
        ArchiveSideWithheld {
            family: self.family,
            owner: self.owner.as_ref().map(EntityId::to_hex),
            reason,
        }
    }
}

impl ArchiveSideRow {
    /// The stored key and value this row carries, each file read through `files`.
    pub(crate) fn stored(
        &self,
        files: &mut dyn FnMut(&ExportBodyFile) -> Result<Vec<u8>>,
    ) -> Result<SideRowBytes> {
        let spec = self.family.spec();
        let key = key_bytes(spec.key, &self.key).ok_or_else(|| invalid("side row key"))?;
        let value = match (spec.value, &self.value) {
            (Form::Empty, ArchiveSideValue::Empty) => Vec::new(),
            (Form::U64Be, ArchiveSideValue::U64(value)) => value.to_be_bytes().to_vec(),
            (Form::U64Le, ArchiveSideValue::U64(value)) => value.to_le_bytes().to_vec(),
            (Form::Hash, ArchiveSideValue::Hash(hash)) => {
                hex_exact(hash, 32).ok_or_else(|| invalid("side row hash"))?
            }
            (Form::LfsObject, ArchiveSideValue::LfsObject(object)) => {
                let mut bytes = hex_exact(&object.asset, ENTITY_ID_LEN)
                    .ok_or_else(|| invalid("lfs object asset"))?;
                bytes.extend_from_slice(&object.size_bytes.to_le_bytes());
                bytes.extend_from_slice(&object.created_at.to_le_bytes());
                bytes.extend(
                    hex_exact(&object.ref_owner, ENTITY_ID_LEN)
                        .ok_or_else(|| invalid("lfs object ref owner"))?,
                );
                bytes
            }
            (Form::MessagePack, ArchiveSideValue::MessagePack(tree)) => {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, &msgpack(tree, files)?)
                    .map_err(|_| invalid("side row value"))?;
                bytes
            }
            _ => return Err(invalid("side row value is not its table's form")),
        };
        Ok(SideRowBytes {
            family: self.family,
            key,
            value,
            owner: self.owner.as_deref().map(parse_id).transpose()?,
        })
    }

    /// The archive files this row names.
    pub(crate) fn files(&self) -> Vec<&ExportBodyFile> {
        fn walk<'a>(tree: &'a ArchiveSideTree, out: &mut Vec<&'a ExportBodyFile>) {
            match tree {
                ArchiveSideTree::BinaryFile(file) | ArchiveSideTree::BytesFile(file) => {
                    out.push(file);
                }
                ArchiveSideTree::Array(items) => items.iter().for_each(|item| walk(item, out)),
                ArchiveSideTree::Map(entries) => entries.iter().for_each(|(key, value)| {
                    walk(key, out);
                    walk(value, out);
                }),
                _ => {}
            }
        }
        let mut out = Vec::new();
        if let ArchiveSideValue::MessagePack(tree) = &self.value {
            walk(tree, &mut out);
        }
        out
    }
}

/// The rows of the allowlisted tables this export carries, read in its snapshot
/// `rtxn`. A record's rows of one family go when the record and every carrier
/// they name are in `included`; a vault-wide row goes only to a caller on this
/// device; an index row no carried record owns stays.
pub(crate) fn archive_side_rows_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    included: &BTreeSet<EntityId>,
    on_device: bool,
) -> Result<Vec<SideRowBytes>> {
    let mut stored = Vec::new();
    for family in ArchiveSideFamily::ALL {
        for (key, value) in lent(family)?.stored_rows(store, rtxn)? {
            stored.push((family, key, value));
        }
    }
    let context = SideContext::of(
        stored
            .iter()
            .map(|(family, key, value)| (*family, key.as_slice(), value.as_slice())),
    );
    let mut travels = Vec::with_capacity(stored.len());
    let mut groups: BTreeMap<(Group, EntityId), bool> = BTreeMap::new();
    for (family, key, value) in &stored {
        let travel = context.travel(*family, key, value)?;
        let group = family.spec().group;
        match &travel {
            Travel::With(owner, carriers) => {
                let whole =
                    included.contains(owner) && carriers.iter().all(|id| included.contains(id));
                *groups.entry((group, *owner)).or_insert(true) &= whole;
            }
            Travel::Broken(owner) => {
                groups.insert((group, *owner), false);
            }
            Travel::Vault | Travel::Orphan => {}
        }
        travels.push(travel);
    }
    Ok(stored
        .into_iter()
        .zip(travels)
        .filter_map(|((family, key, value), travel)| {
            let owner = match travel {
                Travel::With(owner, _)
                    if groups.get(&(family.spec().group, owner)) == Some(&true) =>
                {
                    Some(owner)
                }
                Travel::Vault if on_device => None,
                _ => return None,
            };
            Some(SideRowBytes {
                family,
                key,
                value,
                owner,
            })
        })
        .collect())
}

/// Validates an archive's side rows: each reads back through its table's key
/// type and codec in the very form the exporter writes, no row repeats, and the
/// record and every carrier it names are entities the archive holds (`ids`).
/// `files` reads a file a row names.
pub(crate) fn validate_side_rows(
    rows: &[ArchiveSideRow],
    ids: &BTreeSet<EntityId>,
    files: &mut dyn FnMut(&ExportBodyFile) -> Result<Vec<u8>>,
) -> Result<()> {
    let mut stored = Vec::with_capacity(rows.len());
    let mut seen = BTreeSet::new();
    for row in rows {
        let bytes = row.stored(files)?;
        let again = bytes
            .portable()?
            .ok_or_else(|| invalid("side row does not read back through its table"))?
            .0;
        if again != *row {
            return Err(invalid("side row is not in the form its exporter writes"));
        }
        if !seen.insert((row.family, bytes.key.clone())) {
            return Err(invalid("side row appears twice"));
        }
        stored.push(bytes);
    }
    let context = SideContext::of(
        stored
            .iter()
            .map(|row| (row.family, row.key.as_slice(), row.value.as_slice())),
    );
    for row in &stored {
        let held = match context.travel(row.family, &row.key, &row.value)? {
            Travel::With(owner, carriers) => {
                row.owner == Some(owner)
                    && ids.contains(&owner)
                    && carriers.iter().all(|id| ids.contains(id))
            }
            Travel::Vault => row.owner.is_none(),
            Travel::Broken(_) | Travel::Orphan => false,
        };
        if !held {
            return Err(invalid(
                "side row names a record or carrier the archive does not hold",
            ));
        }
    }
    Ok(())
}

/// Restores an archive's side rows in the import's write transaction, once its
/// entities are in: each family's records, then its indexes, then its heads.
/// A row whose record or carrier is not live here refuses the import; an
/// identical live row is unchanged, and any other live row under its key
/// refuses the import, never overwritten. Returns the rows written and those
/// already here.
pub(crate) fn restore_side_rows_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    rows: &[ArchiveSideRow],
    files: &mut dyn FnMut(&ExportBodyFile) -> Result<Vec<u8>>,
) -> Result<(usize, usize)> {
    let mut stored = rows
        .iter()
        .map(|row| row.stored(files))
        .collect::<Result<Vec<_>>>()?;
    stored.sort_by(|a, b| (a.family, &a.key).cmp(&(b.family, &b.key)));
    let context = SideContext::of(
        stored
            .iter()
            .map(|row| (row.family, row.key.as_slice(), row.value.as_slice())),
    );
    let (mut restored, mut unchanged) = (0, 0);
    for row in &stored {
        let named: Vec<EntityId> = match context.travel(row.family, &row.key, &row.value)? {
            Travel::With(owner, carriers) => std::iter::once(owner).chain(carriers).collect(),
            Travel::Vault => Vec::new(),
            Travel::Broken(_) | Travel::Orphan => {
                return Err(invalid("side row names no record the archive holds"));
            }
        };
        for id in &named {
            if !crate::vault::live_entity_row_in_txn(store, wtxn, id)?.is_live() {
                return Err(invalid("side row's record is not live in this vault"));
            }
        }
        let table = lent(row.family)?;
        match table.stored(store, wtxn, &row.key)? {
            Some(live) if live == row.value => unchanged += 1,
            Some(_) => {
                return Err(invalid("side row collides with a different stored row"));
            }
            None => {
                table.restore(store, wtxn, &row.key, &row.value)?;
                restored += 1;
            }
        }
    }
    Ok((restored, unchanged))
}

/// Where a row goes: with an entity and the carriers it names, broken (its
/// record's rows of that family stay together, so none go), vault-wide, or
/// nowhere (an index row no record owns).
enum Travel {
    With(EntityId, Vec<EntityId>),
    Broken(EntityId),
    Vault,
    Orphan,
}

/// What a row's owner is read from beyond its own key: the LFS object rows and
/// the codebase fork index.
#[derive(Default)]
struct SideContext {
    /// LFS ref owner → the manifest ASSET of its object.
    lfs_by_ref_owner: BTreeMap<[u8; ENTITY_ID_LEN], EntityId>,
    /// LFS object id → its manifest ASSET.
    lfs_by_oid: BTreeMap<[u8; 32], EntityId>,
    /// LFS ref owner → the chunk hashes it references.
    lfs_chunks_by_owner: BTreeMap<[u8; ENTITY_ID_LEN], Vec<[u8; 32]>>,
    /// LFS chunk hash → the chunk ASSETs marked with it.
    lfs_assets_by_chunk: BTreeMap<[u8; 32], Vec<EntityId>>,
    /// Codebase fork hash → the first snapshot recorded under it.
    codebase_by_fork: BTreeMap<[u8; 32], EntityId>,
}

impl SideContext {
    fn of<'a>(rows: impl Iterator<Item = (ArchiveSideFamily, &'a [u8], &'a [u8])>) -> Self {
        let mut context = Self::default();
        for (family, key, value) in rows {
            match family {
                ArchiveSideFamily::LfsObject => {
                    if let (Some(oid), Some(asset), Some(owner)) = (
                        array_at::<32>(key, 0),
                        id_at(value, 0),
                        array_at::<ENTITY_ID_LEN>(value, ENTITY_ID_LEN + 16),
                    ) {
                        context.lfs_by_ref_owner.insert(owner, asset);
                        context.lfs_by_oid.insert(oid, asset);
                    }
                }
                ArchiveSideFamily::LfsOwnerRef => {
                    if let (Some(owner), Some(chunk)) = (
                        array_at::<ENTITY_ID_LEN>(key, 0),
                        array_at::<32>(key, ENTITY_ID_LEN),
                    ) {
                        context
                            .lfs_chunks_by_owner
                            .entry(owner)
                            .or_default()
                            .push(chunk);
                    }
                }
                ArchiveSideFamily::LfsChunkMark => {
                    if let (Some(asset), Some(chunk)) = (id_at(key, 0), array_at::<32>(value, 0)) {
                        context
                            .lfs_assets_by_chunk
                            .entry(chunk)
                            .or_default()
                            .push(asset);
                    }
                }
                ArchiveSideFamily::CodebaseFork => {
                    if let (Some(fork), Some(snapshot)) = (array_at::<32>(key, 0), id_at(key, 33)) {
                        let first = context.codebase_by_fork.entry(fork).or_insert(snapshot);
                        *first = (*first).min(snapshot);
                    }
                }
                _ => {}
            }
        }
        context
    }

    fn travel(&self, family: ArchiveSideFamily, key: &[u8], value: &[u8]) -> Result<Travel> {
        use ArchiveSideFamily as F;
        let tail = |width: usize| key.len().checked_sub(width).and_then(|at| id_at(key, at));
        let with = |owner: Option<EntityId>, carriers: Vec<EntityId>| {
            owner.map_or(Travel::Orphan, |owner| Travel::With(owner, carriers))
        };
        Ok(match family {
            F::BlobVersion | F::BlobHighwater | F::BlobHead => with(id_at(key, 0), Vec::new()),
            F::BlobBornFrom => with(id_at(key, ENTITY_ID_LEN + 1), Vec::new()),
            F::BlobAssetRef => {
                let Some(content) = array_at::<32>(key, 0) else {
                    return Ok(Travel::Orphan);
                };
                let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&content)?;
                with(id_at(key, 32), vec![asset])
            }
            F::LfsChunkMark | F::LfsManifest => with(id_at(key, 0), Vec::new()),
            F::LfsOwnerRef => with(
                array_at::<ENTITY_ID_LEN>(key, 0)
                    .and_then(|owner| self.lfs_by_ref_owner.get(&owner).copied()),
                Vec::new(),
            ),
            F::LfsChunkRef => with(
                array_at::<ENTITY_ID_LEN>(key, 32)
                    .and_then(|owner| self.lfs_by_ref_owner.get(&owner).copied()),
                Vec::new(),
            ),
            F::LfsObject => {
                let Some(asset) = id_at(value, 0) else {
                    return Ok(Travel::Orphan);
                };
                let owner = array_at::<ENTITY_ID_LEN>(value, ENTITY_ID_LEN + 16);
                let mut carriers = Vec::new();
                for chunk in owner
                    .and_then(|owner| self.lfs_chunks_by_owner.get(&owner))
                    .into_iter()
                    .flatten()
                {
                    match self.lfs_assets_by_chunk.get(chunk) {
                        Some(assets) => carriers.extend(assets.iter().copied()),
                        None => return Ok(Travel::Broken(asset)),
                    }
                }
                Travel::With(asset, carriers)
            }
            F::LfsRef => with(
                key.len()
                    .checked_sub(32)
                    .and_then(|at| array_at::<32>(key, at))
                    .and_then(|oid| self.lfs_by_oid.get(&oid).copied()),
                Vec::new(),
            ),
            F::LfsDeleted | F::LfsCdc => Travel::Vault,
            F::CodebaseSnapshot => {
                let Some(snapshot) = id_at(key, 0) else {
                    return Ok(Travel::Orphan);
                };
                let Ok(decoded) = crate::codebase::decode_codebase_snapshot(value) else {
                    return Ok(Travel::Broken(snapshot));
                };
                let carriers = decoded
                    .files
                    .iter()
                    .map(|file| crate::codebase::archive_codebase_asset_id(&file.content_hash))
                    .collect::<Result<Vec<_>>>()?;
                Travel::With(snapshot, carriers)
            }
            F::CodebaseCustody => with(
                std::str::from_utf8(key)
                    .ok()
                    .and_then(|text| hex_exact(text, 32))
                    .and_then(|fork| array_at::<32>(&fork, 0))
                    .and_then(|fork| self.codebase_by_fork.get(&fork).copied()),
                Vec::new(),
            ),
            F::CodebaseRepo | F::CodebaseProject | F::CodebaseFork | F::CodebaseScope => {
                with(tail(ENTITY_ID_LEN), Vec::new())
            }
            F::CodeRevisionRecord
            | F::CodeRevisionIntegrity
            | F::CodeRevisionProposal
            | F::CodeRevisionPromotion
            | F::CodeRevisionFork
            | F::CodeRevisionFrontier => with(id_at(key, 0), Vec::new()),
            F::CodeRevisionSession | F::CodeRevisionParent | F::CodeRevisionForkParent => with(
                id_at(key, ENTITY_ID_LEN),
                id_at(key, 0).into_iter().collect(),
            ),
            F::CodeDocumentIngress
            | F::CodeDocumentFrontier
            | F::CodeDocumentPath
            | F::CodeDocumentGeneration
            | F::CodeDocumentHead => Travel::Vault,
        })
    }
}

fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn id_at(bytes: &[u8], at: usize) -> Option<EntityId> {
    EntityId::from_bytes(array_at::<ENTITY_ID_LEN>(bytes, at)?).ok()
}

/// A stored key as its typed parts, read by the table's layout.
fn key_parts(layout: &[Part], key: &[u8]) -> Option<Vec<ArchiveSideKeyPart>> {
    let text = layout.iter().position(|part| *part == Part::Text);
    let (head, tail) = match text {
        Some(at) => (&layout[..at], &layout[at + 1..]),
        None => (layout, &[][..]),
    };
    let width = |parts: &[Part]| parts.iter().filter_map(|part| part.width()).sum::<usize>();
    let (head_len, tail_len) = (width(head), width(tail));
    if key.len() < head_len + tail_len || (text.is_none() && key.len() != head_len) {
        return None;
    }
    let mut parts = Vec::new();
    let mut at = 0;
    for part in head {
        let end = at + part.width()?;
        push_part(*part, &key[at..end], &mut parts)?;
        at = end;
    }
    if text.is_some() {
        let end = key.len() - tail_len;
        parts.push(ArchiveSideKeyPart::Text(
            String::from_utf8(key[at..end].to_vec()).ok()?,
        ));
        at = end;
        for part in tail {
            let end = at + part.width()?;
            push_part(*part, &key[at..end], &mut parts)?;
            at = end;
        }
    }
    Some(parts)
}

fn push_part(part: Part, bytes: &[u8], parts: &mut Vec<ArchiveSideKeyPart>) -> Option<()> {
    parts.push(match part {
        Part::Id => ArchiveSideKeyPart::Id(bytes_to_hex_lower(bytes)),
        Part::Hash => ArchiveSideKeyPart::Hash(bytes_to_hex_lower(bytes)),
        Part::Source => ArchiveSideKeyPart::Source(bytes_to_hex_lower(bytes)),
        Part::U64 => ArchiveSideKeyPart::U64(u64::from_be_bytes(bytes.try_into().ok()?)),
        Part::Nul => return (bytes == [0_u8]).then_some(()),
        Part::Text => return None,
    });
    Some(())
}

/// A key's stored bytes from its typed parts, by the table's layout.
fn key_bytes(layout: &[Part], parts: &[ArchiveSideKeyPart]) -> Option<Vec<u8>> {
    let mut parts = parts.iter();
    let mut key = Vec::new();
    for part in layout {
        if *part == Part::Nul {
            key.push(0);
            continue;
        }
        match (part, parts.next()?) {
            (Part::Id, ArchiveSideKeyPart::Id(hex)) => key.extend(hex_exact(hex, ENTITY_ID_LEN)?),
            (Part::Hash, ArchiveSideKeyPart::Hash(hex)) => key.extend(hex_exact(hex, 32)?),
            (Part::Source, ArchiveSideKeyPart::Source(hex)) => {
                key.extend(hex_exact(hex, ENTITY_ID_LEN + 1)?);
            }
            (Part::U64, ArchiveSideKeyPart::U64(value)) => key.extend(value.to_be_bytes()),
            (Part::Text, ArchiveSideKeyPart::Text(text)) => key.extend(text.as_bytes()),
            _ => return None,
        }
    }
    parts.next().is_none().then_some(key)
}

/// A MessagePack value as its archive tree. A long binary value or byte array
/// becomes a file, its bytes pushed to `files`; a string that is no UTF-8 has no
/// tree, so its row does not travel.
fn tree(value: &rmpv::Value, files: &mut Vec<Vec<u8>>) -> Option<ArchiveSideTree> {
    use rmpv::Value as Mp;
    Some(match value {
        Mp::Nil => ArchiveSideTree::Nil,
        Mp::Boolean(value) => ArchiveSideTree::Boolean(*value),
        Mp::Integer(value) => ArchiveSideTree::Integer(value.to_string()),
        Mp::F32(value) => ArchiveSideTree::F32(value.to_bits()),
        Mp::F64(value) => ArchiveSideTree::F64(value.to_bits()),
        Mp::String(text) => ArchiveSideTree::String(text.as_str()?.to_owned()),
        Mp::Binary(bytes) if bytes.len() > SIDE_INLINE_BYTES => {
            ArchiveSideTree::BinaryFile(attach(files, bytes.clone()))
        }
        Mp::Binary(bytes) => ArchiveSideTree::Binary(bytes_to_hex_lower(bytes)),
        Mp::Array(items) if items.is_empty() => ArchiveSideTree::Array(Vec::new()),
        Mp::Array(items) => match byte_values(items) {
            Some(bytes) if bytes.len() > SIDE_INLINE_BYTES => {
                ArchiveSideTree::BytesFile(attach(files, bytes))
            }
            Some(bytes) => ArchiveSideTree::Bytes(bytes_to_hex_lower(&bytes)),
            None => ArchiveSideTree::Array(
                items
                    .iter()
                    .map(|item| tree(item, files))
                    .collect::<Option<_>>()?,
            ),
        },
        Mp::Map(entries) => ArchiveSideTree::Map(
            entries
                .iter()
                .map(|(key, value)| Some((tree(key, files)?, tree(value, files)?)))
                .collect::<Option<_>>()?,
        ),
        Mp::Ext(kind, bytes) => ArchiveSideTree::Ext(*kind, bytes_to_hex_lower(bytes)),
    })
}

/// The descriptor of a file a tree names, its bytes pushed to `files`.
fn attach(files: &mut Vec<Vec<u8>>, bytes: Vec<u8>) -> ExportBodyFile {
    let descriptor = ExportBodyFile::of(&bytes);
    files.push(bytes);
    descriptor
}

/// An archive tree as its MessagePack value, each file read through `files`.
fn msgpack(
    tree: &ArchiveSideTree,
    files: &mut dyn FnMut(&ExportBodyFile) -> Result<Vec<u8>>,
) -> Result<rmpv::Value> {
    use rmpv::Value as Mp;
    let bytes = |values: Vec<u8>| Mp::Array(values.into_iter().map(Mp::from).collect());
    Ok(match tree {
        ArchiveSideTree::Nil => Mp::Nil,
        ArchiveSideTree::Boolean(value) => Mp::Boolean(*value),
        ArchiveSideTree::Integer(value) if value.starts_with('-') => Mp::from(
            value
                .parse::<i64>()
                .map_err(|_| invalid("side row integer"))?,
        ),
        ArchiveSideTree::Integer(value) => Mp::from(
            value
                .parse::<u64>()
                .map_err(|_| invalid("side row integer"))?,
        ),
        ArchiveSideTree::F32(bits) => Mp::F32(f32::from_bits(*bits)),
        ArchiveSideTree::F64(bits) => Mp::F64(f64::from_bits(*bits)),
        ArchiveSideTree::String(text) => Mp::from(text.as_str()),
        ArchiveSideTree::Binary(hex) => Mp::Binary(hex_any(hex)?),
        ArchiveSideTree::Bytes(hex) => bytes(hex_any(hex)?),
        ArchiveSideTree::BinaryFile(file) => Mp::Binary(files(file)?),
        ArchiveSideTree::BytesFile(file) => bytes(files(file)?),
        ArchiveSideTree::Ext(kind, hex) => Mp::Ext(*kind, hex_any(hex)?),
        ArchiveSideTree::Array(items) => Mp::Array(
            items
                .iter()
                .map(|item| msgpack(item, files))
                .collect::<Result<_>>()?,
        ),
        ArchiveSideTree::Map(entries) => Mp::Map(
            entries
                .iter()
                .map(|(key, value)| Ok((msgpack(key, files)?, msgpack(value, files)?)))
                .collect::<Result<_>>()?,
        ),
    })
}

fn byte_values(items: &[rmpv::Value]) -> Option<Vec<u8>> {
    items
        .iter()
        .map(|item| item.as_u64().and_then(|value| u8::try_from(value).ok()))
        .collect()
}

/// Lowercase hex of exactly `len` bytes.
fn hex_exact(text: &str, len: usize) -> Option<Vec<u8>> {
    hex_any(text).ok().filter(|bytes| bytes.len() == len)
}

/// Lowercase hex of any length.
fn hex_any(text: &str) -> Result<Vec<u8>> {
    let bytes = text
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.len() == 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| invalid("side row hex"))?;
    if bytes_to_hex_lower(&bytes) != text {
        return Err(invalid("side row hex must be lowercase"));
    }
    Ok(bytes)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault side row: {reason}"))
}
