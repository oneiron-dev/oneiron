//! OF-222 (FIX 2768, FIX 3681): the side tables an archive carries beside the
//! records they index, in the whole-vault archive and in a records archive (an
//! export-first removal's) alike. The binary carriers travel as files; without
//! these rows an import holds the bytes and no index resolves them: an LFS
//! object, a blob version, a codebase snapshot, a code revision, a code
//! document's history or a code symbol's memory. One explicit allowlist names
//! each table, its key layout and its value form. No other row travels: the
//! recovery classes grant nothing here; the LFS upload journal and GC queue and
//! an edit settlement's live work are in-flight work that never leaves; and a
//! code view is a host directory, its id no record.
//!
//! A row goes out with the record it belongs to and every carrier it names, read
//! in the export's snapshot, and a record's rows of one family go together or
//! not at all: a carried record whose family names a carrier the export lacks is
//! named in the manifest instead. A vault-wide row (an LFS tombstone or boundary
//! seed, a code document's history, whose id hashes a repo path and names no
//! record) goes only to a caller on this device: no world scopes it.
//! Each value goes in its table's own codec, typed: ids and hashes as hex, text
//! as text for the document's credential pass, a long binary value as an
//! archive file, byte for byte, and a table's own binary codec as its bytes,
//! which the release scan reads whole. An import reads each row back through its
//! table's own key type and codec, checks the record and carriers it names, and
//! restores it in the import's write transaction once the entities are in:
//! records first, then indexes, then heads. An identical live row is unchanged;
//! any other refuses the import.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::archive_index::{ArchiveIndex, IndexedArchive, Loc, Tag};
use super::document_import::parse_id;
use crate::code_revision::ArchivedRevisionRow;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::serialize::ExportBodyFile;
use crate::side_table::{self, SideCodec, SideKey, SideTable, SideTableDecl};
use crate::source_audience::ExportJudge;
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
    tables.extend(crate::blob_artifact::archive_version_claim_tables());
    tables.push(crate::edit_roundtrip::archive_deck_marks_table());
    tables.push(crate::edit_settle::archive_settlement_table());
    tables.extend(crate::origin::lfs::archive_lfs_tables());
    tables.extend(crate::codebase::archive_codebase_tables());
    tables.extend(crate::code_revision::archive_revision_tables());
    tables.push(crate::store::code_revision_record::tables::archive_promotion_table());
    tables.push(crate::code_revision::archive_proposal_table());
    tables.extend(crate::code_document::archive_document_tables());
    tables.extend(crate::store::code_memory_values::archive_code_memory_tables());
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
    /// A deck artifact's managed native-id history.
    BlobDeckMarks,
    /// An artifact's consume-once edit settlement of one proposal.
    BlobSettlement,
    /// An artifact holding the bytes under a content hash, as a `blob.version`
    /// claim named them.
    BlobVersionClaim,
    /// The same pair, keyed by the artifact.
    BlobClaimedHash,
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
    /// A code symbol's named memory slot and its values.
    CodeMemorySlot,
    /// A code symbol's slot value bound to its NOTE or CLAIM payload.
    CodeMemoryAttachment,
    /// A code symbol's always-on memory contract over one payload.
    CodeMemoryAlwaysOn,
    /// An anchor-transfer receipt from one code symbol to another.
    CodeMemoryTransfer,
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
    /// A kind byte and 16 bytes: a born-from source or a code-memory payload.
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
    /// The table's own binary codec, carried byte for byte.
    Opaque,
}

/// The families a record's rows go out together within.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Blob,
    Lfs,
    Codebase,
    CodeRevision,
    CodeDocument,
    CodeMemory,
    /// A transfer receipt goes apart from its symbol's slots: it names a
    /// second symbol, whose absence leaves the first's memory whole.
    CodeMemoryTransfer,
}

#[derive(Clone, Copy)]
struct Spec {
    decl: &'static SideTableDecl,
    key: &'static [Part],
    value: Form,
    group: Group,
}

impl ArchiveSideFamily {
    const ALL: [Self; 41] = [
        Self::BlobVersion,
        Self::BlobAssetRef,
        Self::BlobBornFrom,
        Self::BlobDeckMarks,
        Self::BlobSettlement,
        Self::BlobVersionClaim,
        Self::BlobClaimedHash,
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
        Self::CodeMemorySlot,
        Self::CodeMemoryAttachment,
        Self::CodeMemoryAlwaysOn,
        Self::CodeMemoryTransfer,
    ];

    fn spec(self) -> Spec {
        use Form::{Empty, Hash, LfsObject, MessagePack, Opaque, U64Be, U64Le};
        use Group::{
            Blob, CodeDocument, CodeMemory, CodeMemoryTransfer, CodeRevision, Codebase, Lfs,
        };
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
            Self::BlobDeckMarks => spec(&t::BLOB_ARTIFACT_DECK_ID_MARKS, &[Id], MessagePack, Blob),
            Self::BlobSettlement => spec(&t::EDIT_SETTLE_RECORD, &[Id, H], MessagePack, Blob),
            Self::BlobVersionClaim => spec(&t::BLOB_ARTIFACT_VERSION_CLAIM, &[H, Id], Empty, Blob),
            Self::BlobClaimedHash => spec(&t::BLOB_ARTIFACT_CLAIMED_HASH, &[Id, H], Empty, Blob),
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
            Self::CodeMemorySlot => {
                spec(&t::CODE_MEMORY_SLOT, &[Id, Nul, Text], Opaque, CodeMemory)
            }
            Self::CodeMemoryAttachment => spec(
                &t::CODE_MEMORY_ATTACHMENT,
                &[Id, Nul, Text, Nul, Source],
                Opaque,
                CodeMemory,
            ),
            Self::CodeMemoryAlwaysOn => spec(
                &t::CODE_MEMORY_ALWAYS_ON,
                &[Id, Nul, Text, Nul, Source],
                Opaque,
                CodeMemory,
            ),
            Self::CodeMemoryTransfer => spec(
                &t::CODE_MEMORY_TRANSFER,
                &[Id, Id, U64, H],
                Opaque,
                CodeMemoryTransfer,
            ),
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
    /// A kind byte and 16 bytes: a born-from source or a code-memory payload.
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
    /// A value in its table's own binary codec, lowercase hex.
    Binary(String),
    /// A value in its table's own binary codec, stored as an archive file.
    BinaryFile(ExportBodyFile),
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
    /// The entity the family's rows travel with; for a code document's
    /// history, which travels vault-wide and names no record, the document
    /// (its 32-byte id) an Owner's copy holds it out under (fix list row
    /// 15416); `None` for a vault-wide row.
    pub owner: Option<String>,
    pub reason: ArchiveSideWithheldReason,
    /// The records a row held out alone names beside its owner, each one
    /// the archive carries (FIX 11128): a projection that cuts one of them
    /// judges the owner's group not whole, as a fresh export of the kept
    /// records does. Empty for a family held out whole.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carriers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveSideWithheldReason {
    /// The credential pass would change the row: it carries a secret.
    Credential,
    /// The stored row does not read back through its table's key type and codec.
    NotPortable,
    /// FIX 3681: a carried record's rows of this family do not all travel (one
    /// names a carrier the export does not hold, or does not read), and they go
    /// together, so none go. Named once per record and family.
    Incomplete,
}

/// One stored row the archive carries: its table, its key after the table's
/// prefix, its stored value, the entity it travels with and the carriers it
/// names beside that entity (known to the export; empty as read back).
#[derive(Debug, Clone)]
pub(crate) struct SideRowBytes {
    pub(crate) family: ArchiveSideFamily,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) owner: Option<EntityId>,
    pub(crate) carriers: Vec<EntityId>,
    /// In an Owner's copy, each entity row the row names, read through its
    /// family's own codec and carried by the copy's mailbox judge (fix list
    /// row 15416): their lineage counts as carried once the writer
    /// serializes the row. Empty elsewhere, and as read back.
    pub(crate) names: Vec<EntityId>,
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
            (Form::Opaque, bytes) if bytes.len() > SIDE_INLINE_BYTES => {
                let file = attach(&mut files, bytes.to_vec());
                Some(ArchiveSideValue::BinaryFile(file))
            }
            (Form::Opaque, bytes) => Some(ArchiveSideValue::Binary(bytes_to_hex_lower(bytes))),
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

    /// Whether the release scan reads a credential in a value carried in its
    /// table's own binary codec, which the document's pass sees only as hex.
    pub(crate) fn opaque_credential(&self) -> bool {
        self.family.spec().value == Form::Opaque
            && crate::batch::secret_scan::scan_file_content("", &self.value).is_some()
    }

    /// The manifest entry of this row held out of the archive, with the
    /// carriers it names.
    pub(crate) fn withheld(&self, reason: ArchiveSideWithheldReason) -> ArchiveSideWithheld {
        ArchiveSideWithheld {
            family: self.family,
            owner: self.owner.as_ref().map(EntityId::to_hex),
            reason,
            carriers: self.carriers.iter().map(EntityId::to_hex).collect(),
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
            (Form::Opaque, ArchiveSideValue::Binary(hex)) => hex_any(hex)?,
            (Form::Opaque, ArchiveSideValue::BinaryFile(file)) => files(file)?,
            _ => return Err(invalid("side row value is not its table's form")),
        };
        Ok(SideRowBytes {
            family: self.family,
            key,
            value,
            owner: self.owner.as_deref().map(parse_id).transpose()?,
            carriers: Vec::new(),
            names: Vec::new(),
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
        match &self.value {
            ArchiveSideValue::MessagePack(tree) => walk(tree, &mut out),
            ArchiveSideValue::BinaryFile(file) => out.push(file),
            _ => {}
        }
        out
    }
}

/// The rows of the allowlisted tables this export carries, read in its snapshot
/// `rtxn`, and the families it holds out. A record's rows of one family go when
/// the record and every carrier they name are in `included`; otherwise none go,
/// and a record in `included` has that family named once. A vault-wide row goes
/// only when `include_vault_wide` (the owner's own whole-vault archive, or one
/// read on this device); a row of a record the export does not carry, and an
/// index row no record owns, stay unnamed (FIX 3681: a records archive never
/// names what its reader could not read).
///
/// In an Owner's copy, `member_mail` is its pass's mailbox judge (fix list row
/// 15416): a row that would go is read through its family's own codec, every
/// typed record inside it too ([`side_names`]), and goes only when the judge
/// carries every entity row it names. A record's row that names one the judge
/// leaves out, or that does not read, holds out the record's rows of its
/// group, as a carrier the export lacks does, so a version's record, its head
/// and its born-from row go or stay together; each family is named once under
/// the record, never by the entity left out. A code document's history goes
/// whole or not at all: one of its rows naming a session, actor or other row
/// the judge leaves out, or a snapshot or stamp that does not read, holds out
/// every row of that document and the generation rows of each repo path it
/// stood at, each family named once under the document. Each row that goes
/// keeps the rows it names, to count as carried once the writer serializes it.
pub(crate) fn archive_side_rows_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    included: &BTreeSet<EntityId>,
    include_vault_wide: bool,
    mut member_mail: Option<&mut ExportJudge<'_, '_, '_>>,
) -> Result<(Vec<SideRowBytes>, Vec<ArchiveSideWithheld>)> {
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
    // In an Owner's copy, what each row that would go names, and whether the
    // judge carries all of it.
    let mut judged = Vec::with_capacity(stored.len());
    for (family, key, value) in &stored {
        let mut travel = context.travel(*family, key, value)?;
        let mut verdict = None;
        if let Some(judge) = member_mail.as_deref_mut()
            && travel.goes(included, include_vault_wide)
        {
            let names = side_names(*family, key, value)?;
            let carried = match &names.rows {
                Some(rows) => judge.carries_all(Some(rows.as_slice()))?,
                None => false,
            };
            if !carried {
                travel = travel.left_out();
            }
            verdict = Some((names, carried));
        }
        travels.push((*family, travel));
        judged.push(verdict);
    }
    let histories = DocumentHistories::of(&judged);
    let mut held_documents = BTreeSet::new();
    for ((family, travel), verdict) in travels.iter_mut().zip(&judged) {
        let Some((names, _)) = verdict else {
            continue;
        };
        let held = histories.held(names);
        if !held.is_empty() {
            *travel = Travel::Orphan;
            held_documents.extend(held.into_iter().map(|document| (*family, document)));
        }
    }
    let groups = whole_groups(&travels, included);
    let mut held_out = BTreeSet::new();
    let rows: Vec<SideRowBytes> = stored
        .into_iter()
        .zip(&travels)
        .zip(judged)
        .filter_map(|(((family, key, value), (_, travel)), verdict)| {
            let owner = carried(
                family,
                travel,
                &groups,
                included,
                include_vault_wide,
                &mut held_out,
            )?;
            let carriers = match travel {
                Travel::With(_, carriers) => carriers.clone(),
                Travel::Broken(_) | Travel::Vault | Travel::Orphan => Vec::new(),
            };
            let names = verdict
                .and_then(|(names, admitted)| admitted.then_some(names.rows))
                .flatten()
                .unwrap_or_default();
            Some(SideRowBytes {
                family,
                key,
                value,
                owner,
                carriers,
                names,
            })
        })
        .collect();
    let mut withheld: Vec<ArchiveSideWithheld> = incomplete(held_out).collect();
    withheld.extend(
        held_documents
            .into_iter()
            .map(|(family, document)| ArchiveSideWithheld {
                family,
                owner: Some(bytes_to_hex_lower(&document)),
                reason: ArchiveSideWithheldReason::Incomplete,
                carriers: Vec::new(),
            }),
    );
    Ok((rows, withheld))
}

/// FIX-LIST 11110: which of a stored records archive's side `rows` stay when
/// the archive is cut down to the records `kept`, as
/// [`archive_side_rows_in_txn`] carries them for those records: each row's
/// record and carriers are read from the archive's own rows, as its import
/// reads them, and a record's rows of one group stay together or not at all.
/// `withheld`, the archive's list already cut to the kept records, then names
/// what a fresh export of them names: each family of a kept record whose group
/// does not stay whole, a row the export held out alone among them too. A row
/// held out alone is not in the archive, so its entry's carriers judge its
/// group with the rest (FIX 11128): one not kept leaves the group not whole.
/// A vault-wide row stays nowhere: a records archive leaves this device.
/// `files` reads a file a row names.
pub(crate) fn project_side_rows(
    rows: &[ArchiveSideRow],
    kept: &BTreeSet<EntityId>,
    withheld: &mut Vec<ArchiveSideWithheld>,
    files: &mut dyn FnMut(&ExportBodyFile) -> Result<Vec<u8>>,
) -> Result<Vec<bool>> {
    let mut stored = Vec::with_capacity(rows.len());
    for row in rows {
        stored.push(row.stored(files)?);
    }
    let context = SideContext::of(
        stored
            .iter()
            .map(|row| (row.family, row.key.as_slice(), row.value.as_slice())),
    );
    let mut travels = Vec::with_capacity(stored.len());
    for row in &stored {
        travels.push((
            row.family,
            context.travel(row.family, &row.key, &row.value)?,
        ));
    }
    let mut groups = whole_groups(&travels, kept);
    for entry in withheld.iter() {
        let Some(owner) = entry.owner.as_deref().map(parse_id).transpose()? else {
            continue;
        };
        let mut whole = kept.contains(&owner);
        for carrier in &entry.carriers {
            whole &= kept.contains(&parse_id(carrier)?);
        }
        if !whole {
            groups.insert((entry.family.spec().group, owner), false);
        }
    }
    let mut held_out = BTreeSet::new();
    let stays: Vec<bool> = travels
        .iter()
        .map(|(family, travel)| {
            carried(*family, travel, &groups, kept, false, &mut held_out).is_some()
        })
        .collect();
    let mut alone = Vec::with_capacity(withheld.len());
    for entry in withheld.drain(..) {
        let owner = entry.owner.as_deref().map(parse_id).transpose()?;
        match owner {
            Some(owner)
                if entry.reason == ArchiveSideWithheldReason::Incomplete
                    || groups.get(&(entry.family.spec().group, owner)) == Some(&false) =>
            {
                held_out.insert((entry.family, owner));
            }
            _ => alone.push(entry),
        }
    }
    *withheld = alone;
    withheld.extend(incomplete(held_out));
    Ok(stays)
}

/// Whether each record's rows of one group all go (FIX 3681): the record and
/// every carrier its rows name are in `included`, and none is broken.
fn whole_groups(
    travels: &[(ArchiveSideFamily, Travel)],
    included: &BTreeSet<EntityId>,
) -> BTreeMap<(Group, EntityId), bool> {
    let mut groups = BTreeMap::new();
    for (family, travel) in travels {
        let group = family.spec().group;
        match travel {
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
    }
    groups
}

/// Where a row of `family` that travels as `travel` goes: `Some(Some(owner))`
/// with its record when that record's group is whole, `Some(None)` as a
/// vault-wide row when `vault`, else nowhere, its family then named in
/// `held_out` for a record in `included`.
fn carried(
    family: ArchiveSideFamily,
    travel: &Travel,
    groups: &BTreeMap<(Group, EntityId), bool>,
    included: &BTreeSet<EntityId>,
    vault: bool,
    held_out: &mut BTreeSet<(ArchiveSideFamily, EntityId)>,
) -> Option<Option<EntityId>> {
    match travel {
        Travel::With(owner, _) | Travel::Broken(owner)
            if groups.get(&(family.spec().group, *owner)) == Some(&true) =>
        {
            Some(Some(*owner))
        }
        Travel::With(owner, _) | Travel::Broken(owner) => {
            if included.contains(owner) {
                held_out.insert((family, *owner));
            }
            None
        }
        Travel::Vault if vault => Some(None),
        Travel::Vault | Travel::Orphan => None,
    }
}

/// The manifest entries of the families `held_out` names, each once.
fn incomplete(
    held_out: BTreeSet<(ArchiveSideFamily, EntityId)>,
) -> impl Iterator<Item = ArchiveSideWithheld> {
    held_out
        .into_iter()
        .map(|(family, owner)| ArchiveSideWithheld {
            family,
            owner: Some(owner.to_hex()),
            reason: ArchiveSideWithheldReason::Incomplete,
            carriers: Vec::new(),
        })
}

/// Validates an archive's side rows: each reads back through its table's key
/// type and codec in the very form the exporter writes, no row repeats, and the
/// record and every carrier it names are entities the archive holds. Each row
/// is read from the import's row index alone (FIX 3678), which keeps its place
/// under its family and stored key.
pub(crate) fn validate_side_rows<R: Read + Seek>(
    archive: &mut IndexedArchive<'_, R>,
) -> Result<()> {
    let mut files = |file: &ExportBodyFile| file.read(&archive.files);
    let mut rows = archive.spool.rows(super::ArchiveRecordKind::SideTable);
    while let Some((loc, row)) = rows.next_parsed::<ArchiveSideRow>(&archive.spool)? {
        let bytes = row.stored(&mut files)?;
        let again = bytes
            .portable()?
            .ok_or_else(|| invalid("side row does not read back through its table"))?
            .0;
        if again != row {
            return Err(invalid("side row is not in the form its exporter writes"));
        }
        let key = side_key(row.family, &bytes.key);
        if !archive.index.insert(Tag::Side, &key, &loc.encode())? {
            return Err(invalid("side row appears twice"));
        }
        if matches!(
            row.family,
            ArchiveSideFamily::LfsObject
                | ArchiveSideFamily::LfsOwnerRef
                | ArchiveSideFamily::LfsChunkMark
                | ArchiveSideFamily::CodebaseFork
        ) {
            archive.index.put(Tag::SideContext, &key, &bytes.value)?;
        }
    }
    let context = side_context(&archive.index)?;
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, value)) = archive.index.next(Tag::Side, &[], after.as_deref())? {
        let row = archive
            .spool
            .parse::<ArchiveSideRow>(Loc::decode(&value)?)?
            .stored(&mut files)?;
        let held = match context.travel(row.family, &row.key, &row.value)? {
            Travel::With(owner, carriers) => {
                let mut held = row.owner == Some(owner)
                    && archive.index.contains(Tag::Entity, owner.as_bytes())?;
                for id in &carriers {
                    held = held && archive.index.contains(Tag::Entity, id.as_bytes())?;
                }
                held
            }
            Travel::Vault => row.owner.is_none(),
            Travel::Broken(_) | Travel::Orphan => false,
        };
        if !held {
            return Err(invalid(
                "side row names a record or carrier the archive does not hold",
            ));
        }
        after = Some(key);
    }
    Ok(())
}

/// Restores an archive's side rows in the import's write transaction, once its
/// entities are in: each family's records, then its indexes, then its heads, in
/// the order the import's row index keeps them (FIX 3678), one at a time.
/// A row whose record or carrier is not live here refuses the import; an
/// identical live row is unchanged, and any other live row under its key
/// refuses the import, never overwritten. Returns the rows written and those
/// already here.
pub(crate) fn restore_side_rows_in_txn<R: Read + Seek>(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
) -> Result<(usize, usize)> {
    let mut files = |file: &ExportBodyFile| file.read(&archive.files);
    let context = side_context(&archive.index)?;
    let (mut restored, mut unchanged) = (0, 0);
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, value)) = archive.index.next(Tag::Side, &[], after.as_deref())? {
        let row = archive
            .spool
            .parse::<ArchiveSideRow>(Loc::decode(&value)?)?
            .stored(&mut files)?;
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
        let stored = table.stored(store, wtxn, &row.key)?;
        let collides = || invalid("side row collides with a different stored row");
        let restore = match row.family {
            // A revision's author this vault erased never lands, and a twin
            // equal but for attribution is unchanged (FIX 6258).
            ArchiveSideFamily::CodeRevisionRecord | ArchiveSideFamily::CodeRevisionProposal => {
                match crate::code_revision::land_archived_revision_row_in_txn(
                    store,
                    wtxn,
                    row.family == ArchiveSideFamily::CodeRevisionProposal,
                    &row.value,
                    stored.as_deref(),
                )? {
                    ArchivedRevisionRow::Unchanged => None,
                    ArchivedRevisionRow::Restore(value) => Some(Cow::Owned(value)),
                    ArchivedRevisionRow::Collides => return Err(collides()),
                }
            }
            _ => match stored {
                Some(live) if live == row.value => None,
                Some(_) => return Err(collides()),
                None => Some(Cow::Borrowed(row.value.as_slice())),
            },
        };
        match restore {
            Some(value) => {
                table.restore(store, wtxn, &row.key, &value)?;
                restored += 1;
            }
            None => unchanged += 1,
        }
        after = Some(key);
    }
    Ok((restored, unchanged))
}

/// A side row's key in the import's row index: its family, then its stored
/// key, so the index keeps the restore order.
fn side_key(family: ArchiveSideFamily, key: &[u8]) -> Vec<u8> {
    let mut indexed = Vec::with_capacity(1 + key.len());
    indexed.push(family as u8);
    indexed.extend_from_slice(key);
    indexed
}

/// The owner context of the side rows the import's row index holds, read from
/// the rows it keeps for it.
fn side_context(index: &ArchiveIndex<'_>) -> Result<SideContext> {
    let mut failed = None;
    let context = SideContext::of(
        index
            .entries(Tag::SideContext)?
            .map_while(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(error) => {
                    failed = Some(error);
                    None
                }
            })
            .filter_map(|(key, value)| {
                let family = *key.first()?;
                let family = ArchiveSideFamily::ALL
                    .into_iter()
                    .find(|known| *known as u8 == family)?;
                Some((family, key.get(1..)?, value))
            }),
    );
    failed.map_or(Ok(context), Err)
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

impl Travel {
    /// Whether a row that travels so can go: with a record in `included`, or
    /// as a vault-wide row where those go (`vault`).
    fn goes(&self, included: &BTreeSet<EntityId>, vault: bool) -> bool {
        match self {
            Self::With(owner, _) => included.contains(owner),
            Self::Vault => vault,
            Self::Broken(_) | Self::Orphan => false,
        }
    }

    /// Where a row goes that names an entity an Owner's copy leaves out (fix
    /// list row 15416): nowhere, and its record's rows of its group with it.
    fn left_out(self) -> Self {
        match self {
            Self::With(owner, _) | Self::Broken(owner) => Self::Broken(owner),
            Self::Vault | Self::Orphan => Self::Orphan,
        }
    }
}

/// What a stored row of one family names as an Owner's copy reads it (fix list
/// row 15416), through its table's own key type and codec and the codec of
/// every typed record inside it: never a value guessed to be an id.
struct SideNames {
    /// The code document a code-document history row is of, as its key or
    /// value names it; `None` for every other row and for a generation row.
    document: Option<[u8; 32]>,
    /// The generation key of each repo path a code-document row's states
    /// stand at, or the one a generation row counts.
    paths: Vec<[u8; 32]>,
    /// Each entity row it names; `None` when the row, or a record inside it,
    /// does not read.
    rows: Option<Vec<EntityId>>,
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
fn side_names(family: ArchiveSideFamily, key: &[u8], value: &[u8]) -> Result<SideNames> {
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

/// What the side ledgers record each entity row's body was made from, read
/// once in an Owner's copy's own snapshot (fix list row 15416), through each
/// family's own codec and the codec of each record inside it: the copy judges
/// these before it reads a body, so a body whose words came from a member's
/// mailbox it leaves out stays home though no edge or stamp names that row.
///
/// - each version of a blob artifact's chain (its version and head records)
///   and each `blob.version` claim about it, which a replica holds without the
///   chain: every row its made_by names is a source of the artifact and of the
///   version's ledger claim, and, with the artifact, of one use of the ASSET
///   its bytes are;
/// - a born-from row: its task, ask or skill source, of its artifact;
/// - an edit settlement: every row its record names, of its artifact;
/// - a code revision's record, integrity fold, stranded proposal (the
///   revision inside it read through the revision's own codec) and promotion:
///   every row they name, its provenance claim among them, of the
///   CODE_ARTIFACT the revision is;
/// - a fork record: its parent session and base revision, of the forked
///   SESSION.
///
/// No other family records a source of a row's body: an LFS, codebase or
/// code-document row names no entity row's source, a code-memory value binds
/// a payload that stands as a row of its own, and a deck's marks, a claimed
/// hash pair, a refcount marker, a high-water mark, a revision's frontier and
/// every index repeat what these records hold.
#[derive(Default)]
pub(crate) struct SideProvenance {
    /// Each row whose body a side ledger records sources of, and every row
    /// those records name beside it: its body goes only when the copy carries
    /// every one. `None` when one of its records does not read.
    owned: BTreeMap<EntityId, Option<BTreeSet<EntityId>>>,
    /// Each content-addressed ASSET a blob version holds, and each recorded
    /// use of its bytes: the version's artifact and every row its made_by
    /// names, `None` when that does not read. Shared bytes go when the copy
    /// carries every row of one use; they stay home only when it carries no
    /// use whole.
    uses: BTreeMap<EntityId, Vec<Option<BTreeSet<EntityId>>>>,
}

impl SideProvenance {
    /// What the side ledgers record each row's body was made from, read in
    /// the snapshot `rtxn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn read_in(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        use crate::code_revision::ArchivedRevisionTable as R;
        use ArchiveSideFamily as F;
        let mut recorded = Self::default();
        for family in [
            F::BlobVersion,
            F::BlobHead,
            F::BlobBornFrom,
            F::BlobSettlement,
            F::CodeRevisionRecord,
            F::CodeRevisionIntegrity,
            F::CodeRevisionProposal,
            F::CodeRevisionPromotion,
            F::CodeRevisionFork,
        ] {
            for (key, value) in lent(family)?.stored_rows(store, rtxn)? {
                // The row a record is of, by its table's own key: a blob
                // row's artifact, a revision's CODE_ARTIFACT, a fork's
                // SESSION.
                let at = if family == F::BlobBornFrom {
                    ENTITY_ID_LEN + 1
                } else {
                    0
                };
                let Some(owner) = id_at(&key, at) else {
                    continue;
                };
                let rows = match family {
                    F::BlobVersion | F::BlobHead => {
                        match crate::blob_artifact::archive_version_source(&value) {
                            Some(version) => {
                                recorded.version(owner, version);
                                continue;
                            }
                            None => None,
                        }
                    }
                    F::BlobBornFrom => crate::blob_artifact::archive_born_from_rows(&key, &value),
                    F::BlobSettlement => crate::edit_settle::archive_settlement_rows(&value),
                    F::CodeRevisionRecord => {
                        crate::code_revision::archive_revision_rows(R::Record, &value)
                    }
                    F::CodeRevisionIntegrity => {
                        crate::code_revision::archive_revision_rows(R::Integrity, &value)
                    }
                    F::CodeRevisionProposal => {
                        crate::code_revision::archive_revision_rows(R::Proposal, &value)
                    }
                    F::CodeRevisionPromotion => {
                        crate::code_revision::archive_revision_rows(R::Promotion, &value)
                    }
                    F::CodeRevisionFork => {
                        crate::code_revision::archive_revision_rows(R::Fork, &value)
                    }
                    _ => continue,
                };
                recorded.record(owner, rows);
            }
        }
        for (artifact, version) in crate::blob_artifact::archive_claimed_versions(store, rtxn)? {
            recorded.version(artifact, version);
        }
        Ok(recorded)
    }

    /// The rows a record of `owner` names as sources of its body (`None`: a
    /// record that does not read), but `owner` itself.
    fn record(&mut self, owner: EntityId, rows: Option<Vec<EntityId>>) {
        let named = self
            .owned
            .entry(owner)
            .or_insert_with(|| Some(BTreeSet::new()));
        match rows {
            Some(rows) => {
                if let Some(named) = named {
                    named.extend(rows.into_iter().filter(|row| *row != owner));
                }
            }
            None => *named = None,
        }
    }

    /// One version of `artifact`: what made its bytes is a source of the
    /// artifact and of the version's ledger claim, and, with the artifact,
    /// one use of the ASSET those bytes are.
    fn version(
        &mut self,
        artifact: EntityId,
        version: crate::blob_artifact::ArchivedVersionSource,
    ) {
        self.record(artifact, version.made_by.clone());
        self.record(version.claim, version.made_by.clone());
        let asset = version.asset;
        let named: Option<BTreeSet<EntityId>> = version.made_by.map(|rows| {
            rows.into_iter()
                .chain([artifact])
                .filter(|row| *row != asset)
                .collect()
        });
        self.uses.entry(asset).or_default().push(named);
    }

    /// The rows the side ledgers record the body of `id` was made from, when
    /// `judge` carries every row its records name and, for bytes a blob
    /// version holds, every row of one recorded use of them: those rows, to
    /// count as carried once the body ships. `None` when the body stays home.
    /// A row no side ledger names goes as its own lineage judges it, with
    /// nothing beside it. Every recorded source is judged, so the copy's
    /// notices name each mailbox one of them is of.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn admitted(
        &self,
        judge: &mut ExportJudge<'_, '_, '_>,
        id: EntityId,
    ) -> Result<Option<Vec<EntityId>>> {
        let mut sources = Vec::new();
        let mut carried = true;
        if let Some(named) = self.owned.get(&id) {
            let named: Option<Vec<EntityId>> =
                named.as_ref().map(|named| named.iter().copied().collect());
            carried &= judge.carries_all(named.as_deref())?;
            sources.extend(named.into_iter().flatten());
        }
        if let Some(uses) = self.uses.get(&id) {
            let mut kept = false;
            for named in uses.iter().flatten() {
                let named: Vec<EntityId> = named.iter().copied().collect();
                if judge.carries_all(Some(named.as_slice()))? {
                    kept = true;
                    sources.extend(named);
                }
            }
            // A use whose made_by does not read is of a source this vault
            // cannot name, and keeps nothing.
            if !kept && uses.iter().any(Option::is_none) {
                judge.carries_all(None)?;
            }
            carried &= kept;
        }
        Ok(carried.then_some(sources))
    }
}

/// The code documents an Owner's copy holds out whole (fix list row 15416),
/// from what each of their rows names as its pass judged it.
#[derive(Default)]
struct DocumentHistories {
    /// Each document one of whose rows names a row the copy leaves out, or
    /// does not read.
    broken: BTreeSet<[u8; 32]>,
    /// The documents that stood at each repo path, by its generation key.
    at_path: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
}

impl DocumentHistories {
    fn of(judged: &[Option<(SideNames, bool)>]) -> Self {
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
    fn held(&self, names: &SideNames) -> Vec<[u8; 32]> {
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
            F::BlobVersion
            | F::BlobHighwater
            | F::BlobHead
            | F::BlobDeckMarks
            | F::BlobSettlement
            | F::BlobClaimedHash => with(id_at(key, 0), Vec::new()),
            F::BlobVersionClaim => with(id_at(key, 32), Vec::new()),
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
                let Ok(decoded) = crate::store::code_snapshot::decode_codebase_snapshot(value)
                else {
                    return Ok(Travel::Broken(snapshot));
                };
                let carriers = decoded
                    .files
                    .iter()
                    .map(|file| {
                        crate::store::code_snapshot::archive_codebase_asset_id(&file.content_hash)
                    })
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
            // A code document is no record: its id hashes its repo path, and
            // an ingress key is an operation id, so no key names an owner.
            F::CodeDocumentIngress
            | F::CodeDocumentFrontier
            | F::CodeDocumentPath
            | F::CodeDocumentGeneration
            | F::CodeDocumentHead => Travel::Vault,
            // A symbol's memory goes with its CODE_SYMBOL, and a binding with
            // the NOTE or CLAIM payload its key ends in.
            F::CodeMemorySlot => with(id_at(key, 0), Vec::new()),
            F::CodeMemoryAttachment | F::CodeMemoryAlwaysOn => {
                with(id_at(key, 0), tail(ENTITY_ID_LEN).into_iter().collect())
            }
            F::CodeMemoryTransfer => with(
                id_at(key, 0),
                id_at(key, ENTITY_ID_LEN).into_iter().collect(),
            ),
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
