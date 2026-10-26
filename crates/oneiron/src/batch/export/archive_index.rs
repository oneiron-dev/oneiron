//! FIX 3678 (rule 5): the whole-vault import's disk-backed row index. The
//! archive's record rows are copied once, as they are read, into an anonymous
//! spool under the vault's staging directory, and a scratch LMDB environment
//! there ([`crate::store::ScratchEnv`]) keeps only where each row is and the
//! keys the cross-row checks join on: entity ids, edge keys, derivation
//! claims, skill names, claim subjects, provenance and expression histories,
//! side-row keys, and the import's growing id and dependency sets. A row is
//! read back from the spool and decoded only when a check or a write needs it,
//! one at a time, so no archive-wide row state stays in memory. One row, one
//! history or the manifest is a codec unit and is read whole.
use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};

use heed::types::Bytes;
use heed::{Database, Env, RwTxn};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{ArchiveFileSource, ArchiveRecordKind, ExportEntity, WholeVaultDocumentManifest};
use crate::Vault;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

/// Writes between two commits of the scratch index's transaction, so its
/// dirty pages stay few however long the archive is.
const INDEX_COMMIT_EVERY: u32 = 4096;

/// Where one row is in the spool: its first byte and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Loc {
    at: u64,
    len: u64,
}

impl Loc {
    pub(crate) const LEN: usize = 16;

    pub(crate) fn encode(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[..8].copy_from_slice(&self.at.to_be_bytes());
        bytes[8..].copy_from_slice(&self.len.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let word = |at: usize| -> Result<u64> {
            bytes
                .get(at..at + 8)
                .and_then(|word| <[u8; 8]>::try_from(word).ok())
                .map(u64::from_be_bytes)
                .ok_or(Error::InvariantViolation("archive index locator"))
        };
        Ok(Self {
            at: word(0)?,
            len: word(8)?,
        })
    }
}

/// The scratch index's tables, each a key prefix in its one database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    /// Entity id → [`EntityAt`].
    Entity = 1,
    /// Archived entity type, entity id → ().
    ByType,
    /// Edge source, kind, target → its row and whether it is provenanced.
    Edge,
    /// The same edge with its MODEL endpoints mapped here → its row; the
    /// first edge in archive order holds a key.
    MappedEdge,
    /// Claim id → its derivation envelope's row.
    Derivation,
    /// Pack source ASSET id → ().
    PackSource,
    /// Agent id → its agent pack row.
    Agent,
    /// Skill id's BLAKE3 (16 bytes), skill entity id → ().
    SkillName,
    /// Claim subject entity id, claim id → (): claims about an entity.
    About,
    /// Provenance subject edge source, kind, target → ().
    ProvenanceSubject,
    /// Skill id → (): a redacted skill source's refusal.
    SourceRefusal,
    /// Embedding space id's BLAKE3 → the id.
    Space,
    /// Side-row family, stored key → its row.
    Side,
    /// Side-row family, stored key → stored value, for the families the
    /// side-row owner context reads.
    SideContext,
    /// Entity id → (): omitted from the import.
    Omitted,
    /// Archive MODEL id → its local id.
    Model,
    /// Local MODEL id → (): here before the import, or restored by it.
    LocalModel,
    /// Entity id → the ids its row waits on.
    Pending,
    /// Entity id → (): pending in any queue.
    Waiting,
    /// Entity id → (): inserted, or pending insertion.
    Inserted,
    /// Mapped subject edge, learned-at, id → the ids the row waits on.
    Cohort,
    /// First id → its cohort's mapped subject edge.
    CohortPending,
    /// Mapped subject, predicate, NUL, learned-at, id → ().
    History,
    /// First id → its history's mapped subject, predicate and NUL.
    HistoryPending,
    /// Superseding id, superseded id → the supersession's time.
    Supersedes,
    /// Custody record id → ().
    Secret,
    /// Project id → its parent shape, signature, home room and parents.
    Project,
    /// Project id → (): archived with the source root.
    ProjectArchived,
    /// Queue, id → (): this round's ready rows.
    Ready,
    /// Result body digest → (): a body the export released.
    Released,
    /// Result body digest → (): its first occurrence was checked.
    Staged,
}

/// The import's disk index: one LMDB database in the scratch environment,
/// written in one transaction that commits every [`INDEX_COMMIT_EVERY`]
/// writes and is never read by anyone else.
pub(crate) struct ArchiveIndex<'e> {
    env: &'e Env,
    db: Database<Bytes, Bytes>,
    txn: Option<RwTxn<'e>>,
    writes: u32,
}

impl<'e> ArchiveIndex<'e> {
    pub(crate) fn open(env: &'e Env) -> Result<Self> {
        let mut txn = env.write_txn()?;
        let db: Database<Bytes, Bytes> = env.create_database(&mut txn, None)?;
        Ok(Self {
            env,
            db,
            txn: Some(txn),
            writes: 0,
        })
    }

    fn txn(&self) -> Result<&RwTxn<'e>> {
        self.txn
            .as_ref()
            .ok_or(Error::InvariantViolation("archive index closed"))
    }

    fn key(tag: Tag, key: &[u8]) -> Vec<u8> {
        let mut full = Vec::with_capacity(1 + key.len());
        full.push(tag as u8);
        full.extend_from_slice(key);
        full
    }

    pub(crate) fn get(&self, tag: Tag, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .get(self.txn()?, &Self::key(tag, key))?
            .map(<[u8]>::to_vec))
    }

    pub(crate) fn contains(&self, tag: Tag, key: &[u8]) -> Result<bool> {
        Ok(self.db.get(self.txn()?, &Self::key(tag, key))?.is_some())
    }

    pub(crate) fn put(&mut self, tag: Tag, key: &[u8], value: &[u8]) -> Result<()> {
        let full = Self::key(tag, key);
        let db = self.db;
        let txn = self
            .txn
            .as_mut()
            .ok_or(Error::InvariantViolation("archive index closed"))?;
        db.put(txn, &full, value)?;
        self.tick()
    }

    /// Writes `key` unless it is present; whether it was absent.
    pub(crate) fn insert(&mut self, tag: Tag, key: &[u8], value: &[u8]) -> Result<bool> {
        if self.contains(tag, key)? {
            return Ok(false);
        }
        self.put(tag, key, value)?;
        Ok(true)
    }

    /// Removes `key`; whether it was present.
    pub(crate) fn remove(&mut self, tag: Tag, key: &[u8]) -> Result<bool> {
        let full = Self::key(tag, key);
        let db = self.db;
        let txn = self
            .txn
            .as_mut()
            .ok_or(Error::InvariantViolation("archive index closed"))?;
        let removed = db.delete(txn, &full)?;
        self.tick()?;
        Ok(removed)
    }

    /// The first entry of `tag` whose key starts with `prefix` and sorts
    /// after `after` (from the prefix when `None`): its key and value.
    pub(crate) fn next(
        &self,
        tag: Tag,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let txn = self.txn()?;
        let entry = match after {
            Some(after) => self.db.get_greater_than(txn, &Self::key(tag, after))?,
            None => self
                .db
                .get_greater_than_or_equal_to(txn, &Self::key(tag, prefix))?,
        };
        let full = Self::key(tag, prefix);
        Ok(entry
            .filter(|(key, _)| key.starts_with(&full))
            .map(|(key, value)| (key[1..].to_vec(), value.to_vec())))
    }

    /// Every entry of `tag` in key order, borrowed from the index: each key
    /// without its tag, and its value.
    pub(crate) fn entries(
        &self,
        tag: Tag,
    ) -> Result<impl Iterator<Item = Result<(&[u8], &[u8])>> + '_> {
        let prefix = [tag as u8];
        Ok(self.db.prefix_iter(self.txn()?, &prefix[..])?.map(|entry| {
            entry
                .map(|(key, value)| (&key[1..], value))
                .map_err(Error::from)
        }))
    }

    /// How many entries `tag` holds.
    pub(crate) fn count(&self, tag: Tag) -> Result<usize> {
        let mut count = 0;
        for entry in self.entries(tag)? {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    /// Whether `tag` holds any key starting with `prefix`.
    pub(crate) fn any(&self, tag: Tag, prefix: &[u8]) -> Result<bool> {
        Ok(self.next(tag, prefix, None)?.is_some())
    }

    fn tick(&mut self) -> Result<()> {
        self.writes += 1;
        if self.writes < INDEX_COMMIT_EVERY {
            return Ok(());
        }
        self.writes = 0;
        if let Some(txn) = self.txn.take() {
            txn.commit()?;
        }
        self.txn = Some(self.env.write_txn()?);
        Ok(())
    }
}

/// The archive's record rows, copied once as they are read: each row a
/// length and its bytes, each member a contiguous run.
pub(crate) struct ArchiveSpool {
    file: File,
    writer: Option<BufWriter<File>>,
    end: u64,
    members: Vec<(ArchiveRecordKind, u64, u64)>,
    member_start: u64,
}

impl ArchiveSpool {
    pub(crate) fn new(vault: &Vault) -> Result<Self> {
        let file = vault.archive_spool_file()?;
        let writer = BufWriter::new(file.try_clone()?);
        Ok(Self {
            file,
            writer: Some(writer),
            end: 0,
            members: Vec::new(),
            member_start: 0,
        })
    }

    /// Starts the spool of one member's rows.
    pub(crate) fn begin_member(&mut self) {
        self.member_start = self.end;
    }

    /// Ends the member of `kind` begun last.
    pub(crate) fn end_member(&mut self, kind: ArchiveRecordKind) {
        self.members.push((kind, self.member_start, self.end));
    }

    /// Spools one row; where it is.
    pub(crate) fn push(&mut self, row: &[u8]) -> Result<Loc> {
        let writer = self
            .writer
            .as_mut()
            .ok_or(Error::InvariantViolation("archive spool sealed"))?;
        let len = row.len() as u64;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(row)?;
        let loc = Loc {
            at: self.end + 8,
            len,
        };
        self.end = loc.at + len;
        Ok(loc)
    }

    /// Ends the writing: from here on rows are only read.
    pub(crate) fn seal(&mut self) -> Result<()> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush()?;
        }
        Ok(())
    }

    fn read_at(&self, buffer: &mut [u8], at: u64) -> Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_exact_at(&self.file, buffer, at)?;
        }
        #[cfg(not(unix))]
        {
            let mut file = &self.file;
            file.seek(std::io::SeekFrom::Start(at))?;
            file.read_exact(buffer)?;
        }
        Ok(())
    }

    /// The row at `loc`.
    pub(crate) fn read(&self, loc: Loc) -> Result<Vec<u8>> {
        let len = usize::try_from(loc.len)
            .map_err(|_| Error::InvariantViolation("archive spool row length"))?;
        let mut row = vec![0; len];
        self.read_at(&mut row, loc.at)?;
        Ok(row)
    }

    /// The row at `loc`, parsed.
    pub(crate) fn parse<T: DeserializeOwned>(&self, loc: Loc) -> Result<T> {
        serde_json::from_slice(&self.read(loc)?)
            .map_err(|_| Error::InvariantViolation("archive spool row"))
    }

    /// A cursor over the rows of `kind`, in archive order.
    pub(crate) fn rows(&self, kind: ArchiveRecordKind) -> SpoolRows {
        SpoolRows {
            ranges: self
                .members
                .iter()
                .filter(|(member, _, _)| *member == kind)
                .map(|(_, start, end)| (*start, *end))
                .collect(),
            index: 0,
            at: None,
        }
    }
}

/// The rows of one kind, read back one at a time.
pub(crate) struct SpoolRows {
    ranges: Vec<(u64, u64)>,
    index: usize,
    at: Option<u64>,
}

impl SpoolRows {
    /// The next row and where it is.
    pub(crate) fn next(&mut self, spool: &ArchiveSpool) -> Result<Option<(Loc, Vec<u8>)>> {
        while let Some((start, end)) = self.ranges.get(self.index).copied() {
            let at = self.at.unwrap_or(start);
            if at >= end {
                self.index += 1;
                self.at = None;
                continue;
            }
            let mut len = [0; 8];
            spool.read_at(&mut len, at)?;
            let loc = Loc {
                at: at + 8,
                len: u64::from_le_bytes(len),
            };
            self.at = Some(loc.at + loc.len);
            return Ok(Some((loc, spool.read(loc)?)));
        }
        Ok(None)
    }

    /// The next row, parsed.
    pub(crate) fn next_parsed<T: DeserializeOwned>(
        &mut self,
        spool: &ArchiveSpool,
    ) -> Result<Option<(Loc, T)>> {
        let Some((loc, row)) = self.next(spool)? else {
            return Ok(None);
        };
        let row = serde_json::from_slice(&row)
            .map_err(|_| Error::InvariantViolation("archive spool row"))?;
        Ok(Some((loc, row)))
    }
}

/// Which document section an entity row is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Ledger = 0,
    Claim = 1,
    Skill = 2,
}

/// The row's body is an archive file (OF-222).
pub(crate) const FLAG_FILE: u8 = 1;
/// The row is an edge-provenance claim.
pub(crate) const FLAG_PROVENANCE: u8 = 1 << 1;
/// The row is an expression-preference claim.
pub(crate) const FLAG_EXPRESSION: u8 = 1 << 2;
/// The row is archive-only.
pub(crate) const FLAG_ARCHIVE_ONLY: u8 = 1 << 3;
/// The row is an evidence-ledger ASSET holding a pack source body.
pub(crate) const FLAG_PACK_SOURCE: u8 = 1 << 4;
/// The row's body is a runtime pack instance's envelope.
pub(crate) const FLAG_PACK_BODY: u8 = 1 << 5;

/// The ready queue of edge-provenance cohorts.
pub(crate) const QUEUE_PROVENANCE: u8 = 0;
/// The ready queue of expression histories.
pub(crate) const QUEUE_EXPRESSION: u8 = 1;
/// The ready queue of entity rows.
pub(crate) const QUEUE_ROW: u8 = 2;

/// The ready-queue key of `id` in `queue`.
pub(crate) fn ready_key(queue: u8, id: &EntityId) -> Vec<u8> {
    let mut key = vec![queue];
    key.extend_from_slice(id.as_bytes());
    key
}

/// Where one entity row is, and what its checks noted about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntityAt {
    pub(crate) section: Section,
    pub(crate) entity_type: u8,
    pub(crate) flags: u8,
    pub(crate) loc: Loc,
}

impl EntityAt {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut bytes = vec![self.section as u8, self.entity_type, self.flags];
        bytes.extend_from_slice(&self.loc.encode());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let section = match bytes.first() {
            Some(0) => Section::Ledger,
            Some(1) => Section::Claim,
            Some(2) => Section::Skill,
            _ => return Err(Error::InvariantViolation("archive index entity")),
        };
        Ok(Self {
            section,
            entity_type: *bytes
                .get(1)
                .ok_or(Error::InvariantViolation("archive index entity"))?,
            flags: *bytes
                .get(2)
                .ok_or(Error::InvariantViolation("archive index entity"))?,
            loc: Loc::decode(bytes.get(3..).unwrap_or_default())?,
        })
    }

    pub(crate) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// A skill row's entity, its source tree left in the spool.
#[derive(Deserialize)]
struct SkillEntity {
    entity: ExportEntity,
}

/// An archive read into the index (FIX 3678): its manifest, its attached
/// files (still in the archive), its spooled rows and the index over them.
pub(crate) struct IndexedArchive<'e, R: Read + Seek> {
    pub(crate) manifest: WholeVaultDocumentManifest,
    pub(crate) files: ArchiveFileSource<R>,
    pub(crate) spool: ArchiveSpool,
    pub(crate) index: ArchiveIndex<'e>,
    /// Whether any row is an expression preference, noted by validation.
    pub(crate) expressions: bool,
    /// The archive's kind slots (OF-370), one per kind; `None` when it
    /// carries no slot rows.
    pub(crate) slot_bindings: Option<super::PortableSlotBindings>,
}

impl<R: Read + Seek> IndexedArchive<'_, R> {
    /// Where the entity `id` is, when the archive holds it.
    pub(crate) fn entity_at(&self, id: &EntityId) -> Result<Option<EntityAt>> {
        self.index
            .get(Tag::Entity, id.as_bytes())?
            .map(|bytes| EntityAt::decode(&bytes))
            .transpose()
    }

    /// The entity row at `at`.
    pub(crate) fn entity_row(&self, at: &EntityAt) -> Result<ExportEntity> {
        entity_of(at.section, &self.spool.read(at.loc)?)
    }

    /// The entity `id` and where it is, when the archive holds it.
    pub(crate) fn entity(&self, id: &EntityId) -> Result<Option<(EntityAt, ExportEntity)>> {
        let Some(at) = self.entity_at(id)? else {
            return Ok(None);
        };
        Ok(Some((at, self.entity_row(&at)?)))
    }

    /// The row at `loc` of a kind holding a source tree. A member stored as
    /// a file stays its descriptor, read from the archive's files when its
    /// tree is validated or imported (FIX 10101).
    pub(crate) fn hydrated<T: DeserializeOwned>(&self, loc: Loc) -> Result<T> {
        self.spool.parse(loc)
    }

    /// The next entity id after `after` in id order, with where it is.
    pub(crate) fn next_entity(
        &self,
        after: Option<&EntityId>,
    ) -> Result<Option<(EntityId, EntityAt)>> {
        let Some((key, value)) =
            self.index
                .next(Tag::Entity, &[], after.map(|id| id.as_bytes().as_slice()))?
        else {
            return Ok(None);
        };
        Ok(Some((id_at(&key, 0)?, EntityAt::decode(&value)?)))
    }

    /// The next entity id of the archived type `entity_type` after `after`.
    pub(crate) fn next_of_type(
        &self,
        entity_type: u8,
        after: Option<&EntityId>,
    ) -> Result<Option<EntityId>> {
        let after = after.map(|id| typed_key(entity_type, id));
        let Some((key, _)) = self
            .index
            .next(Tag::ByType, &[entity_type], after.as_deref())?
        else {
            return Ok(None);
        };
        id_at(&key, 1).map(Some)
    }
}

/// The entity a spooled row of `section` holds: a skill row's is its
/// bundle's, its source tree left unread.
pub(crate) fn entity_of(section: Section, row: &[u8]) -> Result<ExportEntity> {
    let parsed = if section == Section::Skill {
        serde_json::from_slice::<SkillEntity>(row).map(|bundle| bundle.entity)
    } else {
        serde_json::from_slice(row)
    };
    parsed.map_err(|_| Error::InvariantViolation("archive spool row"))
}

/// The index key of an edge: its source, kind and target.
pub(crate) fn edge_key(source: &EntityId, kind: u8, target: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 * ENTITY_ID_LEN + 1);
    key.extend_from_slice(source.as_bytes());
    key.push(kind);
    key.extend_from_slice(target.as_bytes());
    key
}

/// The type index key of `id`.
pub(crate) fn typed_key(entity_type: u8, id: &EntityId) -> Vec<u8> {
    let mut key = vec![entity_type];
    key.extend_from_slice(id.as_bytes());
    key
}

/// The entity id at `at` of an index key or value.
pub(crate) fn id_at(bytes: &[u8], at: usize) -> Result<EntityId> {
    bytes
        .get(at..at + ENTITY_ID_LEN)
        .and_then(|id| <[u8; ENTITY_ID_LEN]>::try_from(id).ok())
        .map(EntityId::from_bytes)
        .ok_or(Error::InvariantViolation("archive index id"))?
}

/// `ids`, each 16 bytes, one after another.
pub(crate) fn id_list(ids: &[EntityId]) -> Vec<u8> {
    ids.iter().flat_map(|id| *id.as_bytes()).collect()
}

/// The ids of an [`id_list`].
pub(crate) fn ids_of(bytes: &[u8]) -> Result<Vec<EntityId>> {
    bytes.chunks(ENTITY_ID_LEN).map(|id| id_at(id, 0)).collect()
}
