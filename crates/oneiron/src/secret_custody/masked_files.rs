//! Files stored with keys in them (OF-560; ARCH-0069 #mask-on-write, owner
//! ruling G04 binary = C2). An ASSET is named by its bytes, so the write door
//! keeps a file's bytes as they are. It lifts each key it finds into its own
//! custody record and records here where the key sits and which record holds
//! it, and the file's band. Custody never holds a copy of the file.
//!
//! A serving door reads that record by the bytes' hash: the owner reads the
//! stored bytes; every other reader a copy with each key's span overwritten
//! by filler of the same length. The stored bytes never change, and a copy
//! the release door's scan still reads as secret is refused, never served.
//!
//! A key inside a container's member (a ZIP entry, a gzip payload, a PDF
//! stream) is marked at its span in the decoded member (OF-067 C). Its copy
//! is rebuilt: the member decoded, its keys overwritten, the container
//! encoded around it again (`batch::secret_scan::container`). A container
//! the write door kept no keys in is still read whole before a masked reader
//! gets it: one that holds a key no mark places is refused. A sealed one,
//! which no reader here reads whole (encrypted, malformed, past a bound), is
//! stored as it is (owner ruling C2): the owner and a granted agent read its
//! bytes (`reveal::file`), and a masked reader gets
//! [`SecretError::SealedFileWithheld`], never the raw bytes.

use heed::{RoTxn, RwTxn};

use crate::blob_artifact::ArtifactExport;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::federation::Sensitivity;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::vault::Vault;

/// The band a file with keys in it carries.
pub(crate) const MASKED_FILE_BAND: Sensitivity = Sensitivity::Restricted;

/// The byte a key's span reads as in a masked copy. A run of it is the
/// door's own mask shape (`********`), never secret material.
pub(super) const FILLER: u8 = b'*';

/// One row per file the write door kept with keys in it. Key: the blake3 hash
/// of the stored bytes, which every door that serves them holds.
const MASKED_FILE: SideTable<[u8; 32], MaskedFile, Named> =
    SideTable::new(&side_table::SECRET_MASK_SPANS);

/// Where the keys sit in one stored file. It holds no value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MaskedFile {
    pub(crate) band: Sensitivity,
    /// In the stored bytes, in byte order; none overlaps the next.
    pub(crate) keys: Vec<KeySpan>,
    pub(crate) masked_at: u64,
    /// The keys inside the file's members, one entry per member, in the
    /// order the walk meets them. A row written before members were read
    /// has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) members: Vec<MemberKeys>,
}

/// The keys in one member of a stored container: its path from the stored
/// bytes down, and each key's span in the member's decoded bytes, in byte
/// order. The path names no member by its name, which may hold a key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MemberKeys {
    pub(crate) path: Vec<MemberStep>,
    pub(crate) keys: Vec<KeySpan>,
}

/// One step from a container into a member it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberStep {
    /// A ZIP entry, by its place in the central directory.
    Zip { entry: u32 },
    /// A gzip file's payload: every member it chains, read as one.
    Gzip,
    /// A PDF stream, by its object's id.
    PdfStream { object: u32, generation: u16 },
}

/// Where a file's keys sit, without their records: one entry per place, the
/// stored bytes' own (an empty path) and each member's, with its spans.
pub(crate) type KeyPlaces = Vec<(Vec<MemberStep>, Vec<(u64, u64)>)>;

impl MaskedFile {
    /// Each place this row marks keys at.
    pub(crate) fn places(&self) -> KeyPlaces {
        let spans = |keys: &[KeySpan]| -> Vec<(u64, u64)> {
            keys.iter().map(|key| (key.start, key.end)).collect()
        };
        let mut places = Vec::with_capacity(self.members.len() + 1);
        if !self.keys.is_empty() {
            places.push((Vec::new(), spans(&self.keys)));
        }
        places.extend(
            self.members
                .iter()
                .map(|member| (member.path.clone(), spans(&member.keys))),
        );
        places
    }
}

/// One key: its byte span in the stored file, or in the decoded member that
/// holds it, and the custody record that holds its value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct KeySpan {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) custody: EntityId,
    /// The scan's reason code: the key's kind.
    pub(crate) reason: String,
}

/// How a serving door hands a file's bytes to its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSight {
    /// The vault owner, verified at the door, and the owner's own export:
    /// the stored bytes.
    Owner,
    /// Every other reader (an agent, a contact, a link): each key's span
    /// overwritten, in the file or in the member that holds it.
    Masked,
    /// An agent whose standing or approve-once grant covers the file's keys,
    /// with the read's receipt already written: the stored bytes.
    Granted,
}

pub(crate) fn masked_file_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<Option<MaskedFile>> {
    MASKED_FILE.get(store, txn, hash)
}

pub(crate) fn put_masked_file_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hash: &[u8; 32],
    file: &MaskedFile,
) -> Result<()> {
    MASKED_FILE.put(store, txn, hash, file)
}

/// Drops `custody`'s key from the mark of the file `hash` names, in its
/// stored bytes and in each member, and the mark with its last key: the
/// owner ruled it no secret.
pub(crate) fn drop_masked_key_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hash: &[u8; 32],
    custody: &EntityId,
) -> Result<()> {
    let Some(mut file) = masked_file_in_txn(store, txn, hash)? else {
        return Ok(());
    };
    file.keys.retain(|key| key.custody != *custody);
    for member in &mut file.members {
        member.keys.retain(|key| key.custody != *custody);
    }
    file.members.retain(|member| !member.keys.is_empty());
    if file.keys.is_empty() && file.members.is_empty() {
        MASKED_FILE.delete(store, txn, hash)?;
        return Ok(());
    }
    MASKED_FILE.put(store, txn, hash, &file)
}

/// `bytes` with each span in `spans` overwritten by the filler.
pub(crate) fn filled(bytes: &[u8], spans: impl IntoIterator<Item = (u64, u64)>) -> Result<Vec<u8>> {
    let mut copy = bytes.to_vec();
    for (start, end) in spans {
        usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| copy.get_mut(start..end))
            .ok_or(Error::CorruptedIndex("masked file key span"))?
            .fill(FILLER);
    }
    Ok(copy)
}

/// `bytes`, read from the store, as `sight` reads them. A file the write
/// door kept no keys in is served as it is, once a container's members read
/// clean to the write door.
pub(crate) fn sighted_bytes_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    bytes: Vec<u8>,
    sight: SecretSight,
) -> Result<Vec<u8>> {
    use crate::batch::secret_scan;
    if sight != SecretSight::Masked {
        return Ok(bytes);
    }
    let Some(file) = masked_file_in_txn(store, txn, blake3::hash(&bytes).as_bytes())? else {
        // A sealed file goes to the owner and a granted agent only: no mark
        // covers what it holds.
        if secret_scan::is_sealed(&bytes) {
            return Err(Error::Secret(SecretError::SealedFileWithheld));
        }
        // A container stored with the scan off, or one no mark covers, may
        // hold keys in its members: it is read before it is served.
        if secret_scan::is_container(&bytes) && secret_scan::scan_container_members(&bytes).is_err()
        {
            return Err(Error::InvariantViolation(
                "an unmarked file's members hold keys or cannot be read",
            ));
        }
        return Ok(bytes);
    };
    let copy = secret_scan::masked_copy(&bytes, &file.places())
        .map_err(|_| Error::InvariantViolation("a masked file's copy could not be rebuilt"))?;
    if secret_scan::scan_file_content("", &copy).is_some() {
        return Err(Error::InvariantViolation(
            "a masked file still reads as secret",
        ));
    }
    Ok(copy)
}

/// Whether the stored body of record `id` is a file with keys in it. A door
/// that hands whole stored records to a contact leaves it out: a contact
/// reads a key's handle only. A body kept in its file is named by the file's
/// digest, never by its manifest's (FIX 5507).
pub(crate) fn holds_masked_keys_in_txn(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(false);
    }
    let hash = match crate::store::asset_file_in_txn(store, txn, id, body)? {
        Some(manifest) => manifest.facts.blake3,
        None => *blake3::hash(body).as_bytes(),
    };
    Ok(masked_file_in_txn(store, txn, &hash)?.is_some())
}

impl Vault {
    /// `bytes`, read from this vault, as `sight` reads them (see
    /// [`SecretSight`]).
    pub fn sighted_asset_bytes(&self, bytes: Vec<u8>, sight: SecretSight) -> Result<Vec<u8>> {
        let rtxn = self.store.env.read_txn()?;
        sighted_bytes_in_txn(&self.store, &rtxn, bytes, sight)
    }

    /// [`Vault::export_blob_artifact`] for a reader at a serving door. The
    /// export's `content_hash` still names the stored version.
    pub fn export_blob_artifact_as(
        &self,
        id: &EntityId,
        version: Option<u64>,
        sight: SecretSight,
    ) -> Result<Option<ArtifactExport>> {
        let Some(mut file) = self.export_blob_artifact_as_raw(id, version, sight)? else {
            return Ok(None);
        };
        // FIX 4513: once, after custody read the stored bytes.
        file.bytes = self.resolve_docx_authors(std::mem::take(&mut file.bytes))?;
        Ok(Some(file))
    }

    /// [`Vault::export_blob_artifact_as`] with a DOCX's default-author token
    /// kept, for a door that reads the file's units and hands no file out. A
    /// version whose body is its ASSET's file is masked as it is read, never
    /// held whole beside its copy (FIX 6507).
    pub(crate) fn export_blob_artifact_as_raw(
        &self,
        id: &EntityId,
        version: Option<u64>,
        sight: SecretSight,
    ) -> Result<Option<ArtifactExport>> {
        let txn = self.store.env.read_txn()?;
        self.export_blob_artifact_read_in_txn(&txn, id, version, |record| {
            self.read_blob_artifact_version_sighted_in_txn(&txn, id, record.version, sight)?
                .ok_or(Error::EntityNotFound)
        })
    }

    /// [`Vault::read_blob_artifact_version`] for a reader at a serving door.
    /// A version whose body is its ASSET's file is read from the file as
    /// `sight` reads it (FIX 5507, `sighted_file`).
    pub fn read_blob_artifact_version_as(
        &self,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.read_blob_artifact_version_sighted_in_txn(&rtxn, artifact_id, version, sight)?
            // FIX 4513: once, after custody read the stored bytes.
            .map(|bytes| self.resolve_docx_authors_in_txn(&rtxn, bytes))
            .transpose()
    }

    /// The version an export of `artifact`'s `version` (the head when
    /// `None`) reads, with its stored digest, when that version's body is
    /// kept in its ASSET's file and a mark covers the file (FIX 6507): the
    /// stored bytes are verified through the checked reader and dropped as
    /// they pass, before any receipt is written. `None` for any other
    /// version, and for one whose bytes may not leave.
    pub(crate) fn marked_blob_version_file(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<(u64, [u8; 32])>> {
        let txn = self.store.env.read_txn()?;
        let version = match version {
            Some(version) => version,
            None => match crate::blob_artifact::read_blob_artifact_head_in_txn(
                &self.store,
                &txn,
                artifact,
            )? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        if self
            .blob_artifact_version_metadata_in_txn(&txn, artifact, version)?
            .is_none()
        {
            return Ok(None);
        }
        let Some((asset, hash)) =
            self.blob_artifact_version_file_in_txn(&txn, artifact, version)?
        else {
            return Ok(None);
        };
        if masked_file_in_txn(&self.store, &txn, &hash)?.is_none()
            || !self.check_body_file_in_txn(&txn, &asset, &hash)?
        {
            return Ok(None);
        }
        Ok(Some((version, hash)))
    }

    /// One version's bytes as `sight` reads them in `txn`, before any DOCX
    /// author projection. A body kept in its ASSET's file is read through
    /// the checked reader and masked as it passes ([`Self::sighted_body_file_in_txn`],
    /// FIX 5507, 6507); any other body is read whole, checked, and masked by
    /// its mark. `None` when the version's bytes may not leave.
    pub(crate) fn read_blob_artifact_version_sighted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        if let Some((asset, hash)) =
            self.blob_artifact_version_file_in_txn(txn, artifact_id, version)?
        {
            return self
                .sighted_body_file_in_txn(txn, &asset, &hash, sight)?
                .ok_or(Error::EntityNotFound)
                .map(Some);
        }
        self.read_blob_artifact_version_in_txn(txn, artifact_id, version)?
            .map(|bytes| sighted_bytes_in_txn(&self.store, txn, bytes, sight))
            .transpose()
    }
}
