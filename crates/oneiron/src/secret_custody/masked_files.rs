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

use heed::{RoTxn, RwTxn};

use crate::blob_artifact::ArtifactExport;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Sensitivity;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::vault::Vault;

/// The band a file with keys in it carries.
pub(crate) const MASKED_FILE_BAND: Sensitivity = Sensitivity::Restricted;

/// The byte a key's span reads as in a masked copy. A run of it is the
/// door's own mask shape (`********`), never secret material.
const FILLER: u8 = b'*';

/// One row per file the write door kept with keys in it. Key: the blake3 hash
/// of the stored bytes, which every door that serves them holds.
const MASKED_FILE: SideTable<[u8; 32], MaskedFile, Named> =
    SideTable::new(&side_table::SECRET_MASK_SPANS);

/// Where the keys sit in one stored file. It holds no value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MaskedFile {
    pub(crate) band: Sensitivity,
    /// In byte order; none overlaps the next.
    pub(crate) keys: Vec<KeySpan>,
    pub(crate) masked_at: u64,
}

/// One key: its byte span in the stored file and the custody record that
/// holds its value.
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
    /// overwritten.
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

/// Drops `custody`'s key from the mark of the file `hash` names, and the mark
/// with its last key: the owner ruled it no secret.
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
    if file.keys.is_empty() {
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
/// door kept no keys in is served as it is.
pub(crate) fn sighted_bytes_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    bytes: Vec<u8>,
    sight: SecretSight,
) -> Result<Vec<u8>> {
    if sight != SecretSight::Masked {
        return Ok(bytes);
    }
    let Some(file) = masked_file_in_txn(store, txn, blake3::hash(&bytes).as_bytes())? else {
        return Ok(bytes);
    };
    let copy = filled(&bytes, file.keys.iter().map(|key| (key.start, key.end)))?;
    if crate::batch::secret_scan::scan_file_content("", &copy).is_some() {
        return Err(Error::InvariantViolation(
            "a masked file still reads as secret",
        ));
    }
    Ok(copy)
}

/// Whether a stored record body is a file with keys in it. A door that hands
/// whole stored records to a contact leaves it out: a contact reads a key's
/// handle only.
pub(crate) fn holds_masked_keys_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    entity_type: u8,
    body: &[u8],
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(false);
    }
    Ok(masked_file_in_txn(store, txn, blake3::hash(body).as_bytes())?.is_some())
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
        let Some(mut file) = self.export_blob_artifact(id, version)? else {
            return Ok(None);
        };
        file.bytes = self.sighted_asset_bytes(std::mem::take(&mut file.bytes), sight)?;
        Ok(Some(file))
    }

    /// [`Vault::read_blob_artifact_version`] for a reader at a serving door.
    pub fn read_blob_artifact_version_as(
        &self,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.read_blob_artifact_version_in_txn(&rtxn, artifact_id, version)?
            .map(|bytes| sighted_bytes_in_txn(&self.store, &rtxn, bytes, sight))
            .transpose()
    }
}
