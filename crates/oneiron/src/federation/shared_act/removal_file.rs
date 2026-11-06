//! A kept removal archive's bytes as a file (FIX 3679, 3857): one complete
//! body in the vault's `bodies/` under an instance of its own, sealed under
//! it where the vault seals its bodies and bound to it plain where it does
//! not, owned by its archive row's owner ([`removal_archive_owner`]: the
//! removed member and the receipt) under an occurrence of its own. The
//! archive's row keeps the occurrence and the body it names; no LMDB value
//! holds the archive.
//!
//! A file is written and published before the writer that names it opens
//! (its instance is minted there), and its descriptor commits with the row
//! in that writer; one no writer names is debris the orphan collector
//! takes. A rewrite publishes a new file under a fresh occurrence and
//! releases the old one in the writer that swaps them: a complete body is
//! never written over. Expiry releases the file; an erase releases it and
//! retires its instance, or owes that retirement while the file still
//! serves until its rewrite lands. The descriptor is storage, never a read
//! permit: only the removal doors' own proof reaches a file.

use std::io::{Read, Seek, SeekFrom};

use super::ArchiveRow;
use crate::error::{Error, Result};
use crate::provenance::body::BodyRef;
use crate::{EntityId, Vault};

/// Where a kept removal archive's bytes are: the body `body`, its archive
/// owner's occurrence `occurrence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveFile {
    pub(super) occurrence: EntityId,
    pub(super) body: BodyRef,
}

impl ArchiveFile {
    /// BLAKE3 of the archive's bytes, lowercase hex.
    pub(super) fn digest(&self) -> String {
        blake3::Hash::from_bytes(self.body.blake3)
            .to_hex()
            .to_string()
    }
}

/// An archive written to a published body file, before the writer that
/// names it opens. It holds the file's instance row and lease and the
/// reader pin on its digest until that writer is done; dropped unnamed, the
/// file is debris.
pub(super) struct StagedArchive {
    body: BodyRef,
    #[cfg(unix)]
    key: crate::store::StagedBodyKey,
    #[cfg(unix)]
    _pin: crate::store::result_body_pins::ResultBodyPin,
}

impl StagedArchive {
    /// The archive's body: its digest, length and place.
    pub(super) const fn body(&self) -> &BodyRef {
        &self.body
    }
}

/// The owner the archive files of the row `row` are held under: derived
/// from its receipt and its removed member in a namespace of its own, never
/// a record's id, so a release of one row's archives reaches no other row's
/// bodies, another member's archive of the same receipt included, whatever
/// ids an imported copy names.
///
/// # Errors
///
/// A derivation that lands on a reserved id.
pub(crate) fn removal_archive_owner(row: ArchiveRow) -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::REMOVAL_ARCHIVE_OWNER,
        &[row.receipt.as_bytes(), row.member.as_bytes()],
    )
}

/// BLAKE3 and length of everything `source` holds, read from its start.
fn measure(source: &mut (impl Read + Seek)) -> Result<([u8; 32], u64)> {
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let len = std::io::copy(source, &mut hasher)?;
    source.seek(SeekFrom::Start(0))?;
    Ok((*hasher.finalize().as_bytes(), len))
}

#[cfg(unix)]
impl Vault {
    /// Writes the archive `source` holds, from its start, as a published
    /// body file: measured first, then streamed into the vault's `bodies/`
    /// under an instance minted here, sealed under it when the directory
    /// seals. A plain vault's file takes its instance now too, as every
    /// vault body file does: an image that later seals the file seals it
    /// under this instance, which an erase of the archive then owes, never
    /// one minted after the erase. Call it before the writer that names it
    /// opens.
    ///
    /// # Errors
    ///
    /// An empty archive, custody and filesystem errors; nothing is left
    /// behind but debris the collector takes.
    pub(super) fn stage_removal_archive(
        &self,
        source: &mut (impl Read + Seek),
    ) -> Result<StagedArchive> {
        use crate::provenance::body::BodyLocation;
        let (digest, len) = measure(source)?;
        if len == 0 {
            return Err(Error::InvariantViolation("a removal archive is empty"));
        }
        // Pinned before it is published: the collector leaves it be until
        // the writer that names it is done.
        let pin = self.pin_result_body(digest);
        let dir = self.store.body_dir()?;
        let instance = self.store.body_mint()?.mint()?;
        let key = dir.import_sealing(&digest, len, source, false, instance)?;
        Ok(StagedArchive {
            body: BodyRef {
                blake3: digest,
                bytes: len,
                location: BodyLocation::File,
            },
            key,
            _pin: pin,
        })
    }

    /// Names `staged` as the archive of the row `row` in `wtxn`, the writer
    /// that keeps that row: its instance row and a complete descriptor under
    /// a fresh occurrence of the row's archive owner.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors.
    pub(super) fn bind_removal_archive_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        staged: &StagedArchive,
    ) -> Result<ArchiveFile> {
        use crate::provenance::body::{BodyState, OwnedBody, publish_body_in_txn};
        crate::store::bind_body_key_in_txn(
            &self.store,
            wtxn,
            &self.store.body_dir()?,
            &staged.key,
        )?;
        let occurrence = self.store.clock.entity_id()?;
        publish_body_in_txn(
            &self.store,
            wtxn,
            &OwnedBody {
                owner: removal_archive_owner(row)?,
                occurrence,
                state: BodyState::Complete {
                    body: staged.body.clone(),
                },
                result: None,
            },
        )?;
        Ok(ArchiveFile {
            occurrence,
            body: staged.body.clone(),
        })
    }

    /// The bytes of the row `row`'s archive `file`, as `txn` names
    /// it: its descriptor must be complete with this body, and the file is
    /// read through the instance row `txn` holds and checked against its
    /// digest. A writer's snapshot keeps the file: no release of it commits
    /// while the writer is open.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a descriptor, file or digest that does
    /// not match; storage and filesystem errors.
    pub(super) fn read_removal_archive_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: ArchiveRow,
        file: &ArchiveFile,
    ) -> Result<Vec<u8>> {
        let named = crate::provenance::body::owned_body_in_txn(
            &self.store,
            txn,
            &removal_archive_owner(row)?,
            &file.occurrence,
        )?
        .is_some_and(|held| {
            held.state
                == crate::provenance::body::BodyState::Complete {
                    body: file.body.clone(),
                }
        });
        if !named {
            return Err(Error::CorruptedIndex("removal archive descriptor"));
        }
        let key = crate::store::body_key_row_in_txn(&self.store, txn, &file.body.blake3)?;
        let mut reader = self
            .store
            .body_dir()?
            .open_reader(&file.body.blake3, file.body.bytes, key.as_ref())?
            .ok_or(Error::CorruptedIndex("removal archive file"))?;
        let mut bytes = Vec::with_capacity(usize::try_from(file.body.bytes).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        if blake3::hash(&bytes).as_bytes() != &file.body.blake3 {
            return Err(Error::CorruptedIndex("removal archive digest"));
        }
        Ok(bytes)
    }

    /// Releases the archive file `file` of the row `row` in `wtxn`: its
    /// descriptor goes, and its digest, when nothing else holds it, is
    /// queued for the collector. An erase that owes its instance a
    /// retirement stages it now.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn release_removal_archive_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        file: &ArchiveFile,
    ) -> Result<()> {
        crate::provenance::body::release_body_in_txn(
            &self.store,
            wtxn,
            &removal_archive_owner(row)?,
            &file.occurrence,
        )?;
        Ok(())
    }

    /// Releases every archive file of the row `row` in `wtxn`, read from its
    /// archive owner's descriptors alone, so an archive row that does not
    /// decode strands no file, and no other row's body is reached, another
    /// member's archive of the same receipt included. With `erase`, that
    /// record's erase retires each file's instances, or owes it while
    /// another holder keeps the bytes, and its receipt names them.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(super) fn release_removal_archives_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        erase: Option<EntityId>,
    ) -> Result<()> {
        use crate::provenance::body::{owned_bodies_in_txn, release_owner_bodies_in_txn};
        let owner = removal_archive_owner(row)?;
        let held: Vec<[u8; 32]> = owned_bodies_in_txn(&self.store, wtxn, &owner)?
            .iter()
            .filter_map(|body| body.state.held().map(|held| held.blake3))
            .collect();
        release_owner_bodies_in_txn(&self.store, wtxn, &owner)?;
        if let Some(cause) = erase {
            crate::store::erase_bodies_for_owner_in_txn(
                &self.store,
                wtxn,
                &cause,
                &owner,
                &held,
                false,
            )?;
        }
        Ok(())
    }

    /// The erase of the record `cause` owes the instance of the row `row`'s
    /// archive `file` a retirement, in that erase's writer: the file still
    /// holds the erased record until its rewrite lands, and the rewrite's
    /// release of it stages the retirement. The erase's receipt names it.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(super) fn owe_removal_archive_erase_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        file: &ArchiveFile,
        cause: EntityId,
    ) -> Result<()> {
        crate::store::erase_bodies_for_owner_in_txn(
            &self.store,
            wtxn,
            &cause,
            &removal_archive_owner(row)?,
            &[file.body.blake3],
            false,
        )
    }
}

/// Adds to `keys` the `vault_meta` keys a left environment keeps for the
/// archive files of every removal archive row `store` holds (FIX 3679): each
/// row's archive descriptors, and the digest, instance, key and erase
/// debt rows they stand on. An archive owner is no kept entity, so its
/// descriptors are spelled here, and the leave's body collector finds every
/// kept archive's file named.
///
/// # Errors
///
/// Storage errors, and a descriptor that does not decode.
#[cfg(all(unix, feature = "sync"))]
pub(crate) fn removal_archive_body_keys_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    keys: &mut std::collections::HashSet<Vec<u8>>,
) -> Result<()> {
    use crate::provenance::body::owned_bodies_in_txn;
    for row_key in super::REMOVAL_EXPORT.scan_keys(store, txn, b"")? {
        let Some(row) = ArchiveRow::from_key(&row_key) else {
            continue;
        };
        let owner = removal_archive_owner(row)?;
        for body in owned_bodies_in_txn(store, txn, &owner)? {
            keys.insert(crate::store::owned_body::BODY.key_bytes(&(body.owner, body.occurrence)));
        }
        crate::provenance::body::retained_body_side_keys_in_txn(store, txn, &owner, keys)?;
    }
    Ok(())
}

/// A host without the vault's body store keeps no removal archive: the
/// store is where its bytes go.
#[cfg(not(unix))]
impl Vault {
    pub(super) fn stage_removal_archive(
        &self,
        source: &mut (impl Read + Seek),
    ) -> Result<StagedArchive> {
        let _ = measure(source)?;
        Err(no_body_store())
    }

    pub(super) fn bind_removal_archive_in_txn(
        &self,
        _wtxn: &mut heed::RwTxn<'_>,
        _row: ArchiveRow,
        _staged: &StagedArchive,
    ) -> Result<ArchiveFile> {
        Err(no_body_store())
    }

    pub(super) fn read_removal_archive_in_txn(
        &self,
        _txn: &heed::RoTxn<'_>,
        _row: ArchiveRow,
        _file: &ArchiveFile,
    ) -> Result<Vec<u8>> {
        Err(no_body_store())
    }

    pub(super) fn release_removal_archive_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        file: &ArchiveFile,
    ) -> Result<()> {
        crate::provenance::body::release_body_in_txn(
            &self.store,
            wtxn,
            &removal_archive_owner(row)?,
            &file.occurrence,
        )?;
        Ok(())
    }

    pub(super) fn release_removal_archives_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        row: ArchiveRow,
        _erase: Option<EntityId>,
    ) -> Result<()> {
        crate::provenance::body::release_owner_bodies_in_txn(
            &self.store,
            wtxn,
            &removal_archive_owner(row)?,
        )?;
        Ok(())
    }

    pub(super) fn owe_removal_archive_erase_in_txn(
        &self,
        _wtxn: &mut heed::RwTxn<'_>,
        _row: ArchiveRow,
        _file: &ArchiveFile,
        _cause: EntityId,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(not(unix))]
fn no_body_store() -> Error {
    Error::InvalidConfig("removal archives need the vault's body store".to_owned())
}
