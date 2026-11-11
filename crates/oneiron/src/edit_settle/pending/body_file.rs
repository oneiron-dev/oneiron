//! A waiting native output past the inline size keeps its bytes in a body
//! file, not in its row (FIX 20812): one complete body in the vault's
//! `bodies/` under an instance minted before the writer that keeps the row
//! opened, sealed under it where the vault seals its bodies, and named in
//! that writer by a complete descriptor the artifact itself owns under an
//! occurrence of its own. The row keeps the occurrence and the body; no
//! LMDB value holds the output.
//!
//! Keep reads the file whole before its writer opens. Keep, Discard and the artifact's
//! purge release the occurrence as they delete the row; an erase of the
//! artifact reaches the file through the artifact's own bodies, as it
//! reaches every body the artifact owns. A file no writer names is debris
//! the orphan collector takes. The descriptor is storage, never a read
//! permit: only the pending doors' own checks reach a file.

use std::io::{Cursor, Read};

use crate::Vault;
use crate::blob_artifact::BlobContent;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::body::{BodyLocation, BodyRef};
use crate::store::result_body_pins::ResultBodyPin;
use crate::store::{ASSET_INLINE_BODY_BYTES, BodyMint, StagedBodyKey, StagedHold};

/// Where a waiting output's bytes are: the body `body`, under the artifact's
/// occurrence `occurrence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingFile {
    pub(super) occurrence: EntityId,
    pub(super) body: BodyRef,
}

/// A waiting output written to a published body file, before its row is
/// written. It holds the file's instance lease and the reader pin on its
/// digest until the writer that names it is done; dropped unnamed, the file
/// is debris.
pub(super) struct StagedPendingBody {
    body: BodyRef,
    key: StagedBodyKey,
    pin: ResultBodyPin,
}

impl StagedPendingBody {
    /// What holding this body keeps once its row is written: its instance's
    /// lease and its digest's pin, until the writer has committed.
    pub(super) fn into_hold(self) -> StagedHold {
        StagedHold::of_file(self.key, self.pin)
    }
}

impl Vault {
    /// Writes `content` as a published body file when it is past the
    /// inline size and `mint` is given ([`Vault::asset_body_mint`] gives one
    /// for exactly those bytes); `None` otherwise, and the bytes wait in
    /// their row. The instance comes from `mint`, taken before the writer
    /// the file serves opened, so this runs before that writer or in it. A
    /// body file an ingress door measured streams from that file (FIX 22074).
    ///
    /// # Errors
    ///
    /// Custody and filesystem errors; nothing is left behind but debris the
    /// collector takes. A body file past the inline size with no mint is an
    /// [`Error::InvariantViolation`]: its bytes never wait in a row.
    pub(super) fn stage_pending_output_body(
        &self,
        content: BlobContent<'_>,
        mint: Option<&BodyMint>,
    ) -> Result<Option<StagedPendingBody>> {
        let len = content.len();
        if len <= ASSET_INLINE_BODY_BYTES {
            return Ok(None);
        }
        let Some(mint) = mint else {
            return match content {
                BlobContent::Bytes(_) => Ok(None),
                BlobContent::File(_) => Err(Error::InvariantViolation(
                    "a native output body file past the inline size waits in a file",
                )),
            };
        };
        let digest = content.blake3();
        // Pinned before it is published: the collector leaves it be until
        // the writer that names it is done.
        let pin = self.pin_result_body(digest);
        let dir = self.store.body_dir()?;
        let instance = mint.mint()?;
        let key = match content {
            BlobContent::Bytes(bytes) => {
                dir.import_sealing(&digest, len, &mut Cursor::new(bytes), false, instance)?
            }
            // Checked as it streams: other bytes than the measured body fail
            // the copy before it publishes under this digest (FIX 22074).
            BlobContent::File(file) => {
                dir.import_sealing(&digest, len, &mut file.checked_reader()?, false, instance)?
            }
        };
        Ok(Some(StagedPendingBody {
            body: BodyRef {
                blake3: digest,
                bytes: len,
                location: BodyLocation::File,
            },
            key,
            pin,
        }))
    }

    /// Names `staged` as a waiting output of `artifact_id` in `wtxn`, the
    /// writer that keeps its row: its instance row and a complete descriptor
    /// under a fresh occurrence of the artifact.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors.
    pub(super) fn bind_pending_output_body_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        staged: &StagedPendingBody,
    ) -> Result<PendingFile> {
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
                owner: *artifact_id,
                occurrence,
                mark_occurrence: occurrence,
                state: BodyState::Complete {
                    body: staged.body.clone(),
                },
                result: None,
                code_run_output: None,
            },
        )?;
        Ok(PendingFile {
            occurrence,
            body: staged.body.clone(),
        })
    }

    /// The bytes of `artifact_id`'s waiting output `file`, read whole under
    /// the custody guard and its digest's pin, both taken before the
    /// snapshot that finds the file opens and held until it is read. Call it
    /// before a writer opens: the bytes are checked against the digest, so a
    /// writer needs no snapshot of the file.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a descriptor, file or digest that does
    /// not match (a restored row whose instance was retired among them);
    /// storage and filesystem errors.
    pub(super) fn read_pending_output_body(
        &self,
        artifact_id: &EntityId,
        file: &PendingFile,
    ) -> Result<Vec<u8>> {
        let _custody = self.store.gate_custody_read_guard()?;
        let _pin = self.pin_result_body(file.body.blake3);
        let txn = self.store.env.read_txn()?;
        self.read_pending_output_body_in_txn(&txn, artifact_id, file)
    }

    /// The bytes of `artifact_id`'s waiting output `file`, as `txn` names
    /// it: its descriptor must be complete with this body, and the file is
    /// read through the instance row `txn` holds and checked against its
    /// digest.
    fn read_pending_output_body_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        file: &PendingFile,
    ) -> Result<Vec<u8>> {
        let named = crate::provenance::body::owned_body_in_txn(
            &self.store,
            txn,
            artifact_id,
            &file.occurrence,
        )?
        .is_some_and(|held| {
            held.state
                == crate::provenance::body::BodyState::Complete {
                    body: file.body.clone(),
                }
        });
        if !named || file.body.location != BodyLocation::File {
            return Err(Error::CorruptedIndex("pending output descriptor"));
        }
        let key = crate::store::body_key_row_in_txn(&self.store, txn, &file.body.blake3)?;
        let mut reader = self
            .store
            .body_dir()?
            .open_reader(&file.body.blake3, file.body.bytes, key.as_ref())?
            .ok_or(Error::CorruptedIndex("pending output file"))?;
        let mut bytes = Vec::with_capacity(usize::try_from(file.body.bytes).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != file.body.bytes
            || blake3::hash(&bytes).as_bytes() != &file.body.blake3
        {
            return Err(Error::CorruptedIndex("pending output digest"));
        }
        Ok(bytes)
    }
}

/// Releases `artifact_id`'s waiting output `file` in `txn`, the writer that
/// deletes its row: its descriptor goes, and its digest, when nothing else
/// holds it, is queued for the collector. An erase that owes the file's
/// instance a retirement stages it now.
///
/// # Errors
///
/// Storage errors.
pub(super) fn release_pending_output_body_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    artifact_id: &EntityId,
    file: &PendingFile,
) -> Result<()> {
    crate::provenance::body::release_body_in_txn(store, txn, artifact_id, &file.occurrence)?;
    Ok(())
}
