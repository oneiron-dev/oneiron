//! The inference snapshot custody client: one erasable wrapped data key
//! per snapshot, on the one typed custody every other client shares.
//!
//! A snapshot's body is sealed under its own data key, wrapped under the
//! vault's key; the 61 wrapped bytes live here, at generation 0 under the
//! snapshot catalog's id, and nowhere else durable: never in the catalog
//! row, the sealed body, an image, a log, an error, or a receipt. The host
//! engine opens the key in its own process to import the snapshot into its
//! worker, so the kind reads host-side; a missing key means a cold
//! recompute, never a failed restore.

use std::path::PathBuf;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::error::{Error, Result, StoreError};
use crate::inference_snapshot::WrappedSnapshotKey;
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodySecret, CustodySubject, EntryState, RetireCause,
    RetirementIntent, retirement_in_txn, stage_retirement_in_txn,
};

/// The width of every inference snapshot custody entry: the serialized
/// wrapped snapshot key, version ‖ nonce ‖ sealed key and tag.
pub(crate) const INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES: usize = 61;

/// The directory under the vault root that sealed snapshot bodies live in.
const SNAPSHOT_BODY_DIR: &str = "inference-snapshots";

/// `catalog_id`'s wrapped-key subject in `binding`'s custody.
fn snapshot_subject(binding: &CustodyBinding, catalog_id: &[u8; 16]) -> Result<CustodySubject> {
    binding.subject(CustodyKind::InferenceSnapshot, catalog_id)
}

/// The wrapped key `secret` holds: exactly
/// [`INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES`], of the sealed format.
fn copy_wrapped(secret: &CustodySecret) -> Result<WrappedSnapshotKey> {
    WrappedSnapshotKey::parse(secret.expose()).map_err(|_| CustodyKind::InferenceSnapshot.corrupt())
}

impl Store {
    /// This vault's sealed snapshot body directory, `inference-snapshots/`
    /// under the root it opened at: sealed bodies only, never a key.
    pub(crate) fn inference_snapshot_dir(&self) -> PathBuf {
        self.owner._registered_path.path.join(SNAPSHOT_BODY_DIR)
    }

    /// Writes `wrapped`'s 61 bytes as snapshot `catalog_id`'s key in `wtxn`,
    /// the binding pinned in the same transaction: published, synced and its
    /// Mint journaled before the catalog row sealed under it commits, so a
    /// crash leaves either nothing or the whole item. The writer keeps the
    /// finisher from every entry, so no custody guard is taken. The same
    /// bytes already there are kept; other bytes, or a retired id, are
    /// refused, never replaced.
    ///
    /// # Errors
    /// An archived vault, whose custody is its replacement's; a retired id,
    /// which is never minted again; custody faults.
    pub(crate) fn publish_inference_snapshot_key_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        catalog_id: &[u8; 16],
        wrapped: &WrappedSnapshotKey,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = snapshot_subject(custody.binding(), catalog_id)?.at(0);
        let bytes = Zeroizing::new(wrapped.to_bytes());
        debug_assert_eq!(bytes.len(), INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES);
        let secret = CustodySecret::from_bytes(bytes);
        custody.publish_minted(&id, &secret)
    }

    /// Snapshot `catalog_id`'s wrapped key, or `None` when no live key stands
    /// for it: no custody, no entry, a standing retirement intent, or a
    /// retired entry. Absent means the caller treats the snapshot as gone
    /// (cold). A live entry of other bytes is damaged, never absent. `txn`
    /// is the caller's: a writer, or a snapshot taken after the custody read
    /// guard. The caller checks the catalog row first, so an absent row
    /// denies this read without reaching here.
    ///
    /// # Errors
    /// A damaged entry, and custody and storage faults.
    pub(crate) fn read_inference_snapshot_key(
        &self,
        txn: &RoTxn<'_>,
        catalog_id: &[u8; 16],
    ) -> Result<Option<WrappedSnapshotKey>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        let subject = snapshot_subject(custody.binding(), catalog_id)?;
        if retirement_in_txn(self, txn, &subject)?.is_some() {
            return Ok(None);
        }
        match custody.state(&subject.at(0))? {
            EntryState::Live => Ok(Some(copy_wrapped(&custody.read(&subject.at(0))?)?)),
            EntryState::Missing | EntryState::Retired => Ok(None),
        }
    }

    /// Stages retirement of snapshot `catalog_id`'s wrapped key in `wtxn`,
    /// the writer that deletes its catalog row: one erase intent through
    /// generation 0, the only one a snapshot key is minted at, so a restored
    /// pre-erase image cannot open it, and a standing intent denies reads
    /// from then on. No custody file is read here. The custody finisher
    /// carries it out after commit; an entry never published retires as a
    /// marker alone. No custody, or an archived vault whose custody is its
    /// replacement's, stages none.
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn stage_inference_snapshot_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        catalog_id: &[u8; 16],
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        stage_retirement_in_txn(
            self,
            wtxn,
            &RetirementIntent {
                subject: snapshot_subject(custody.binding(), catalog_id)?,
                through: 0,
                cause: RetireCause::Erase,
            },
        )
    }

    /// Carries out every staged inference snapshot key retirement, an
    /// interrupted process's included, in the custody finisher's order: each
    /// generation's marker synced, its entry unlinked, the directory synced,
    /// then the handoff to the custody journal. Only an erase's intent runs:
    /// a snapshot key retires with its catalog row and for nothing else. The
    /// caller retires its transient wrapped copies with
    /// [`WrappedSnapshotKey::retire`], and resumes this at startup and
    /// housekeeping.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, an intent of another
    /// cause, and custody faults.
    pub(crate) fn finish_inference_snapshot_retirements(&self) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::InferenceSnapshot, |_, intent| {
            if intent.cause == RetireCause::Erase {
                Ok(true)
            } else {
                Err(Error::CorruptedIndex(
                    "inference snapshot keys retire for an erase only",
                ))
            }
        })
    }
}
