//! The source a filed reminder wording quotes (FIX 4997).
//!
//! The attempt filer pins the admitted commitment body beside its filing:
//! the source row rides the version's MadeBy inputs and the row's revision
//! its params hash, under the attempt kind's process identity. A served
//! read judges that persisted binding through its own lane; the raw filer
//! writes no binding and its versions read as they always have.

use crate::Vault;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::provenance::made_by::MadeByInputRole;

use super::{
    COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND, UNSENT_WORDING_RUN_PREFIX, WORDING_RUN_PREFIX,
};

/// The commitment body one attempt-filed wording version quotes: its exact
/// source row and that row's fenced body revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WordingSourceBinding {
    pub(crate) source: EntityId,
    pub(crate) revision: [u8; 32],
}

/// The binding `record` carries, when it carries one: `None` for every
/// version no wording attempt filed. A version the attempt kind marks whose
/// binding is malformed errors; it never reads as unmarked.
pub(crate) fn wording_source_binding(
    record: &BlobArtifactVersion,
) -> Result<Option<WordingSourceBinding>> {
    if record.made_by.process.identity != COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND {
        return Ok(None);
    }
    let BlobVersionProvenance::AgentRun { run_ref } = &record.provenance else {
        return Err(malformed());
    };
    if !run_ref.starts_with(WORDING_RUN_PREFIX) && !run_ref.starts_with(UNSENT_WORDING_RUN_PREFIX) {
        return Err(malformed());
    }
    let [input] = record.made_by.inputs.as_slice() else {
        return Err(malformed());
    };
    if input.role != MadeByInputRole::Input {
        return Err(malformed());
    }
    let Ok(revision) = blake3::Hash::from_hex(&record.made_by.process.params_hash) else {
        return Err(malformed());
    };
    Ok(Some(WordingSourceBinding {
        source: input.row,
        revision: *revision.as_bytes(),
    }))
}

fn malformed() -> Error {
    Error::InvalidClaimBody("a reminder wording version names no readable source")
}

impl Vault {
    /// Whether `artifact_id`'s `version` is an attempt filing whose source a
    /// served read must judge through its own lane (FIX 4997): its
    /// ledger-bound record carries the attempt kind's MadeBy identity. A
    /// marked version reads protected even when its binding is malformed —
    /// the lane check then denies it — and a version that is gone reads
    /// unprotected, as its bytes read absent.
    ///
    /// # Errors
    ///
    /// The store failed, or the version record mismatches its ledger claim.
    pub fn commitment_reminder_wording_protected(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Some(record) =
            self.blob_artifact_version_metadata_in_txn(&txn, artifact_id, version)?
        else {
            return Ok(false);
        };
        Ok(record.made_by.process.identity == COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND)
    }
}
