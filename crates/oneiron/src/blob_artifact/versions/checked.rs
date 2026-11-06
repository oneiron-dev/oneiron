//! Checked append decisions shared by direct and Memory transaction doors.

use super::{
    BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactAppendOutcome, BlobArtifactBody,
    BlobArtifactVersion, BlobVersionProvenance, VERSIONS, default_version_made_by,
    read_blob_artifact_head_in_txn, read_blob_artifact_highwater_in_txn,
    validate_version_made_by_in_txn,
};
use crate::Vault;
use crate::blob_artifact::native_output::NativeOutput;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use heed::RwTxn;

impl Vault {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn decide_blob_artifact_append_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        made_by: Option<&MadeBy>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(
        Option<BlobArtifactVersion>,
        Option<(u64, [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN])>,
    )> {
        let later = read_blob_artifact_highwater_in_txn(&self.store, wtxn, artifact_id)?.is_some();
        let content_hash = blake3::hash(bytes);
        let dedupe = fork_parent.is_none()
            && read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .is_some_and(|head| head.content_hash == *content_hash.as_bytes());
        if later && !dedupe && matches!(provenance, BlobVersionProvenance::AgentRun { .. }) {
            if let Some(named) = made_by {
                validate_version_made_by_in_txn(self, wtxn, named)?;
            }
            let fork_base = match fork_parent {
                Some(parent) => {
                    let record =
                        match read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)? {
                            Some(head) if parent > 0 && parent <= head.version => {
                                VERSIONS.get(&self.store, wtxn, &(*artifact_id, parent))?
                            }
                            _ => None,
                        };
                    let Some(record) = record else {
                        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                            "fork parent version does not exist",
                        )));
                    };
                    if record.version != parent {
                        return Err(Error::CorruptedIndex("blob artifact fork parent"));
                    }
                    Some((parent, record.content_hash))
                }
                None => None,
            };
            return Ok((None, fork_base));
        }
        let version = match made_by {
            Some(made_by) => self.append_blob_artifact_version_made_by_in_txn(
                wtxn,
                artifact_id,
                fork_parent,
                bytes,
                provenance,
                made_by,
                actor,
                occurred,
                learned_at,
            )?,
            None => self.append_blob_artifact_version_with_parent_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                learned_at,
                fork_parent,
            )?,
        };
        Ok((Some(version), None))
    }

    /// Memory's checked append on its existing content writer. This door has
    /// no caller-supplied made_by or reader: its proposal names only its writer.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_checked_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactAppendOutcome> {
        let (version, fork_base) = self.decide_blob_artifact_append_in_txn(
            wtxn,
            artifact_id,
            None,
            bytes,
            provenance,
            None,
            actor,
            occurred,
            learned_at,
        )?;
        if let Some(version) = version {
            return Ok(BlobArtifactAppendOutcome::Landed(version));
        }
        let body = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let output = direct_append_output(body, bytes, provenance, None, actor, learned_at);
        self.propose_direct_append_output_in_txn(
            wtxn,
            artifact_id,
            &output,
            actor,
            learned_at,
            fork_base,
        )
        .map(BlobArtifactAppendOutcome::Proposed)
    }
}

pub(super) fn direct_append_output(
    body: BlobArtifactBody,
    bytes: &[u8],
    provenance: &BlobVersionProvenance,
    made_by: Option<&MadeBy>,
    actor: WriteActor,
    learned_at: u64,
) -> NativeOutput {
    let BlobVersionProvenance::AgentRun { run_ref } = provenance else {
        unreachable!("only a later AgentRun append takes the proposal path")
    };
    // The default names only the submitter. Keep must not replace it with
    // the keeper, and there are no additional input rows to admit.
    NativeOutput {
        run_ref: run_ref.clone(),
        name: body.name,
        media_type: body.media_type,
        bytes: bytes.to_vec(),
        report: "{}".to_owned(),
        made_by: made_by.cloned().or_else(|| {
            Some(default_version_made_by(
                &actor, provenance, None, learned_at,
            ))
        }),
    }
}
