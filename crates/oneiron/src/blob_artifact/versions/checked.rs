//! Checked append decisions shared by direct and Memory transaction doors.

use super::super::made_by::{default_version_made_by, validate_version_made_by_in_txn};
use super::{
    BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactAppendOutcome, BlobArtifactBody,
    BlobArtifactVersion, BlobVersionProvenance, VERSIONS, VersionAuthority, VersionBody,
    read_blob_artifact_head_in_txn, read_blob_artifact_highwater_in_txn,
};
use crate::Vault;
use crate::blob_artifact::BlobContent;
use crate::blob_artifact::native_output::NativeOutput;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::federation::record_scope::BirthPosition;
use crate::provenance::made_by::MadeBy;
use crate::store::{BodyMint, StagedAssetBody, StagedHold};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use heed::RwTxn;

/// What a checked append decided: the version it landed, or the fork base
/// its proposal waits on; and the hold on a landed body file, kept until the
/// writer has committed (FIX 20812).
type CheckedAppend = (
    Option<BlobArtifactVersion>,
    Option<(u64, [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN])>,
    Option<StagedHold>,
);

impl Vault {
    /// Lands `content` as the next version, or decides it waits as a
    /// proposal. A landing version past the asset plane's inline size goes
    /// to its body file under `mint`, taken before `wtxn` opened, so its
    /// ASSET is a file manifest rather than one value holding the bytes
    /// (FIX 20812); the same bytes as the head land nothing new. A body file
    /// an ingress door measured is staged from that file, the head's bytes
    /// too, so it is never held whole (FIX 22074). A landed version's claim
    /// is born at `producer_position` (FIX 3171).
    #[expect(clippy::too_many_arguments)]
    pub(super) fn decide_blob_artifact_append_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        content: BlobContent<'_>,
        mint: Option<&BodyMint>,
        provenance: &BlobVersionProvenance,
        made_by: Option<&MadeBy>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        producer_position: BirthPosition,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<CheckedAppend> {
        let later = read_blob_artifact_highwater_in_txn(&self.store, wtxn, artifact_id)?.is_some();
        let content_hash = content.blake3();
        let dedupe = fork_parent.is_none()
            && read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .is_some_and(|head| head.content_hash == content_hash);
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
            return Ok((None, fork_base, None));
        }
        let staged = match content {
            BlobContent::Bytes(_) if dedupe => None,
            BlobContent::Bytes(bytes) => self.stage_version_slice_in_txn(wtxn, bytes, mint)?,
            BlobContent::File(file) => {
                let staged = self.stage_blob_body_in_txn(wtxn, &mut file.reader()?, mint)?;
                file.check(staged.facts().len, staged.facts().blake3)?;
                Some(staged)
            }
        };
        let body = match (&staged, content) {
            (Some(staged), _) => VersionBody::Staged(staged),
            (None, BlobContent::Bytes(bytes)) => VersionBody::Bytes(bytes),
            (None, BlobContent::File(_)) => {
                return Err(Error::InvariantViolation(
                    "a blob body file is staged before its version lands",
                ));
            }
        };
        let version = self.append_blob_artifact_version_body_with_authority_in_txn(
            wtxn,
            artifact_id,
            body,
            provenance,
            VersionAuthority::Actor(actor),
            occurred,
            learned_at,
            fork_parent,
            None,
            made_by,
            false,
            true,
            None,
            producer_position,
            lane,
        )?;
        Ok((Some(version), None, staged.map(StagedAssetBody::into_hold)))
    }

    /// Memory's checked append on its existing content writer. This door has
    /// no caller-supplied made_by: its proposal names only its writer, and a
    /// landed append uses the content writer's actual credential lane. The
    /// hold on a body file, a landed version's or a waiting proposal's, comes
    /// back beside the outcome: the caller took `mint` before its writer
    /// opened and keeps the hold until it commits (FIX 20812). `content` is
    /// a slice or a body file an ingress door measured (FIX 22074).
    /// `producer_position` is the position the producing Memory's host bound
    /// (FIX 3171). A landed version's claim is born there. A proposal keeps
    /// it for Keep, so the claim is born at the producer's position, never
    /// at the keeper's.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_checked_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        content: BlobContent<'_>,
        mint: Option<&BodyMint>,
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        producer_position: BirthPosition,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<(BlobArtifactAppendOutcome, Option<StagedHold>)> {
        let (version, fork_base, hold) = self.decide_blob_artifact_append_in_txn(
            wtxn,
            artifact_id,
            None,
            content,
            mint,
            provenance,
            None,
            actor,
            occurred,
            learned_at,
            producer_position,
            lane,
        )?;
        if let Some(version) = version {
            return Ok((BlobArtifactAppendOutcome::Landed(version), hold));
        }
        let body = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let output = direct_append_output(body, content, provenance, None, actor, learned_at);
        self.propose_direct_append_output_in_txn(
            wtxn,
            artifact_id,
            &output,
            content,
            mint,
            (actor, learned_at),
            fork_base,
            producer_position,
        )
        .map(|(proposal, hold)| (BlobArtifactAppendOutcome::Proposed(proposal), hold))
    }
}

/// The waiting output a later AgentRun append becomes: its bytes in memory
/// for a slice; none for a body file, which its proposal stages from the
/// file (FIX 22074).
pub(super) fn direct_append_output(
    body: BlobArtifactBody,
    content: BlobContent<'_>,
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
        bytes: match content {
            BlobContent::Bytes(bytes) => bytes.to_vec(),
            BlobContent::File(_) => Vec::new(),
        },
        report: "{}".to_owned(),
        made_by: made_by.cloned().or_else(|| {
            Some(default_version_made_by(
                &actor, provenance, None, learned_at,
            ))
        }),
    }
}
