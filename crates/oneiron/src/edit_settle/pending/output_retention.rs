//! Native-output row preparation and direct-append retention.

use super::NATIVE_OUTPUT_REPORT_MAX_BYTES;
use super::{
    DeckExportHold, NativeOutput, PendingBody, PendingProposalView, PendingRow, admission,
};
use crate::Vault;
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, read_blob_artifact_head_in_txn,
};
use crate::claim::ScopedRead;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::write_envelope::WriteActor;
use heed::RwTxn;

pub(super) fn validate_native_output(
    output: &NativeOutput,
    body: &BlobArtifactBody,
    authorize_content_write: bool,
) -> Result<String> {
    if output.media_type != body.media_type {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "a native output must export the artifact's own media type",
        )));
    }
    if !authorize_content_write && (output.bytes.is_empty() || output.name.trim().is_empty()) {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "a native output needs a file name and non-empty bytes",
        )));
    }
    let report = output.report.clone();
    serde_json::from_str::<&serde_json::value::RawValue>(&report).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "native output report does not encode",
        ))
    })?;
    if report.len() > NATIVE_OUTPUT_REPORT_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "native output report is too large",
        )));
    }
    crate::batch::secret_scan::scan_metadata_field(&output.name)?;
    if !authorize_content_write && OfficeFormat::from_media_type(&output.media_type).is_ok() {
        // An organ's office export must at least open as a package before
        // it waits. A direct append keeps the append door's byte acceptance
        // (FIX 8208): its authorized Keep reaches the same core append.
        crate::edit_roundtrip::read_office_package(&output.bytes)?;
    }
    Ok(report)
}

pub(super) fn native_output_pending_row(
    output: &NativeOutput,
    (actor, kind): (WriteActor, Option<u8>),
    retained_at: u64,
    base: Option<(u64, [u8; 32])>,
    explicit_fork: bool,
    deck: Option<DeckExportHold>,
    report: String,
) -> PendingRow {
    PendingRow {
        proposal_ref: output.run_ref.clone(),
        retained_by: actor.entity_ref(),
        retained_by_kind: kind,
        retained_at,
        made_by: output.made_by.as_ref().map(|named| {
            Vault::bind_retained_producer_envelope(
                &actor,
                &BlobVersionProvenance::AgentRun {
                    run_ref: output.run_ref.clone(),
                },
                named,
                retained_at,
            )
        }),
        base_version: base.map(|(version, _)| version),
        base_content_hash: base.map(|(_, hash)| hash),
        explicit_fork: explicit_fork,
        new_bytes: output.bytes.clone(),
        read_rows: Vec::new(),
        deck: deck,
        body: PendingBody::Output {
            name: output.name.clone(),
            media_type: output.media_type.clone(),
            report,
        },
    }
}

impl Vault {
    /// The direct append's default writer-only envelope needs no read lane
    /// or grant-clock preparation. All snapshots belong to the caller's writer.
    pub(crate) fn propose_direct_append_output_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        output: &NativeOutput,
        actor: WriteActor,
        retained_at: u64,
        base_override: Option<(u64, [u8; 32])>,
    ) -> Result<PendingProposalView> {
        let body = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let report = validate_native_output(output, &body, true)?;
        let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
        let base =
            base_override.or_else(|| head.as_ref().map(|head| (head.version, head.content_hash)));
        let row = native_output_pending_row(
            output,
            (
                actor,
                self.get_entity_type_in_txn(wtxn, &actor.entity_ref())?,
            ),
            retained_at,
            base,
            base_override.is_some(),
            None,
            report,
        );
        // None cannot clock a lane. It still rejects an envelope naming
        // anything beyond its writer; no reader authority is invented here.
        let lane =
            admission::retention_lane(artifact_id, row.made_by.as_ref(), row.retained_by, None)?;
        self.put_pending_with_content_write_grant_in_txn(
            wtxn,
            artifact_id,
            &row,
            lane.as_ref(),
            actor,
        )
    }

    pub(super) fn put_pending_with_content_write_grant_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        row: &PendingRow,
        lane: Option<&ScopedRead<'_>>,
        actor: WriteActor,
    ) -> Result<PendingProposalView> {
        self.authorize_shared_content_write_in_txn(wtxn, *artifact_id, &actor)?;
        if let (Some(lane), Some(made_by)) = (lane, &row.made_by) {
            admission::admit_made_by_in_txn(self, wtxn, lane, made_by, row.retained_by)?;
        }
        self.put_pending_in_txn(wtxn, artifact_id, row)?;
        Ok(row.view(*artifact_id))
    }
}
