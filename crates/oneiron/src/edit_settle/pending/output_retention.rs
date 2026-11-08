//! Native-output row preparation and direct-append retention.

use super::NATIVE_OUTPUT_REPORT_MAX_BYTES;
use super::{
    DeckExportHold, NativeOutput, PendingBody, PendingProposalView, PendingRow, StagedPendingBody,
    admission,
};
use crate::Vault;
use crate::blob_artifact::{
    BlobArtifactBody, BlobContent, BlobVersionProvenance, read_blob_artifact_head_in_txn,
};
use crate::claim::ScopedRead;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::federation::record_scope::BirthPosition;
use crate::store::{BodyMint, StagedHold};
use crate::write_envelope::WriteActor;
use heed::RwTxn;

/// Checks `output`, whose bytes are `content` (FIX 22074), before it waits.
pub(super) fn validate_native_output(
    output: &NativeOutput,
    content: BlobContent<'_>,
    body: &BlobArtifactBody,
    authorize_content_write: bool,
) -> Result<String> {
    if output.media_type != body.media_type {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "a native output must export the artifact's own media type",
        )));
    }
    if !authorize_content_write && (content.is_empty() || output.name.trim().is_empty()) {
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
        match content {
            BlobContent::Bytes(bytes) => crate::edit_roundtrip::read_office_package(bytes)?,
            BlobContent::File(file) => {
                crate::edit_roundtrip::read_office_package_from(&mut file.reader()?)?;
            }
        }
    }
    Ok(report)
}

/// The row `output` waits in. With `in_body_file` its bytes wait in the
/// body file staged for them, which the writer that keeps the row names
/// (FIX 20812), and the row holds none of them.
/// The row a native output waits in. `producer_position` is frozen in its
/// body as the producing run's host bound it (FIX 3171).
#[expect(clippy::too_many_arguments)]
pub(super) fn native_output_pending_row(
    output: &NativeOutput,
    (actor, kind): (WriteActor, Option<u8>),
    retained_at: u64,
    base: Option<(u64, [u8; 32])>,
    explicit_fork: bool,
    deck: Option<DeckExportHold>,
    report: String,
    delta_receipt: Option<&str>,
    in_body_file: bool,
    producer_position: BirthPosition,
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
        next_sheet_row: None,
        new_bytes: if in_body_file {
            Vec::new()
        } else {
            output.bytes.clone()
        },
        new_file: None,
        read_rows: Vec::new(),
        deck: deck,
        delta_receipt: delta_receipt.map(str::to_owned),
        body: PendingBody::Output {
            name: output.name.clone(),
            media_type: output.media_type.clone(),
            report,
            producer_world: producer_position.world,
            producer_facet: producer_position.facet,
        },
    }
}

impl Vault {
    /// The direct append's default writer-only envelope needs no read lane
    /// or grant-clock preparation. All snapshots belong to the caller's writer.
    /// An output past the inline size waits in its body file under an
    /// instance from `mint`, which the caller took before its writer opened
    /// and no landed version used; the file's hold comes back beside the
    /// view, for the caller to keep until its writer commits (FIX 20812).
    /// Its bytes are `content`: a body file is staged from the file (FIX
    /// 22074). The proposal keeps `producer_position` for its Keep (FIX 3171).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn propose_direct_append_output_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        output: &NativeOutput,
        content: BlobContent<'_>,
        mint: Option<&BodyMint>,
        (actor, retained_at): (WriteActor, u64),
        base_override: Option<(u64, [u8; 32])>,
        producer_position: BirthPosition,
    ) -> Result<(PendingProposalView, Option<StagedHold>)> {
        let body = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let report = validate_native_output(output, content, &body, true)?;
        let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
        let base =
            base_override.or_else(|| head.as_ref().map(|head| (head.version, head.content_hash)));
        let staged = self.stage_pending_output_body(content, mint)?;
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
            None,
            staged.is_some(),
            producer_position,
        );
        // None cannot clock a lane. It still rejects an envelope naming
        // anything beyond its writer; no reader authority is invented here.
        let lane =
            admission::retention_lane(artifact_id, row.made_by.as_ref(), row.retained_by, None)?;
        let view = self.put_pending_with_content_write_grant_in_txn(
            wtxn,
            artifact_id,
            &row,
            staged.as_ref(),
            lane.as_ref(),
            actor,
        )?;
        Ok((view, staged.map(StagedPendingBody::into_hold)))
    }

    pub(super) fn put_pending_with_content_write_grant_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        row: &PendingRow,
        staged: Option<&StagedPendingBody>,
        lane: Option<&ScopedRead<'_>>,
        actor: WriteActor,
    ) -> Result<PendingProposalView> {
        self.authorize_shared_content_write_in_txn(wtxn, *artifact_id, &actor)?;
        if let (Some(lane), Some(made_by)) = (lane, &row.made_by) {
            admission::admit_made_by_in_txn(self, wtxn, lane, made_by, row.retained_by)?;
        }
        self.put_pending_in_txn(wtxn, artifact_id, row, staged)
    }
}
