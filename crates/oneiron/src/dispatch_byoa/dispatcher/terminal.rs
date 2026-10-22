//! The terminal capture door, moved whole from the dispatcher: a terminated
//! executor's exhaust folded into one canonical artifact, its result
//! reference attached and its row settled, in one write transaction.

use crate::attempt_queue::{
    AbandonAttempt, AbandonOutcome, AttemptQueue, CompleteAttempt, CompleteOutcome, FailAttempt,
    FailOutcome, FinishAttemptLanding, FinishLandingOutcome, SetAttemptResult,
};
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body,
    read_blob_artifact_head_in_txn,
};
use crate::dispatch_byoa::connector::{BYOA_CONNECTOR_SCHEMA_VERSION, BYOA_EXHAUST_MEDIA_TYPE};
use crate::dispatch_byoa::error::{
    ByoaError, ByoaResult, ERR_ARTIFACT_COLLISION, ERR_ATTEMPT_MISSING, ERR_CAPTURE_CONFLICT,
    invalid,
};
use crate::dispatch_byoa::exhaust::{
    ByoaEgressPort, ByoaExhaustEnvelope, ByoaTerminalDisposition, ByoaTerminalReceipt,
    CaptureByoaExhaust, append_exhaust_envelope, byoa_exhaust_artifact_id,
    byoa_exhaust_artifact_name, byoa_result_ref, canonical_result_version,
    disposition_matches_state, ensure_byoa_runtime_actor, normalize_capture_reason,
    validate_canonical_capture,
};
use crate::dispatch_byoa::repo_binding::mark_stale_capture_in_txn;
use crate::dispatch_byoa::validate::validate_exhaust;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ArtifactError, Error};
use crate::temporal::TimeRange;

use super::{ByoEndpointBackendFactory, ByoaDispatcher};

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Folds a terminated executor's exhaust into one canonical artifact:
    /// streams past the inline budget as chunk versions, then the envelope as
    /// its head, whose version the result reference names.
    ///
    /// Artifact, actor, result reference, and terminal settlement commit in one
    /// write transaction. Completed and failed captures require a leased row;
    /// cancelled captures finish an accepted landing without force authority or
    /// handoff. Retries never append another version. An abandoned retry returns
    /// the first result, even if the new exhaust differs.
    ///
    /// # Errors
    ///
    /// Refuses invalid BYOA rows, stale leases, conflicting results, artifact
    /// collisions, and invalid exhaust without durable writes. No exhaust is
    /// refused for its size.
    pub fn capture_terminal_exhaust(
        &mut self,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        self.vault
            .try_with_write_txn_grouped(|wtxn| self.capture_terminal_exhaust_in_txn(wtxn, request))
    }

    pub(in crate::dispatch_byoa) fn capture_terminal_exhaust_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        validate_exhaust(&request.exhaust)?;
        let mut reason = normalize_capture_reason(request.disposition, request.reason)?;
        if request.lease_owner.is_empty() || request.lease_owner.len() > 128 {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        let artifact_id = byoa_exhaust_artifact_id(request.attempt_id)?;
        let mut envelope = ByoaExhaustEnvelope {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            attempt_id: *request.attempt_id.as_bytes(),
            lease_owner: request.lease_owner,
            attempt_count: request.attempt_count,
            disposition: request.disposition,
            exhaust: request.exhaust,
        };
        let body = BlobArtifactBody::new(
            byoa_exhaust_artifact_name(request.attempt_id),
            BYOA_EXHAUST_MEDIA_TYPE,
        )
        .with_secret_taint_refs(envelope.exhaust.secret_taint_refs.clone());
        let occurred = TimeRange {
            start: request.now,
            end: request.now,
        };
        let action = match request.disposition {
            ByoaTerminalDisposition::Completed => "complete",
            ByoaTerminalDisposition::Failed => "fail",
            ByoaTerminalDisposition::Cancelled => "finish_landing",
            ByoaTerminalDisposition::Abandoned => "abandon",
        };
        let queue = AttemptQueue::new(self.vault);
        let record = queue
            .get_in_write_txn(wtxn, request.attempt_id)?
            .ok_or(ByoaError::Store(Error::Artifact(
                ArtifactError::InvalidAttemptQueueTransition {
                    action: "capture_byoa_exhaust",
                    state: ERR_ATTEMPT_MISSING,
                },
            )))?;
        // CALL "FIX 6867 stale capture": exhaust kept, Abandoned + repo_stale_lease.
        mark_stale_capture_in_txn(self.vault, wtxn, &record, &mut envelope, &mut reason)?;
        if record.state.is_running() {
            AttemptQueue::check_result_lease(
                &record,
                &envelope.lease_owner,
                envelope.attempt_count,
                action,
            )?;
        } else if record.result_ref.is_none()
            || record.attempt_count != envelope.attempt_count
            || !disposition_matches_state(envelope.disposition, record.state)
        {
            return Err(ByoaError::Store(Error::Artifact(
                ArtifactError::InvalidAttemptQueueTransition {
                    action,
                    state: record.state.as_str(),
                },
            )));
        }
        let provenance = BlobVersionProvenance::AgentRun {
            run_ref: record
                .run_id
                .clone()
                .unwrap_or_else(|| bytes_to_hex_lower(request.attempt_id.as_bytes())),
        };
        if let Some(result_ref) = record.result_ref.clone() {
            // This build never commits a canonical capture on a running row.
            // A generic result attachment cannot stand in for terminal custody.
            let Some(version) = canonical_result_version(&result_ref, &artifact_id)
                .filter(|_| record.state.is_terminal())
            else {
                return Err(invalid(ERR_CAPTURE_CONFLICT));
            };
            if matches!(
                envelope.disposition,
                ByoaTerminalDisposition::Failed | ByoaTerminalDisposition::Abandoned
            ) && record.last_error.as_deref() != Some(reason.as_str())
            {
                return Err(invalid(ERR_CAPTURE_CONFLICT));
            }
            validate_canonical_capture(
                self.vault,
                wtxn,
                &artifact_id,
                version,
                &body,
                &provenance,
                &envelope,
            )?;
            return Ok(ByoaTerminalReceipt {
                attempt: record,
                artifact_id,
                artifact_version: version,
                result_ref,
                skipped_seats: Vec::new(),
            });
        }
        // An unattached artifact can never be a partial successful capture:
        // all custody writes now share this transaction. Refuse collisions,
        // including empty chains with perfectly matching caller-made metadata.
        if self
            .vault
            .get_entity_type_in_txn(wtxn, &artifact_id)?
            .is_some()
            || read_blob_artifact_head_in_txn(&self.vault.store, wtxn, &artifact_id)?.is_some()
        {
            return Err(invalid(ERR_ARTIFACT_COLLISION));
        }
        let actor = ensure_byoa_runtime_actor(self.vault, wtxn, occurred, request.now)?;
        self.vault
            .batch_in()
            .put(
                &artifact_id,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                request.now,
                &encode_blob_artifact_body(&body)?,
            )
            .apply(wtxn)?;
        let version = append_exhaust_envelope(
            self.vault,
            wtxn,
            &artifact_id,
            &envelope,
            &provenance,
            actor,
            request.now,
        )?;
        let result_ref = byoa_result_ref(&artifact_id, version.version)?;
        // Attach and settle through the queue's existing fenced doors. No
        // writer can interleave a different disposition, and any later failure
        // rolls back the row, dedupe release, receipts, and artifact together.
        queue.set_result_in_txn(
            wtxn,
            SetAttemptResult {
                id: request.attempt_id,
                lease_owner: envelope.lease_owner.clone(),
                attempt_count: envelope.attempt_count,
                result_ref: result_ref.clone(),
                now: request.now,
            },
        )?;
        let attempt = match envelope.disposition {
            ByoaTerminalDisposition::Completed => match crate::ports::JobQueue::port_job_complete(
                self.vault,
                wtxn,
                CompleteAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    now: request.now,
                },
            )? {
                CompleteOutcome::Completed(attempt)
                | CompleteOutcome::AlreadyCompleted(attempt) => attempt,
            },
            ByoaTerminalDisposition::Failed => match crate::ports::JobQueue::port_job_fail(
                self.vault,
                wtxn,
                FailAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    reason,
                    now: request.now,
                },
            )? {
                FailOutcome::Failed(attempt) | FailOutcome::AlreadyFailed(attempt) => attempt,
            },
            ByoaTerminalDisposition::Cancelled => match queue.finish_landing_in_txn(
                wtxn,
                FinishAttemptLanding {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    hand_off: false,
                    scheduled_at: None,
                    now: request.now,
                },
            )? {
                FinishLandingOutcome::Landed(attempt) => attempt,
                FinishLandingOutcome::HandedOff { .. } => {
                    return Err(invalid(ERR_CAPTURE_CONFLICT));
                }
            },
            ByoaTerminalDisposition::Abandoned => match queue.abandon_in_txn(
                wtxn,
                AbandonAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    result_ref: result_ref.clone(),
                    reason,
                    now: request.now,
                },
            )? {
                AbandonOutcome::Abandoned(attempt) | AbandonOutcome::AlreadyAbandoned(attempt) => {
                    attempt
                }
            },
        };
        Ok(ByoaTerminalReceipt {
            attempt,
            artifact_id,
            artifact_version: version.version,
            result_ref,
            skipped_seats: Vec::new(),
        })
    }
}
