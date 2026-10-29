//! A staged job stored and its first attempt landed in one write (FIX 7613).
//!
//! The job's digest, its file and the pointer task its run is handed are
//! derived before anything is written ([`StagedJob`]), so the caller builds
//! and checks the run's connector first. One writer then reads the TASK's
//! permanent hard-delete marker, stores the job, pins it in the connector
//! and lands the attempt: an erase either finds the attempt and its pin, or
//! comes first and nothing is stored. Task-less work stages the same way.

use crate::Vault;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::dispatch_byoa::connector::{
    BYOA_ATTEMPT_KIND, ByoaConnectorSpec, ByoaDispatchOutcome, DispatchByoa,
};
use crate::dispatch_byoa::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher, ByoaEnqueue};
use crate::dispatch_byoa::error::{
    ByoaError, ByoaResult, ERR_EXECUTION_SHAPE, ERR_STAGED_INPUT_COLLISION, invalid,
};
use crate::dispatch_byoa::exhaust::{ByoaEgressPort, byoa_result_ref, ensure_byoa_runtime_actor};
use crate::dispatch_byoa::validate::validate_connector;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;
use crate::temporal::TimeRange;

use super::{
    BYOA_STAGED_INPUT_MEDIA_TYPE, StagedInputPin, pointer_to, staged_input_artifact_id,
    staged_input_name,
};

/// A job about to be staged, before anything is written: its bytes and
/// BLAKE3 digest, from which its artifact, its file and the pointer task its
/// run is handed all derive.
pub(crate) struct StagedJob<'j> {
    job: &'j [u8],
    digest: [u8; 32],
}

impl<'j> StagedJob<'j> {
    /// `job`, hashed once.
    pub(crate) fn new(job: &'j [u8]) -> Self {
        Self {
            job,
            digest: *blake3::hash(job).as_bytes(),
        }
    }

    /// The task a run of this job is handed: a pointer to the file the job
    /// is staged as, never its text.
    pub(crate) fn pointer(&self) -> String {
        pointer_to(&staged_input_name(&self.digest))
    }
}

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Stores `job` and lands the CLI run that stages it, in one write
    /// (FIX 7613): when `request` names a TASK that bears the permanent
    /// hard-delete marker, nothing is stored and no attempt lands; otherwise
    /// the job is stored whole, its pin set on the connector, and the
    /// attempt enqueued as [`Self::dispatch`] enqueues it. The connector is
    /// checked before the writer opens.
    ///
    /// # Errors
    /// [`ByoaError::StagedInputErased`] for an erased TASK; an
    /// execution-shape refusal for a connector that is not a CLI run; the
    /// staged artifact's collision refusal; every refusal
    /// [`Self::dispatch`] has. Nothing is written on any of them.
    pub(crate) fn dispatch_staged_job(
        &self,
        job: &StagedJob<'_>,
        run_ref: &str,
        request: DispatchByoa,
    ) -> ByoaResult<ByoaDispatchOutcome> {
        if !matches!(request.connector, ByoaConnectorSpec::CliSandbox(_)) {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        }
        validate_connector(&request.connector)?;
        let vault = self.vault();
        vault.try_with_write_txn_grouped(|wtxn| {
            if let Some(task) = &request.task_ref
                && task_erased_in_txn(&vault.store, wtxn, task)?
            {
                return Err(ByoaError::StagedInputErased);
            }
            let pin = persist_staged_input_in_txn(vault, wtxn, job, run_ref, request.now)?;
            let mut connector = request.connector;
            if let ByoaConnectorSpec::CliSandbox(spec) = &mut connector {
                spec.staged_input = Some(pin);
            }
            self.enqueue_in_txn(
                wtxn,
                ByoaEnqueue {
                    user_login: request.user_login,
                    connector,
                    task_ref: request.task_ref.map(|task| task.to_hex()),
                    parent_attempt: request.parent_attempt_id.map(|id| *id.as_bytes()),
                    dev_refs: request.dev_refs,
                    run_id: request.run_id,
                    dedupe_key: request.dedupe_key,
                    now: request.now,
                    official_seat: None,
                    work: None,
                },
            )
        })
    }
}

/// Whether `task` bears the permanent hard-delete marker, read in `txn`.
fn task_erased_in_txn(store: &Store, txn: &heed::RoTxn<'_>, task: &EntityId) -> ByoaResult<bool> {
    Ok(store.port_deletion_marked(txn, DeletionMarker::HardDelete, task)?)
}

/// Stores `job` whole as a version of the artifact its digest names, made
/// on first use, in the writer `wtxn`, and pins it. The same job stores
/// once: its bytes as the head again are the head.
///
/// # Errors
/// [`ERR_STAGED_INPUT_COLLISION`] when the id holds anything else; a store
/// failure.
fn persist_staged_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    job: &StagedJob<'_>,
    run_ref: &str,
    now: u64,
) -> ByoaResult<StagedInputPin> {
    let digest = job.digest;
    let artifact_id = staged_input_artifact_id(&digest)?;
    let body = BlobArtifactBody::new(
        format!("{BYOA_ATTEMPT_KIND}/staged/{}", bytes_to_hex_lower(&digest)),
        BYOA_STAGED_INPUT_MEDIA_TYPE,
    );
    let provenance = BlobVersionProvenance::AgentRun {
        run_ref: run_ref.to_owned(),
    };
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    // The id is the job's: anything else already there is a collision.
    if vault.get_entity_type_in_txn(wtxn, &artifact_id)?.is_none() {
        vault
            .batch_in()
            .put(
                &artifact_id,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                now,
                &encode_blob_artifact_body(&body)?,
            )
            .apply(wtxn)?;
    } else if vault
        .get_blob_artifact_in_txn(wtxn, &artifact_id)
        .ok()
        .flatten()
        .as_ref()
        != Some(&body)
    {
        return Err(invalid(ERR_STAGED_INPUT_COLLISION));
    }
    let actor = ensure_byoa_runtime_actor(vault, wtxn, occurred, now)?;
    let version = vault
        .append_blob_artifact_version_in_txn(
            wtxn,
            &artifact_id,
            job.job,
            &provenance,
            actor,
            occurred,
            now,
        )?
        .version;
    super::erase::drop_owed_staged_erase_in_txn(&vault.store, wtxn, &digest)?;
    Ok(StagedInputPin {
        artifact: byoa_result_ref(&artifact_id, version)?.as_str().to_owned(),
        len: job.job.len() as u64,
        blake3: digest,
        name: staged_input_name(&digest),
    })
}
