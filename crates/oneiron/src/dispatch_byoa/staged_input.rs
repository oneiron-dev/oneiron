//! A CLI run's job carried as a file in its checkout, never in argv: one argv
//! entry has an OS limit (Linux `MAX_ARG_STRLEN`, 128 KiB) past which exec
//! fails, and a job has none.
//!
//! The job is stored whole, once, as a version of a BLOB_ARTIFACT addressed
//! by its BLAKE3 digest, and the run's connector carries a pin to it
//! ([`StagedInputPin`]): that version, the job's length and digest, and the
//! file the job is staged as. The job is stored and the run that stages it
//! lands in one write ([`StagedJob`], FIX 7613), and an erase of its TASK
//! removes the job's artifact row too (FIX 7614). After the checkout and
//! lease checks and before the run, the dispatcher reads the pinned version
//! back, checks it against the pin, and hands it whole to the host's
//! [`ByoaInputStager`], which writes it into the checkout. Completion reads
//! the job back through the same pin. Nothing here refuses a job for its
//! size.

mod dispatch;
mod erase;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState,
};
use crate::checkout::CheckoutLeaseAct;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;

use super::connector::{ByoaConnectorSpec, CliSandboxSpec};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher};
use super::error::{
    ByoaError, ByoaResult, ERR_ATTEMPT_MISSING, ERR_CAPTURE_CONFLICT, ERR_EXECUTION_SHAPE,
    ERR_STAGED_INPUT_PIN, invalid,
};
use super::exhaust::{
    ByoaEgressPort, ByoaExhaust, ByoaTerminalDisposition, byoa_exhaust_artifact_id,
    canonical_result_version, decode_byoa_exhaust, decode_byoa_record,
};

pub(crate) use self::dispatch::StagedJob;
pub(crate) use self::erase::erase_staged_input_in_txn;

/// Domain separator for a staged job's artifact id, derived from the job's
/// digest.
const BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN: &[u8] = b"oneiron:byoa-staged-input-artifact:v1";

/// Media type of a staged job's artifact.
const BYOA_STAGED_INPUT_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-staged-input+json";

/// The directory a job is staged in, relative to the checkout's root.
const BYOA_STAGED_INPUT_DIR: &str = ".oneiron/staged";

/// One run's staged job: the artifact version that holds it whole, its length
/// and digest, and the file it is staged as. The artifact id and the file
/// name are both derived from the digest, so a pin cannot point a run at
/// another artifact's bytes or at another path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedInputPin {
    /// The artifact version holding the job, as `blob-artifact:<id>@<version>`.
    pub artifact: String,
    /// The job's length in bytes.
    pub len: u64,
    /// BLAKE3 of the job.
    pub blake3: [u8; 32],
    /// The file the job is staged as, relative to the checkout's root:
    /// `.oneiron/staged/<blake3 hex>.json`.
    pub name: String,
}

/// The host's port that writes a run's job into its checkout before the run.
/// The host resolves the live checkout into its real worktree, as its
/// [`ByoaCliExecutor`](super::ByoaCliExecutor) does.
pub trait ByoaInputStager: Send + Sync {
    /// Writes `bytes`, whole, as the file `name` relative to the root of
    /// `checkout`'s worktree.
    ///
    /// # Errors
    /// Refuses a `name` that is absolute or leaves the checkout, and a write
    /// that fails.
    fn stage(&mut self, checkout: &CheckoutLeaseAct, name: &str, bytes: &[u8]) -> ByoaResult<()>;
}

/// A pin names its job's own artifact, in its canonical spelling, and its
/// job's own file. A grammar check: no length is refused.
pub(super) fn validate_staged_input(pin: &StagedInputPin) -> ByoaResult<()> {
    pinned_version(pin).map(|_| ())
}

/// The artifact and version `pin` names, once it passes
/// [`validate_staged_input`].
fn pinned_version(pin: &StagedInputPin) -> ByoaResult<(EntityId, u64)> {
    let artifact_id = staged_input_artifact_id(&pin.blake3)?;
    let version = AttemptResultRef::new(pin.artifact.as_str())
        .ok()
        .and_then(|artifact| canonical_result_version(&artifact, &artifact_id))
        .filter(|_| pin.name == staged_input_name(&pin.blake3))
        .ok_or_else(|| invalid(ERR_STAGED_INPUT_PIN))?;
    Ok((artifact_id, version))
}

/// `connector` carrying the pinned job `pin` names (the spent run's, or the
/// bound work's), when it is a CLI run: a runner seat that takes over spent
/// work runs the same task, and the task points at that job.
pub(super) fn carry_staged_input(
    mut connector: ByoaConnectorSpec,
    pin: Option<&StagedInputPin>,
) -> ByoaConnectorSpec {
    if let ByoaConnectorSpec::CliSandbox(spec) = &mut connector {
        spec.staged_input = pin.cloned();
    }
    connector
}

/// The task a CLI run is handed when its job is staged (FIX 7449, 7503): a
/// pointer to the file the job is staged as, never the job's text. A bound
/// work's CLI seat whose task first landed as its staged job gets it, and so
/// does a dev-time Coach runner.
pub(crate) fn staged_job_pointer(pin: &StagedInputPin) -> String {
    pointer_to(&pin.name)
}

/// The pointer task for a job staged as the file `name`.
fn pointer_to(name: &str) -> String {
    format!("Your task is the JSON job in `{name}` in the working directory. Read it first.")
}

/// Whether `pin`'s job still reads back whole in `rtxn`, as a run would
/// stage it: `false` for a pin that names no version of its own job, and
/// for a version that is gone, erased, or not the bytes the pin names.
///
/// # Errors
/// A store failure.
pub(super) fn staged_input_readable_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    pin: &StagedInputPin,
) -> ByoaResult<bool> {
    let Ok((artifact_id, version)) = pinned_version(pin) else {
        return Ok(false);
    };
    match vault.read_blob_artifact_version_in_txn(rtxn, &artifact_id, version) {
        Ok(Some(job)) => {
            Ok(job.len() as u64 == pin.len && *blake3::hash(&job).as_bytes() == pin.blake3)
        }
        Ok(None) | Err(Error::EntityNotFound) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn staged_input_artifact_id(digest: &[u8; 32]) -> ByoaResult<EntityId> {
    Ok(entity_id_from_hash_material(
        BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN,
        &[digest.as_slice()],
    )?)
}

fn staged_input_name(digest: &[u8; 32]) -> String {
    format!(
        "{BYOA_STAGED_INPUT_DIR}/{}.json",
        bytes_to_hex_lower(digest)
    )
}

impl<'a, B, E> ByoaDispatcher<'a, B, E> {
    /// This dispatcher, staging each CLI run's pinned job in its checkout
    /// through `stager` before the run ([`Self::execute_cli`]).
    #[must_use]
    pub fn with_input_stager(mut self, stager: impl ByoaInputStager + 'a) -> Self {
        self.stager = Some(Box::new(stager));
        self
    }
}

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Whether a stager is installed ([`Self::with_input_stager`]).
    pub(crate) fn stages_input(&self) -> bool {
        self.stager.is_some()
    }

    /// The job `pin` names, read back from its artifact and checked against
    /// the pin's length and digest. A read: nothing here measures or refuses
    /// the job for its size.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::StagedInputUnresolved`] when the version is
    /// missing or does not hold the bytes the pin names.
    pub(crate) fn resolve_staged_input(&self, pin: &StagedInputPin) -> ByoaResult<Vec<u8>> {
        let (artifact_id, version) = pinned_version(pin)?;
        let job = self
            .vault()
            .read_blob_artifact_version(&artifact_id, version)?
            .ok_or(ByoaError::StagedInputUnresolved)?;
        if job.len() as u64 != pin.len || *blake3::hash(&job).as_bytes() != pin.blake3 {
            return Err(ByoaError::StagedInputUnresolved);
        }
        Ok(job)
    }

    /// Stages `spec`'s pinned job in `checkout` through the installed stager,
    /// checked against its pin first. A run with no pin stages nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::InputStagerUnavailable`] when a pinned job meets
    /// no stager, the resolution's refusal, or the stager's.
    pub(super) fn stage_pinned_input(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
    ) -> ByoaResult<()> {
        let Some(pin) = &spec.staged_input else {
            return Ok(());
        };
        let job = self.resolve_staged_input(pin)?;
        let stager = self
            .stager
            .as_mut()
            .ok_or(ByoaError::InputStagerUnavailable)?;
        stager.stage(checkout, &pin.name, &job)
    }

    /// Read the canonical successful capture, not a worker-supplied receipt.
    pub(crate) fn completed_cli_exhaust(
        &self,
        attempt_id: AttemptId,
    ) -> ByoaResult<(AttemptRecord, CliSandboxSpec, ByoaExhaust)> {
        let record = AttemptQueue::new(self.vault())
            .get(attempt_id)?
            .ok_or_else(|| invalid(ERR_ATTEMPT_MISSING))?;
        let payload = decode_byoa_record(&record)?;
        self.check_payload_placement(&payload)?;
        let ByoaConnectorSpec::CliSandbox(spec) = payload.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let artifact_id = byoa_exhaust_artifact_id(attempt_id)?;
        // The result ref names the capture's head version, its envelope.
        let version = record
            .result_ref
            .as_ref()
            .and_then(|result_ref| canonical_result_version(result_ref, &artifact_id));
        let Some(version) = version.filter(|_| record.state == AttemptState::Completed) else {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        };
        if self
            .vault()
            .blob_artifact_version_metadata(&artifact_id, version)?
            .is_none()
        {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        let (captured_id, disposition, exhaust) =
            decode_byoa_exhaust(self.vault(), &artifact_id, version)?;
        if captured_id != attempt_id || disposition != ByoaTerminalDisposition::Completed {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        Ok((record, spec, exhaust))
    }
}
