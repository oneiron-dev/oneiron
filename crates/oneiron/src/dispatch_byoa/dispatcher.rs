//! Dispatcher organ with dispatch, execute, authorize, and capture doors.

use std::sync::Arc;

use crate::Vault;
use crate::attempt_queue::{
    AbandonAttempt, AbandonOutcome, AttemptId, AttemptQueue, AttemptRecord, CompleteAttempt,
    CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome,
    FinishAttemptLanding, FinishLandingOutcome, SetAttemptResult,
};
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body,
    read_blob_artifact_head_in_txn,
};
use crate::checkout::{
    CheckoutFactSink, CheckoutLeaseAct, CheckoutLeaseService, CheckoutLeaseState, CheckoutLiveness,
};
use crate::code_sandbox::SandboxBoundaryContract;
use crate::code_sandbox::microvm::ExecutionBudget;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::llm::{BudgetLease, LlmBackend, LlmRequest};
use crate::temporal::TimeRange;

use super::connector::{
    BYOA_ATTEMPT_KIND, BYOA_CONNECTOR_SCHEMA_VERSION, BYOA_EXHAUST_MEDIA_TYPE,
    BYOA_MAX_EXHAUST_STREAM_BYTES, ByoEndpointSpec, ByoaAttemptPayload, ByoaConnectorSpec,
    ByoaDispatchOutcome, ByoaDispatchStatus, CliSandboxSpec, DispatchByoa, MAX_ALLOWED_HOSTS,
    ProtocolAttachSpec, encode_byoa_attempt_payload,
};
use super::error::{
    ByoaError, ByoaResult, ERR_ARTIFACT_COLLISION, ERR_ATTEMPT_MISSING, ERR_CAPTURE_CONFLICT,
    ERR_EXECUTION_CHECKOUT, ERR_EXECUTION_SHAPE, ERR_EXHAUST_TOO_LARGE, ERR_LEASE_EXPIRED,
    ERR_LEASE_HOST_DENIED, ERR_LEASE_ID_ZERO, ERR_LEASE_PROFILE_MISMATCH, ERR_LEASE_UNBOUNDED,
    invalid,
};
use super::exhaust::{
    ByoaEgressLease, ByoaEgressPort, ByoaExhaust, ByoaExhaustEnvelope, ByoaTerminalDisposition,
    ByoaTerminalReceipt, CaptureByoaExhaust, byoa_exhaust_artifact_id, byoa_exhaust_artifact_name,
    byoa_result_ref, decode_byoa_record, disposition_matches_state, encode_exhaust_envelope,
    ensure_byoa_runtime_actor, normalize_capture_reason, validate_canonical_capture,
};
use super::validate::{
    encode_execution_transcript, validate_cli_sandbox, validate_connector, validate_endpoint,
    validate_execution_budget, validate_exhaust,
};
use crate::error::ArtifactError;
/// Resolves an endpoint config into a concrete host-owned backend.
///
/// The factory is the host's, not this module's: provider transports, custody
/// wiring, and retry policy all stay on the host side of this seam.
pub trait ByoEndpointBackendFactory {
    /// Resolves `spec` into the backend that serves it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Backend`] when no backend can serve the config, or
    /// [`ByoaError::CredentialUnavailable`] when the custody handle cannot be
    /// opened.
    fn resolve_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>>;
}

/// The claimed attempt a host is about to execute. Connector truth is loaded
/// from this row, never supplied again by the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaExecutionFence {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
}

/// Host-owned MCP client. Implementations attach to the configured server,
/// perform the bounded call, close the session, and return its exhaust.
/// Credential resolution and MCP wire details stay outside the engine.
pub trait ByoaMcpExecutor {
    /// Must enforce the supplied runtime budget and exhaust byte limits while
    /// collecting output, not after reading an unbounded transport response.
    ///
    /// # Errors
    /// Returns a refusal if attachment or execution fails.
    fn attach_and_run(
        &mut self,
        spec: &ProtocolAttachSpec,
        input: &[u8],
        budget: ExecutionBudget,
    ) -> ByoaResult<ByoaExhaust>;
}

/// Host-owned foreign sandbox runner. There is no process/shell fallback.
/// The host resolves the live checkout into its real worktree, enforces the
/// supplied foreign boundary and budget, and routes every guest network reach
/// through `authorize`. A returned lease is not permission for direct sockets.
pub trait ByoaCliExecutor {
    /// Run the exact argv against the named checkout and collect bounded exhaust.
    ///
    /// # Errors
    /// Refuses unavailable checkouts, confinement, egress, or runtime failures.
    fn run(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        boundary: SandboxBoundaryContract,
        budget: ExecutionBudget,
        authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust>;
}

/// The foreign-agent dispatch organ.
///
/// It owns no transport of its own. The endpoint factory and the egress port
/// are both INJECTED, which is what makes "network only through the egress
/// door" a structural property rather than a convention: there is no field
/// here that could reach a socket without one.
pub struct ByoaDispatcher<'a, B, E> {
    vault: &'a Vault,
    endpoint_factory: B,
    egress: E,
}

impl<'a, B, E> ByoaDispatcher<'a, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Opens a dispatcher over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault, endpoint_factory: B, egress: E) -> Self {
        Self {
            vault,
            endpoint_factory,
            egress,
        }
    }

    /// Validates a foreign connector and lands it on a durable attempt row.
    ///
    /// Nothing is reached out to here. Dispatch records the INTENT; the
    /// endpoint backend and the egress lease are both acquired later, at the
    /// moment work actually runs, because an expiring lease taken at dispatch
    /// time would be dead before the executor used it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the connector fails the door or the
    /// queue refuses the row.
    pub fn dispatch(&mut self, request: DispatchByoa) -> ByoaResult<ByoaDispatchOutcome> {
        validate_connector(&request.connector)?;
        let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            connector: request.connector,
            parent_attempt: request.parent_attempt_id.map(|id| *id.as_bytes()),
        })?;

        let queue = AttemptQueue::new(self.vault);
        let outcome = queue.enqueue_with_task_ref(
            EnqueueAttempt {
                kind: BYOA_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: request.dedupe_key,
                run_id: request.run_id,
                now: request.now,
            },
            request.task_ref.map(|task_ref| task_ref.to_hex()),
        )?;

        let status = |attempt: AttemptRecord| -> ByoaResult<ByoaDispatchStatus> {
            let connector_kind = decode_byoa_record(&attempt)?.connector.kind();
            Ok(ByoaDispatchStatus {
                attempt,
                connector_kind,
            })
        };
        Ok(match outcome {
            EnqueueOutcome::Enqueued(attempt) => ByoaDispatchOutcome::Dispatched(status(attempt)?),
            EnqueueOutcome::Existing(attempt) => ByoaDispatchOutcome::Existing(status(attempt)?),
        })
    }

    /// Resolves an endpoint connector into the host backend that serves it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the config fails the door, or the
    /// factory's own refusal.
    pub fn endpoint_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        validate_endpoint(spec)?;
        self.endpoint_factory.resolve_backend(spec)
    }

    fn execution_record(&self, fence: &ByoaExecutionFence) -> ByoaResult<AttemptRecord> {
        let record = AttemptQueue::new(self.vault)
            .get(fence.attempt_id)?
            .ok_or_else(|| invalid(ERR_ATTEMPT_MISSING))?;
        decode_byoa_record(&record)?;
        AttemptQueue::check_result_lease(
            &record,
            &fence.lease_owner,
            fence.attempt_count,
            "execute_byoa",
        )?;
        if record.result_ref.is_some() {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        Ok(record)
    }

    /// Invokes the persisted endpoint through its host backend and budget lease.
    /// The returned transcript can be passed to `capture_terminal_exhaust`.
    /// The backend owns transport timeouts and enforces its budget lease.
    ///
    /// # Errors
    /// Refuses stale fences, unbound/mismatched models, oversized input/output,
    /// and backend failures. Provider error text is not copied into custody.
    pub async fn execute_endpoint(
        &self,
        fence: &ByoaExecutionFence,
        slug: &str,
        request: LlmRequest,
        lease: &BudgetLease,
    ) -> ByoaResult<ByoaExhaust> {
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::Endpoint(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        if spec.model_for_slug(slug)? != &request.model {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        }
        encode_execution_transcript(&request)?;
        let backend = self.endpoint_backend(&spec)?;
        let response = backend
            .generate(request, lease)
            .await
            .map_err(|_| ByoaError::Backend("endpoint execution failed".to_owned()))?;
        Ok(ByoaExhaust {
            transcript: Some(encode_execution_transcript(&response)?),
            ..ByoaExhaust::default()
        })
    }

    /// Attaches and executes MCP using the host client, not just its config.
    ///
    /// # Errors
    /// Refuses an invalid fence, connector, budget, or oversized input/output,
    /// and propagates the host client's refusal.
    pub fn execute_mcp<M: ByoaMcpExecutor>(
        &self,
        fence: &ByoaExecutionFence,
        input: &[u8],
        budget: ExecutionBudget,
        executor: &mut M,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        if input.len() > BYOA_MAX_EXHAUST_STREAM_BYTES {
            return Err(invalid(ERR_EXHAUST_TOO_LARGE));
        }
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::ProtocolAttach(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let exhaust = executor.attach_and_run(&spec, input, budget)?;
        validate_exhaust(&exhaust)?;
        Ok(exhaust)
    }

    /// Invokes a host sandbox against a live checkout through the foreign
    /// boundary. Lease validation occurs again at terminal capture; no LMDB
    /// write lock is held while host code executes.
    ///
    /// # Errors
    /// Refuses stale leases, missing/expired checkouts, invalid budgets, and
    /// unbounded output, or propagates the sandbox's refusal.
    pub fn execute_cli<C: ByoaCliExecutor, F: CheckoutFactSink, L: CheckoutLiveness>(
        &mut self,
        fence: &ByoaExecutionFence,
        budget: ExecutionBudget,
        checkouts: &CheckoutLeaseService<'_, F, L>,
        executor: &mut C,
        now: u64,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::CliSandbox(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let checkout = checkouts
            .get(spec.checkout_id)
            .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?
            .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
        if checkout.state != CheckoutLeaseState::Active
            || now < checkout.updated_at
            || checkout
                .lease_expires_at
                .is_some_and(|expiry| now >= expiry)
            || record
                .task_ref
                .as_ref()
                .is_some_and(|task| *task != checkout.task_ref.to_hex())
        {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        let intent = bytes_to_hex_lower(fence.attempt_id.as_bytes());
        let mut authorize = |host: &str, at: u64| {
            if at < now {
                return Err(invalid(ERR_LEASE_EXPIRED));
            }
            self.authorize_cli_egress(&spec, host, &intent, at)
        };
        let exhaust = executor.run(
            &spec,
            &checkout,
            CliSandboxSpec::boundary_contract(),
            budget,
            &mut authorize,
        )?;
        validate_exhaust(&exhaust)?;
        Ok(exhaust)
    }

    /// Authorizes ONE outbound host for a CLI-sandbox guest.
    ///
    /// This is the only network door in the module. A guest that tries to
    /// reach the network any other way has no lease, and no lease means no
    /// reach: there is nothing else here to grant it.
    ///
    /// The lease the port hands back is re-checked rather than trusted: a port
    /// that returned a lease for the wrong profile, an already-expired one, an
    /// unbounded one, or one that does not admit the requested host is a
    /// denial, not a grant.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::EgressDenied`] when the port refuses or the lease
    /// does not actually authorize `host`.
    pub fn authorize_cli_egress(
        &mut self,
        spec: &CliSandboxSpec,
        host: &str,
        intent_ref: &str,
        now: u64,
    ) -> ByoaResult<ByoaEgressLease> {
        validate_cli_sandbox(spec)?;
        let lease = self.egress.open(&spec.egress_profile_ref, intent_ref)?;
        let denied = |reason: &str| ByoaError::EgressDenied {
            profile_ref: spec.egress_profile_ref.clone(),
            reason: reason.to_owned(),
        };
        if lease.profile_ref != spec.egress_profile_ref {
            return Err(denied(ERR_LEASE_PROFILE_MISMATCH));
        }
        if lease.lease_id == [0_u8; 16] {
            return Err(denied(ERR_LEASE_ID_ZERO));
        }
        if lease.allowed_hosts.is_empty() || lease.allowed_hosts.len() > MAX_ALLOWED_HOSTS {
            return Err(denied(ERR_LEASE_UNBOUNDED));
        }
        if now >= lease.expires_at {
            return Err(denied(ERR_LEASE_EXPIRED));
        }
        if !lease.permits_host(host, now) {
            return Err(denied(ERR_LEASE_HOST_DENIED));
        }
        Ok(lease)
    }

    /// Folds a terminated executor's exhaust into one canonical artifact.
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
    /// collisions, and invalid or oversized exhaust without durable writes.
    pub fn capture_terminal_exhaust(
        &mut self,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        self.vault
            .try_with_write_txn(|wtxn| self.capture_terminal_exhaust_in_txn(wtxn, request))
    }

    pub(super) fn capture_terminal_exhaust_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        validate_exhaust(&request.exhaust)?;
        let reason = normalize_capture_reason(request.disposition, request.reason)?;
        if request.lease_owner.is_empty() || request.lease_owner.len() > 128 {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        let artifact_id = byoa_exhaust_artifact_id(request.attempt_id)?;
        let result_ref = byoa_result_ref(&artifact_id, 1)?;
        let envelope = ByoaExhaustEnvelope {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            attempt_id: *request.attempt_id.as_bytes(),
            lease_owner: request.lease_owner,
            attempt_count: request.attempt_count,
            disposition: request.disposition,
            exhaust: request.exhaust,
        };
        let bytes = encode_exhaust_envelope(&envelope)?;
        let body = BlobArtifactBody::new(
            byoa_exhaust_artifact_name(request.attempt_id),
            BYOA_EXHAUST_MEDIA_TYPE,
        );
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
        decode_byoa_record(&record)?;
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
        if let Some(existing_ref) = record.result_ref.as_ref() {
            // This build never commits a canonical capture on a running row.
            // A generic result attachment cannot stand in for terminal custody.
            if !record.state.is_terminal() || existing_ref != &result_ref {
                return Err(invalid(ERR_CAPTURE_CONFLICT));
            }
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
                &body,
                &provenance,
                &envelope,
            )?;
            return Ok(ByoaTerminalReceipt {
                attempt: record,
                artifact_id,
                artifact_version: 1,
                result_ref,
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
            ByoaTerminalDisposition::Completed => match queue.complete_in_txn(
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
            ByoaTerminalDisposition::Failed => match queue.fail_in_txn(
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
        let version = self.vault.append_blob_artifact_version_in_txn(
            wtxn,
            &artifact_id,
            &bytes,
            &provenance,
            actor,
            occurred,
            request.now,
        )?;
        if version.version != 1 {
            return Err(invalid(ERR_ARTIFACT_COLLISION));
        }
        Ok(ByoaTerminalReceipt {
            attempt,
            artifact_id,
            artifact_version: version.version,
            result_ref,
        })
    }
}
