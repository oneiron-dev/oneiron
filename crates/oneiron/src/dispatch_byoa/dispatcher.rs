//! Dispatcher organ with dispatch, execute, authorize, and capture doors.

mod terminal;

use std::sync::Arc;

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome,
};
use crate::checkout::{CheckoutFactSink, CheckoutLeaseAct, CheckoutLeaseService, CheckoutLiveness};
use crate::code_sandbox::SandboxBoundaryContract;
use crate::code_sandbox::microvm::ExecutionBudget;
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::llm::{BudgetLease, LlmBackend, LlmError, LlmRequest};

use super::connector::{
    BYOA_ATTEMPT_KIND, BYOA_CONNECTOR_SCHEMA_VERSION, ByoEndpointSpec, ByoaAttemptPayload,
    ByoaConnectorSpec, ByoaDispatchOutcome, ByoaDispatchStatus, CliSandboxSpec, DevRunnerRefs,
    DispatchByoa, ProtocolAttachSpec, encode_byoa_attempt_payload,
};
use super::error::{
    ByoaError, ByoaResult, ERR_ATTEMPT_MISSING, ERR_CAPTURE_CONFLICT, ERR_EXECUTION_SHAPE,
    ERR_LEASE_EXPIRED, ERR_LEASE_HOST_DENIED, ERR_LEASE_ID_ZERO, ERR_LEASE_PROFILE_MISMATCH,
    ERR_LEASE_TAINT, ERR_LEASE_UNBOUNDED, invalid,
};
use super::exhaust::{
    ByoaEgressLease, ByoaEgressPort, ByoaExhaust, ByoaTerminalDisposition, CaptureByoaExhaust,
    decode_byoa_record, union_taint_refs,
};
use super::official_seats::{
    DispatchOfficialSeat, DrySeatDecision, OfficialSeatDispatchOutcome, OfficialSeatStamp,
    check_seat_placement, decide_dry_seat, validate_official_seat,
};
use super::provider::ProviderAdapterRegistry;
use super::repo_binding::{
    StartedCliExecution, pin_checkout_in_txn, reserve_in_txn, start_execution,
};
use super::seat::{
    HostedSeatBound, OnSeatSpent, RunnerSeatPolicy, RunnerWork, SeatIdentity, SeatRoute, SeatSpent,
    hosted_seat_bound, spent_seat_in,
};
use super::seat_quota::{record_seat_quota_in_txn, seat_quota_id};
use super::validate::{
    encode_execution_transcript, encoded_json_len, validate_cli_sandbox, validate_connector,
    validate_endpoint, validate_execution_budget, validate_exhaust,
};
use super::work_binding::{
    RunnerWorkBinding, SpentCapture, capture_hop_seat_quota_in_txn, capture_seat_in_txn,
    note_spent_hop_in_txn,
};
use super::work_resume::moved_on_in_txn;
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
    /// Must enforce the supplied runtime budget while collecting output, and
    /// capture every output byte, spooling past the inline budget
    /// ([`ByoaStream::writer`](super::ByoaStream::writer)), never cutting it.
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
    /// Run the exact argv against the named checkout and capture its whole
    /// exhaust, spooled past the inline budget.
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

/// One attempt row a dispatch door lands, with its task scope already a
/// queue-shaped reference.
pub(super) struct ByoaEnqueue {
    pub(super) user_login: bool,
    pub(super) connector: ByoaConnectorSpec,
    pub(super) task_ref: Option<String>,
    pub(super) parent_attempt: Option<[u8; 16]>,
    pub(super) dev_refs: Option<DevRunnerRefs>,
    pub(super) run_id: Option<String>,
    pub(super) dedupe_key: Option<String>,
    pub(super) now: u64,
    /// The official seat stamp a seat dispatch carries (OF-375), and a
    /// runner seat whose adapter names one (FIX 5104); the generic door
    /// leaves it empty.
    pub(super) official_seat: Option<OfficialSeatStamp>,
    /// The runner work a bound dispatch carries (OF-137); none for
    /// unbound work.
    pub(super) work: Option<RunnerWorkBinding>,
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
    /// Writes a CLI run's pinned job into its checkout before the run.
    pub(super) stager: Option<Box<dyn super::staged_input::ByoaInputStager + 'a>>,
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
            stager: None,
        }
    }

    pub(crate) fn vault(&self) -> &Vault {
        self.vault
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
        self.dispatch_stamped(request, None)
    }

    /// [`Self::dispatch`] carrying `official_seat`, the stamp an approved
    /// official seat's adapter names (FIX 5104): the row's placement is then
    /// judged by the vendor's table, here and again at execution. A raw
    /// dispatch carries none.
    fn dispatch_stamped(
        &self,
        request: DispatchByoa,
        official_seat: Option<OfficialSeatStamp>,
    ) -> ByoaResult<ByoaDispatchOutcome> {
        let enqueue = ByoaEnqueue {
            user_login: request.user_login,
            connector: request.connector,
            task_ref: request.task_ref.map(|task_ref| task_ref.to_hex()),
            parent_attempt: request.parent_attempt_id.map(|id| *id.as_bytes()),
            dev_refs: request.dev_refs,
            run_id: request.run_id,
            dedupe_key: request.dedupe_key,
            now: request.now,
            official_seat,
            work: None,
        };
        self.vault
            .try_with_write_txn_grouped(|txn| self.enqueue_in_txn(txn, enqueue))
    }

    pub(super) fn enqueue_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: ByoaEnqueue,
    ) -> ByoaResult<ByoaDispatchOutcome> {
        // A stamped official seat is judged by its vendor's terms (the
        // seat table admits what the generic login door would refuse, e.g.
        // an approved hosted plan login); every other row keeps the
        // generic placement rule.
        match request.official_seat {
            Some(stamp) => check_seat_placement(
                stamp.route,
                self.vault.config.privacy.posture,
                stamp.approvals,
                stamp.unmodified_binary,
            )?,
            None => self.check_login_placement(request.user_login, &request.connector)?,
        }
        validate_connector(&request.connector)?;
        if let ByoaConnectorSpec::CliSandbox(spec) = &request.connector {
            let longest = spec.argv.iter().map(String::len).max().unwrap_or_default();
            let _ = self
                .vault
                .measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
        }
        // FIX 6867: a CLI attempt's checkout is pinned before encode and
        // reserved for the returned attempt in this same writer.
        let pinned = pin_checkout_in_txn(self.vault, txn, &request.connector, &request.task_ref)?;
        // A bound work keeps the first custody a CLI seat of it pinned, so a
        // successor of any shape claims its fresh checkout from it.
        let work = request.work.map(|mut work| {
            if work.repo_binding.is_none() {
                work.repo_binding.clone_from(&pinned);
            }
            work
        });
        let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
            user_login: request.user_login,
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            connector: request.connector,
            parent_attempt: request.parent_attempt,
            dev_refs: request.dev_refs,
            official_seat: request.official_seat,
            repo_binding: pinned.clone(),
            work,
        })?;
        let outcome = crate::ports::JobQueue::port_job_enqueue_scoped(
            self.vault,
            txn,
            EnqueueAttempt {
                kind: BYOA_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: request.dedupe_key,
                run_id: request.run_id,
                now: request.now,
            },
            crate::ports::JobScope {
                task_ref: request.task_ref,
                dedupe_actor_ref: None,
            },
        )?;
        reserve_in_txn(self.vault, txn, pinned.as_ref(), &outcome)?;
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

    /// Dispatches one official subscription seat (OF-375).
    ///
    /// Placement follows the vendor's terms, not only the generic
    /// login-placement rule: the unmodified Claude Code binary may run in a
    /// hosted vault VM, a Claude.ai SDK login needs Anthropic's approval,
    /// and a ChatGPT-plan login stays on the person's own runtime until
    /// OpenAI approves hosted use. A dry seat is an outcome, never an error
    /// and never a silent spend: it parks, or it hands back the owner's
    /// pre-chosen fallback for the host to route. The seat rides the
    /// attempt payload as a stamp, so execution re-judges the same table.
    ///
    /// # Errors
    ///
    /// Returns the typed seat refusal (unsupported route, missing vendor
    /// approval, modified binary, cloud login) or [`ByoaError::Store`] when
    /// the connector fails the door or the queue refuses the row.
    pub fn dispatch_official_seat(
        &mut self,
        request: DispatchOfficialSeat,
    ) -> ByoaResult<OfficialSeatDispatchOutcome> {
        validate_official_seat(&request.seat)?;
        check_seat_placement(
            request.seat.route,
            self.vault.config.privacy.posture,
            request.seat.approvals,
            request.seat.unmodified_binary,
        )?;
        let decision = decide_dry_seat(
            request.seat.plan_window.as_ref(),
            request.seat.dry_fallback,
            request.now,
        );
        match decision {
            DrySeatDecision::Park { until } => {
                Ok(OfficialSeatDispatchOutcome::Parked { resets_at: until })
            }
            DrySeatDecision::ContinueOnLocal | DrySeatDecision::Spend { .. } => {
                Ok(OfficialSeatDispatchOutcome::DryFallback(decision))
            }
            DrySeatDecision::Run => {
                let enqueue = ByoaEnqueue {
                    user_login: request.seat.route.is_user_login(),
                    connector: request.connector,
                    task_ref: request.task_ref.map(|task_ref| task_ref.to_hex()),
                    parent_attempt: request.parent_attempt_id.map(|id| *id.as_bytes()),
                    dev_refs: None,
                    run_id: request.run_id,
                    dedupe_key: request.dedupe_key,
                    now: request.now,
                    official_seat: Some(request.seat.stamp()),
                    work: None,
                };
                let outcome = self
                    .vault
                    .try_with_write_txn_grouped(|txn| self.enqueue_in_txn(txn, enqueue))?;
                Ok(OfficialSeatDispatchOutcome::Dispatched(outcome))
            }
        }
    }

    /// Dispatches `work` to the policy's `seat` through the runner adapter
    /// the registry names for it (OF-137). The seat's login rides the attempt
    /// as `user_login`, and the adapter's official stamp, when it names one
    /// (FIX 5104), as the row's seat, so the placement door holds again
    /// before execution on the same terms.
    ///
    /// # Errors
    ///
    /// Refuses an invalid policy or seat index, an unknown runner, a login
    /// this runtime may not run, and every refusal [`Self::dispatch`] has.
    pub fn dispatch_runner(
        &mut self,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        seat: usize,
        work: RunnerWork,
    ) -> ByoaResult<ByoaDispatchOutcome> {
        policy.validate(registry)?;
        let chosen = policy.seat(seat)?;
        let connector = chosen.connector(registry, work.task, work.checkout_id)?;
        let context = registry.resolve(&chosen.runner)?.placement_context();
        self.dispatch_stamped(
            DispatchByoa {
                user_login: chosen.logs_in(),
                connector,
                task_ref: work.task_ref,
                dev_refs: None,
                parent_attempt_id: work.parent_attempt_id,
                run_id: work.run_id,
                dedupe_key: work.dedupe_key,
                now: work.now,
            },
            context,
        )
    }

    /// Captures a runner attempt's terminal exhaust and, when the seat it
    /// ran on is spent, routes its work under the owner's policy, all in one
    /// write transaction (OF-137). A failed capture is read whole for a
    /// spent seat unless the host already knows one (`spent`, from
    /// [`ByoaError::SeatSpent`]), and what it read is kept as the seat's
    /// quota ([`super::runner_seat_quotas`]). A failed run that its seat's
    /// spend interrupted settles Abandoned, keeping its reason, exhaust,
    /// frontier, taint and result (FIX 9793). Stop parks the work until the
    /// seat is back; NextSeat hands it to the next seat this runtime may
    /// run, as a child of the spent attempt, from the durable row alone: a
    /// bound work of any connector shape ([`super::RunnerWorkBinding`]), or
    /// a CLI runner's task. It parks, its capture standing, when no seat is
    /// left or the work has nothing to hand on (an unbound endpoint or MCP
    /// seat's). A spent seat, a CLI seat with no readable task and a seat a
    /// hosted-only bound keeps off this runtime are passed over and named in
    /// `skipped_seats`; a stamped seat is judged, and dispatched, on its
    /// stamp (FIX 5104). InternalModels hands the work
    /// back to the Dreamer's own model roles. A bound work's record notes
    /// each hop. A replay finds the same capture and the same child, or
    /// where a bound work that has since moved on stands.
    ///
    /// # Errors
    ///
    /// Refuses an invalid policy or seat index, and every refusal capture
    /// and dispatch have, without durable writes.
    pub fn route_runner_terminal(
        &mut self,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        seat: usize,
        mut capture: CaptureByoaExhaust,
        spent: Option<SeatSpent>,
    ) -> ByoaResult<SeatRoute> {
        policy.validate(registry)?;
        policy.seat(seat)?;
        let spent = match spent {
            None if capture.disposition == ByoaTerminalDisposition::Failed => {
                spent_seat_in(&capture.exhaust)?
            }
            spent => spent,
        };
        if let Some(spent) = &spent {
            // FIX 9793: the spend interrupted a failed run, so it settles
            // Abandoned before its reason is normalized and its capture and
            // route are written. A Completed or Cancelled landing keeps its own.
            if capture.disposition == ByoaTerminalDisposition::Failed {
                capture.disposition = ByoaTerminalDisposition::Abandoned;
            }
            capture
                .reason
                .get_or_insert_with(|| spent.reason().to_owned());
        }
        let now = capture.now;
        self.vault.try_with_write_txn_grouped(|wtxn| {
            let receipt = self.capture_terminal_exhaust_in_txn(wtxn, capture)?;
            // A replayed spend of a bound work that moved past it (FIX 7450)
            // writes nothing more and names where the work stands.
            if let Some(route) =
                moved_on_in_txn(self.vault, wtxn, policy, &receipt, spent.as_ref())?
            {
                return Ok(route);
            }
            let seat = capture_seat_in_txn(self.vault, wtxn, policy, &receipt, seat)?;
            let ran = match seat {
                Some(index) => Some(policy.seat(index)?),
                None => None,
            };
            if let Some(ran) = ran {
                record_seat_quota_in_txn(self.vault, wtxn, ran, &receipt.attempt, spent.as_ref())?;
            }
            let Some(spent) = spent else {
                return Ok(SeatRoute::Settled(receipt));
            };
            let route = match policy.on_spent {
                OnSeatSpent::Stop => SeatRoute::Park {
                    until: spent.back_at(now),
                    receipt,
                    spent: spent.clone(),
                },
                OnSeatSpent::InternalModels => SeatRoute::InternalModels {
                    receipt,
                    spent: spent.clone(),
                },
                OnSeatSpent::NextSeat => self.next_seat_in_txn(
                    wtxn,
                    registry,
                    policy,
                    SpentCapture {
                        receipt,
                        spent: spent.clone(),
                        seat,
                        now,
                    },
                )?,
            };
            // A bound work the spend kept on this seat notes it for its outcome.
            if !matches!(route, SeatRoute::NextSeat { .. }) {
                let (seat, quota) = match seat {
                    Some(index) => (index, *seat_quota_id(policy.seat(index)?)?.as_bytes()),
                    None => capture_hop_seat_quota_in_txn(self.vault, wtxn, route.receipt())?,
                };
                note_spent_hop_in_txn(self.vault, wtxn, route.receipt(), seat, quota, &spent)?;
            }
            Ok(route)
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

    /// The hosted-only bound that keeps a login behind `connector` off this
    /// runtime, if any ([`hosted_seat_bound`]). A connector without a login
    /// has none.
    fn login_bound(
        &self,
        user_login: bool,
        connector: &ByoaConnectorSpec,
    ) -> Option<HostedSeatBound> {
        hosted_seat_bound(
            SeatIdentity::of(connector),
            user_login,
            self.vault.config.privacy.posture,
            None,
        )
    }

    /// The hosted-only bound that keeps a fallback seat off this runtime:
    /// judged by its vendor's table when its adapter names an official stamp
    /// (FIX 5104), as its dispatch and execution judge it, else by the
    /// connector's login ([`Self::login_bound`]).
    pub(super) fn seat_bound(
        &self,
        user_login: bool,
        connector: &ByoaConnectorSpec,
        context: Option<OfficialSeatStamp>,
    ) -> ByoaResult<Option<HostedSeatBound>> {
        let Some(stamp) = context else {
            return Ok(self.login_bound(user_login, connector));
        };
        match check_seat_placement(
            stamp.route,
            self.vault.config.privacy.posture,
            stamp.approvals,
            stamp.unmodified_binary,
        ) {
            Ok(()) => Ok(None),
            Err(ByoaError::CloudLoginRefused { bound }) => Ok(Some(bound)),
            Err(error) => Err(error),
        }
    }

    fn check_login_placement(
        &self,
        user_login: bool,
        connector: &ByoaConnectorSpec,
    ) -> ByoaResult<()> {
        if let Some(bound) = self.login_bound(user_login, connector) {
            return Err(ByoaError::CloudLoginRefused { bound });
        }
        Ok(())
    }

    /// Execution-time placement, re-checked from the durable row. A stamped
    /// official seat is judged by its vendor's terms (the same table its
    /// dispatch passed); an unstamped row by the connector it carries. Both
    /// re-resolve [`hosted_seat_bound`] here; no verdict is stored.
    pub(super) fn check_payload_placement(&self, payload: &ByoaAttemptPayload) -> ByoaResult<()> {
        match payload.official_seat {
            Some(stamp) => check_seat_placement(
                stamp.route,
                self.vault.config.privacy.posture,
                stamp.approvals,
                stamp.unmodified_binary,
            ),
            None => self.check_login_placement(payload.user_login, &payload.connector),
        }
    }

    fn execution_record(&self, fence: &ByoaExecutionFence) -> ByoaResult<AttemptRecord> {
        let record = AttemptQueue::new(self.vault)
            .get(fence.attempt_id)?
            .ok_or_else(|| invalid(ERR_ATTEMPT_MISSING))?;
        let payload = decode_byoa_record(&record)?;
        self.check_payload_placement(&payload)?;
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
    /// Refuses stale fences, unbound/mismatched models, and backend failures;
    /// the request and response are measured, never refused for their size.
    /// Provider error text is not copied into custody.
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
        let _ = self.vault.measure_limit(
            EngineLimit::MaintenanceTextBytes,
            encoded_json_len(&request)?,
        );
        let backend = self.endpoint_backend(&spec)?;
        let response = backend.generate(request, lease).await.map_err(|error| {
            // A spent seat keeps its type so the caller can route it; every
            // other provider error stays out of custody.
            let spent = match &error {
                LlmError::Retryable(retryable) => SeatSpent::from_retryable(retryable),
                _ => None,
            };
            spent.map_or_else(
                || ByoaError::Backend("endpoint execution failed".to_owned()),
                ByoaError::SeatSpent,
            )
        })?;
        Ok(ByoaExhaust {
            transcript: Some(encode_execution_transcript(&response)?),
            ..ByoaExhaust::default()
        })
    }

    /// Attaches and executes MCP using the host client, not just its config.
    ///
    /// # Errors
    /// Refuses an invalid fence, connector, or budget, and propagates the host
    /// client's refusal. The input is measured, never refused for its size.
    pub fn execute_mcp<M: ByoaMcpExecutor>(
        &self,
        fence: &ByoaExecutionFence,
        input: &[u8],
        budget: ExecutionBudget,
        executor: &mut M,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::ProtocolAttach(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, input.len() as u64);
        let exhaust = executor.attach_and_run(&spec, input, budget)?;
        validate_exhaust(&exhaust)?;
        Ok(exhaust)
    }

    /// Invokes a host sandbox against a live checkout through the foreign
    /// boundary, once the run's pinned job is staged there. The checkout's
    /// custody is judged at the vault's time in one short writer before
    /// staging, and again at terminal capture; no LMDB write lock is held
    /// meanwhile. `_checkouts` is kept for the host's call; custody is read
    /// from the vault in that writer.
    ///
    /// # Errors
    /// Refuses stale leases, missing/expired checkouts, invalid budgets and a
    /// pinned job with no stager, or propagates the stager's or the sandbox's
    /// refusal (its spool's disk floor and deadline among them).
    pub fn execute_cli<C: ByoaCliExecutor, F: CheckoutFactSink, L: CheckoutLiveness>(
        &mut self,
        fence: &ByoaExecutionFence,
        budget: ExecutionBudget,
        _checkouts: &CheckoutLeaseService<'_, F, L>,
        executor: &mut C,
        now: u64,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        self.execution_record(fence)?;
        // FIX 6867, 9792: the checkout's custody, bound at dispatch or now,
        // and its generation saved in a short writer before staging, which
        // returns the spec the row carries now; no writer spans the child.
        let StartedCliExecution { spec, checkout } = start_execution(self.vault, fence)?;
        self.stage_pinned_input(&spec, &checkout)?;
        let intent = bytes_to_hex_lower(fence.attempt_id.as_bytes());
        // Every secret a granted lease injected taints this run's output.
        let mut injected = Vec::new();
        let mut authorize = |host: &str, at: u64| {
            if at < now {
                return Err(invalid(ERR_LEASE_EXPIRED));
            }
            let lease = self.authorize_cli_egress(&spec, host, &intent, at)?;
            union_taint_refs(&mut injected, &lease.secret_taint_refs);
            Ok(lease)
        };
        let mut exhaust = executor.run(
            &spec,
            &checkout,
            CliSandboxSpec::boundary_contract(),
            budget,
            &mut authorize,
        )?;
        union_taint_refs(&mut injected, &exhaust.secret_taint_refs);
        exhaust.secret_taint_refs = injected;
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
        // The requested host is judged against the whole granted list;
        // how many hosts a grant names is never refused.
        if lease.allowed_hosts.is_empty() {
            return Err(denied(ERR_LEASE_UNBOUNDED));
        }
        if now >= lease.expires_at {
            return Err(denied(ERR_LEASE_EXPIRED));
        }
        if !lease.permits_host(host, now) {
            return Err(denied(ERR_LEASE_HOST_DENIED));
        }
        if crate::secret_rotation::validate_taint_refs(&lease.secret_taint_refs).is_err() {
            return Err(denied(ERR_LEASE_TAINT));
        }
        Ok(lease)
    }
}
