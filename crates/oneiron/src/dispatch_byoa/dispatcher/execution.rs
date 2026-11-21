//! The execution doors: endpoint, MCP, and CLI runs, with the egress authorize
//! door the CLI runs reach through.

use super::*;

impl<'a, B, E> ByoaDispatcher<'a, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
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
    /// The returned exhaust can be passed to `capture_terminal_exhaust`: its
    /// transcript, and the secrets the host's binding says it injected, so the
    /// capture carries their taint. The backend owns transport timeouts and
    /// enforces its budget lease.
    ///
    /// # Errors
    /// Refuses stale fences, unbound/mismatched models, a binding whose taint
    /// refs are malformed (before any traffic moves), and backend failures;
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
        let ByoEndpointBinding {
            backend,
            secret_taint_refs,
        } = self.endpoint_backend(&spec)?;
        crate::secret_rotation::validate_taint_refs(&secret_taint_refs)
            .map_err(|_| invalid(ERR_EXHAUST_TAINT))?;
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
            transcript: Some(encode_execution_transcript(
                &response,
                self.vault.proposal_spool(),
            )?),
            secret_taint_refs,
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
    /// meanwhile.
    ///
    /// # Errors
    /// Refuses stale leases, missing/expired checkouts, invalid budgets and a
    /// pinned job with no stager, or propagates the stager's or the sandbox's
    /// refusal (its spool's disk floor and deadline among them).
    pub fn execute_cli<C: ByoaCliExecutor>(
        &mut self,
        fence: &ByoaExecutionFence,
        budget: ExecutionBudget,
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
