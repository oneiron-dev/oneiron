//! Real model requests served on one held credential attachment (FIX 7176).

use std::sync::{Arc, Mutex};

use oneiron::agent_def::ensure_listed;
use oneiron::authority::VerifiedSlip;
use oneiron::code_run::live_run::CodeRunLiveRunBinding;
use oneiron::code_run::{RepoModelGenerateInput, RepoRequestWitness};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, LlmRequest, LlmResponse, ModelTierRef, TierPrecedence,
    Vault,
};

use crate::ai_host::live_lease::{LiveLease, LiveLeaseState};
use crate::mcp::ScopeMeter;

use super::{HeldLiveRun, LiveRunEntry, LiveRuns, lock};
use crate::server::SyncServer;

const REPO_MODEL_PURPOSE: &str = "repo.model.generate";

/// Books the same per-rung ledger even if the HTTP future is dropped.
struct ScopeBooking {
    vault: Arc<Vault>,
    state: Option<LiveLeaseState>,
}

impl ScopeBooking {
    fn finish(&mut self) -> oneiron::Result<()> {
        if let Some(state) = self.state.take() {
            LiveLease::from_state(&self.vault, state).book_rest()?;
        }
        Ok(())
    }
}

impl Drop for ScopeBooking {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            tracing::warn!(kind = ?error.kind(), "an attached model call's spend was not booked");
        }
    }
}

impl HeldLiveRun {
    /// The last request this exact credential attachment was actually served.
    /// A different issue, credential or leased generation never inherits it.
    pub(crate) fn repo_request(&self) -> Option<RepoRequestWitness> {
        lock(&self.entry.repo_request)
            .as_ref()
            .filter(|(binding, _)| binding == &self.binding)
            .map(|(_, request)| request.clone())
    }

    pub(crate) async fn generate_repo_model(
        &self,
        server: &Arc<SyncServer>,
        credential: VerifiedSlip,
        input: RepoModelGenerateInput,
    ) -> MemoryResult<LlmResponse> {
        let vault = Arc::clone(server.vault());
        let unavailable = || MemoryError::bad_request("this live run has no native model backend");
        let seat = self.entry.model_seat.as_ref().ok_or_else(unavailable)?;
        let provider = server
            .code_execution_host()
            .and_then(|host| host.engine_native())
            .map(|host| Arc::clone(host.provider()))
            .ok_or_else(unavailable)?;
        let (guard, payer, state) = match self.entry.spend_scope.as_ref() {
            Some(scope) => {
                // A failed scoped line never falls back to the host's line.
                let meter = ScopeMeter::open(&vault, scope).map_err(|_| {
                    MemoryError::bad_request("the attached run's spend line did not open")
                })?;
                let state = meter.lease.on(&vault).state();
                (meter.guard, meter.payer, Some(state))
            }
            None => (provider.host_meter().ok_or_else(unavailable)?, None, None),
        };
        let mut booking = ScopeBooking {
            vault: Arc::clone(&vault),
            state: state.clone(),
        };
        let observed = Arc::new(Mutex::new(None));
        let observer = {
            let (vault, runs, entry, binding, credential, observed) = (
                Arc::clone(&vault),
                Arc::clone(&server.live_runs),
                Arc::clone(&self.entry),
                self.binding.clone(),
                credential.clone(),
                Arc::clone(&observed),
            );
            Arc::new(move |request: &LlmRequest| {
                if !attachment_holds(&runs, &vault, &entry, &binding, &credential).unwrap_or(false)
                {
                    return false;
                }
                *lock(&observed) = RepoRequestWitness::capture(request);
                true
            }) as crate::mcp::ReaderRequestObserver
        };
        let backend = provider
            .reader_backend_observed(
                guard,
                payer,
                state,
                self.entry.definition.models.clone(),
                observer,
            )
            .ok_or_else(unavailable)?;
        let purpose = CallPurpose::Other {
            name: REPO_MODEL_PURPOSE.to_owned(),
        };
        let mut request = LlmRequest {
            model: seat.model().clone(),
            envelope: CallEnvelope {
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(REPO_MODEL_PURPOSE.to_owned()),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: input.response_format,
                locality: seat.locality(),
                host_keyless: false,
                host_paid: false,
                seat_effort: None,
            },
            messages: input.messages,
            tools: input.tools,
            params: input.params,
            provider_options: input.provider_options,
            host_segments: None,
        };
        seat.bind(&mut request);
        ensure_listed(&self.entry.definition, &request.model)?;
        let _turn = server.ai.enter_turn();
        let answer = backend.generate(request, provider.lease()).await;
        booking.finish()?;
        let answer = answer
            .map_err(|_| MemoryError::bad_request("the attached model call did not complete"))?;
        if !attachment_holds(
            &server.live_runs,
            &vault,
            &self.entry,
            &self.binding,
            &credential,
        )? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the live-run credential or lease no longer holds",
                &[],
            ));
        }
        if let Some(request) = lock(&observed).take() {
            *lock(&self.entry.repo_request) = Some((self.binding.clone(), request));
        }
        Ok(answer)
    }
}

fn attachment_holds(
    runs: &LiveRuns,
    vault: &Vault,
    entry: &Arc<LiveRunEntry>,
    binding: &CodeRunLiveRunBinding,
    credential: &VerifiedSlip,
) -> oneiron::Result<bool> {
    Ok(runs.holds(vault, entry)?
        && lock(&entry.attached).as_ref() == Some(binding)
        && vault.credential_read_key(credential)?.is_some())
}
