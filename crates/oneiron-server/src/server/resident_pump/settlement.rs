//! Completion, failure, and durable parking of leased agent runs.
//! `settle` chooses the existing completion or failure door for each outcome.
//! The parent module keeps the claim, lease constants, and shared run state.

use super::{
    AgentDispatchStatus, AgentDispatcher, AttemptConfession, AttemptId, AttemptQueue,
    AttemptResultRef, BoundRun, Claimed, CodeRunReplayRecord, CompleteDreamerAttempt, DecisionHost,
    DetectorTier, DreamerParkCause, DreamerRunnerStore, DurableStepContext, EngineExecutorOutcome,
    EngineExecutorStatus, EngineRunError, EntityId, FORK_REFUSALS, FailureEscalationMode,
    FailureLadderOutcome, FailureScope, FailureScopePolicy, HandleAttemptFailure, HealerSlot,
    LEASE_OWNER, LlmError, OUTAGE_PARK_REASON, OutputContextEntry, ParkDreamerAttempt, PayerFault,
    RUN_MAX_TRIES, RUN_RETRY_BACKOFF_SECS, RetryableLlmError, SetAttemptResult, SpentKind, TypeRef,
    TypedFailureEvidence, TypedFailureVerdict, Vault, WAITING_PARK_REASON, agent_dispatch_actor,
    browser_workflow, open_trap, park_and_bind_wait_trap, park_for_payer, parks_on_outage,
    parse_confession, register_wait, restore_output, run_continuation, trap_for_durable_wait,
    trap_park_owner, unix_now,
};

/// Settles the run's attempt: complete, parked on its wait or on a provider
/// outage, or failed; a run whose model call failed for a reason that passes
/// is tried again.
pub(super) fn settle(
    vault: &Vault,
    decisions: &DecisionHost,
    claimed: &Claimed,
    ran: Result<BoundRun, EngineRunError>,
) -> oneiron::Result<()> {
    let status = &claimed.status;
    let attempt = &status.attempt;
    let now = unix_now();
    // OF-540: the run's execution context, bound while its lease holds; one
    // that cannot bind leaves the run to close unattributed.
    if let Err(error) = oneiron::skill_attribution::bind_agent_run_attribution(
        vault,
        attempt.id,
        LEASE_OWNER,
        decisions.ladder(),
    ) {
        tracing::warn!(%error, attempt = ?attempt.id, "an agent run's pack attribution did not bind");
    }
    let mut evidence = TypedFailureEvidence {
        evidence_ref: None,
        verdict: TypedFailureVerdict::Indeterminate,
        tier: None,
        stable_reason: String::new(),
    };
    let mut retry_at = now;
    let reason = match ran {
        // CUA E4: a bound try whose program met its TASK's goal settles on
        // its receipt, with no model call.
        Ok(BoundRun::Library(receipt)) => {
            return browser_workflow::complete(vault, decisions, claimed, receipt, now);
        }
        Ok(BoundRun::Agent(outcome)) => match outcome.status {
            EngineExecutorStatus::Complete => {
                return complete(vault, decisions, claimed, &outcome, now);
            }
            // The run waits on a durable signal; its lease waits with it.
            EngineExecutorStatus::Waiting(_) => return park_on_wait(vault, status, &outcome, now),
            EngineExecutorStatus::Yielded { .. } | EngineExecutorStatus::WindowFull { .. } => {
                "agent_run_unfinished"
            }
        },
        // A model call no provider answered, the run's own step's or a host
        // door's (FIX 3194): the same attempt parks, its lease and spend
        // scope held, and the run goes on once a provider recovers.
        Err(error) if parks_on_outage(&error) => {
            tracing::info!(%error, attempt = ?attempt.id, "an agent run parks on a provider outage");
            DreamerRunnerStore::new(vault).park_attempt(ParkDreamerAttempt {
                attempt_id: attempt.id,
                reason: OUTAGE_PARK_REASON.to_owned(),
                cause: DreamerParkCause::ProviderUnavailable,
                park_owner: LEASE_OWNER.to_owned(),
                now,
            })?;
            // FIX 2146: the outage counts once for the run's agent, here,
            // where the park returns before the failure ladder's door.
            vault.count_dispatch_failure(
                attempt.id,
                attempt.attempt_count,
                oneiron::failure_signals::DispatchFailure::ProviderOutage,
                now,
            );
            return Ok(());
        }
        // A run whose payer waits on the owners' payer-needed ask (OF-531,
        // FIX 805) parks as this try, its lease and spend scope held: it
        // neither fails nor spends a try, and goes on once they say yes.
        Err(EngineRunError::Payer(fault @ PayerFault::Needed { .. })) => {
            tracing::info!(%fault, attempt = ?attempt.id, "an agent run parks on its payer");
            park_for_payer(vault, attempt.id, LEASE_OWNER, &fault, now)?;
            return Ok(());
        }
        Err(error) => {
            tracing::warn!(%error, attempt = ?attempt.id, "an agent run failed");
            match error.llm().and_then(|error| passing(error, now)) {
                // A model call that failed for a reason that passes is a
                // tripwire's typed verdict, its evidence the attempt: the
                // run is tried again, fresh, once the reason has passed.
                Some((reason, reset)) => {
                    let tries = AttemptQueue::new(vault)
                        .retry_chain_depth(attempt.id)?
                        .saturating_add(1);
                    evidence.evidence_ref =
                        Some(EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex());
                    evidence.verdict = TypedFailureVerdict::Retryable;
                    evidence.tier = Some(DetectorTier::T1Tripwire);
                    retry_at = reset.unwrap_or_else(|| {
                        now.saturating_add(RUN_RETRY_BACKOFF_SECS.saturating_mul(u64::from(tries)))
                    });
                    reason
                }
                None => fork_refusal(&error).unwrap_or("agent_run_failed"),
            }
        }
    };
    evidence.stable_reason = reason.to_owned();
    // Any other failure has no detector verdict, and the ladder never infers
    // one from prose: the run ends for a person to look at. Its checkpoint is
    // the start of the step that failed (FIX 3694), a ref of its own, never
    // the run's or the attempt's id; its Q&A thread is the claim's: a
    // resident's home, its TASK, or its tree's root.
    let ended = DreamerRunnerStore::new(vault).fail_agent_dispatch_with_evidence(
        HandleAttemptFailure {
            attempt_id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            evidence,
            blocked_reports: vault
                .blocked_reports_of_run(EntityId::from_bytes(*attempt.id.as_bytes())?)?,
            pre_fail_checkpoint_ref: oneiron::engine_executor::continuation::pre_fail_checkpoint(
                vault,
                EntityId::from_bytes(*attempt.id.as_bytes())?,
            )?
            .id()?,
            qa_thread_ref: claimed.qa_thread_ref,
            retry_at,
            now,
        },
        FailureScopePolicy {
            scope: FailureScope {
                agent_ref: claimed.agent.to_hex(),
                skill_ref: None,
            },
            max_consecutive_transients: RUN_MAX_TRIES,
            escalation_mode: FailureEscalationMode::Human,
            healer_slot: HealerSlot::Reserved,
        },
    )?;
    // A retry shares the run's spend scope; only an end closes it.
    if !matches!(ended, FailureLadderOutcome::Retried { .. }) {
        AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
    }
    Ok(())
}

/// The code a continuation's fork refused with (FIX 3694), when that is why
/// the run stopped.
fn fork_refusal(error: &EngineRunError) -> Option<&'static str> {
    let EngineRunError::Binding(text) = error else {
        return None;
    };
    let code = text.split(':').next()?;
    FORK_REFUSALS.into_iter().find(|refusal| *refusal == code)
}

/// Whether a run's model call failed for a reason that passes, with its
/// stable reason and the reset its provider named, if one is still ahead:
/// a rate limit, a spent usage window, or no on-device offer until a
/// resting one is back. Spent credit waits for the owner, and any other
/// failure is not one a retry answers; an outage parks the run
/// ([`parks_on_outage`]).
fn passing(error: &LlmError, now: u64) -> Option<(&'static str, Option<u64>)> {
    let (reason, retry_after, resets_at) = match error {
        LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        }) => ("agent_run_rate_limited", retry_after, resets_at),
        LlmError::Retryable(RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
        }) => ("agent_run_window_spent", retry_after, resets_at),
        LlmError::Retryable(RetryableLlmError::KeptOnDevice {
            retry_after,
            resets_at,
            ..
        }) if retry_after.is_some() || !resets_at.is_empty() => {
            ("agent_run_kept_on_device", retry_after, resets_at)
        }
        _ => return None,
    };
    let reset = resets_at
        .iter()
        .copied()
        .find(|reset| *reset > now)
        .or_else(|| {
            retry_after
                .filter(|after| *after > 0)
                .map(|after| now.saturating_add(after))
        });
    Some((reason, reset))
}

/// Completes the attempt through the runner's one completion door, its
/// result the run's result TURN, and closes its spend. The TASK's "Done
/// means met?" is asked first, on this thread, so the completion carries
/// its answer, and the run's confession (OF-544) is sealed in the commit
/// that completes it.
fn complete(
    vault: &Vault,
    decisions: &DecisionHost,
    claimed: &Claimed,
    outcome: &EngineExecutorOutcome,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = &claimed.status.attempt;
    // A run that settled its TASK itself (tasks.refuse; tasks.update once a
    // run may report) is owed no Done from its result. A continued run's
    // calls its source made are history, never its own (FIX 3694).
    let settled_itself =
        settling_calls(&outcome.replay_record) > inherited_settling_calls(vault, attempt.id)?;
    if settled_itself {
        let body =
            serde_json::json!({ "run_id": outcome.replay_record.run_id.to_hex() }).to_string();
        let entry = OutputContextEntry::capture(vault, body.as_bytes(), now, String::new())?;
        AttemptQueue::new(vault).set_result(SetAttemptResult {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            result_ref: AttemptResultRef::new(entry.source.handle())?,
            now,
        })?;
    } else {
        // The run's durable result: the TASK's Done names it.
        let output = AgentDispatcher::new(vault).attach_resident_run_result(
            attempt,
            LEASE_OWNER,
            &outcome.replay_record,
            now,
        )?;
        // OF-540: the result derives from what the run derived, witnessed
        // while the lease holds; a run that cannot witness closes as bound.
        if let Err(error) =
            oneiron::skill_attribution::witness_agent_run_close(vault, attempt, LEASE_OWNER, output)
        {
            tracing::warn!(%error, attempt = ?attempt.id, "an agent run's close was not witnessed");
        }
    }
    let judged = oneiron::task_verb::runner_done_question(vault, attempt.id)?.and_then(
        |question| match decisions.task_decisions() {
            Ok(decisions) => Some(question.decide(&decisions)),
            Err(error) => {
                tracing::warn!(%error, "the task surface's questions are invalid; Done asks up");
                None
            }
        },
    );
    // A confession that cannot be read seals nothing; the run still
    // completes.
    let confession = run_confession(vault, claimed, outcome).unwrap_or_else(|error| {
        tracing::warn!(%error, attempt = ?attempt.id, "an agent run's confession does not read; it seals none");
        None
    });
    DreamerRunnerStore::new(vault).complete_with_confession(
        CompleteDreamerAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            now,
        },
        judged,
        confession.as_ref(),
    )?;
    AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
    Ok(())
}

/// How many of `record`'s bridge calls settle the TASK its run realizes.
fn settling_calls(record: &CodeRunReplayRecord) -> usize {
    record
        .bridge_calls
        .iter()
        .filter(|call| matches!(call.effect.as_str(), "tasks.refuse" | "tasks.update"))
        .count()
}

/// How many TASK-settling calls a continued run took over from its source
/// run (FIX 3694); 0 for any other run. A continuation is written and forked
/// only when no call after its cut may have committed an effect, so every
/// settling call its source made is in the prefix the child holds.
fn inherited_settling_calls(vault: &Vault, attempt: AttemptId) -> oneiron::Result<usize> {
    let Some(continuation) = run_continuation(vault, attempt)? else {
        return Ok(0);
    };
    Ok(vault
        .get_code_run_replay_record(&continuation.checkpoint.source_run)?
        .map_or(0, |source| settling_calls(&source)))
}

/// The confession the run's finished answer ends with (OF-544), against the
/// objectives it was asked: read whole from the finished step's
/// observation, the answer its result names, never a preview or a marker.
/// A run asked none, or whose answer gives none or is withheld, confesses
/// nothing. The seal measures the agent that ran, on the type its spawn was
/// placed under.
fn run_confession(
    vault: &Vault,
    claimed: &Claimed,
    outcome: &EngineExecutorOutcome,
) -> oneiron::Result<Option<AttemptConfession>> {
    if claimed.objectives.is_empty() {
        return Ok(None);
    }
    let status = &claimed.status;
    let Some(answer) = outcome
        .replay_record
        .outputs
        .iter()
        .rev()
        .find(|output| output.complete && output.path.ends_with(".observation.txt"))
    else {
        return Ok(None);
    };
    let bytes = restore_output(vault, answer.output_ref())?;
    let Some(objectives) = parse_confession(&bytes, &claimed.objectives) else {
        tracing::warn!(attempt = ?status.attempt.id, "an agent run asked for its confession gave none that parses");
        return Ok(None);
    };
    Ok(Some(AttemptConfession {
        attempt: status.attempt.id,
        subject: status.input.target.agent_definition_ref()?,
        type_ref: TypeRef::from(&status.input.type_ref),
        objectives,
    }))
}

/// Parks a Waiting run's attempt on a C9 trap its wait's reply wakes: the
/// trap opens and waits, then the attempt parks under the trap's owner and
/// the trap is bound to the wait in one commit, so a wake always finds the
/// park and no park is left unbound. The woken attempt is ready again, and
/// the next pass enters the run, which goes on from the reply.
fn park_on_wait(
    vault: &Vault,
    status: &AgentDispatchStatus,
    outcome: &EngineExecutorOutcome,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = &status.attempt;
    let parked = outcome
        .parked_wait()
        .ok_or(oneiron::Error::InvariantViolation(
            "a waiting run parked on no wait",
        ))?;
    let now_ms = now.saturating_mul(1000);
    let trap = open_trap(
        vault,
        &DurableStepContext {
            vault,
            attempt_id: attempt.id,
            run_id: attempt.run_id.clone(),
            envelope_actor: agent_dispatch_actor(&status.input)?,
            subject: parked.wait.wait_id,
            deadline: None,
            now_ms,
        },
        trap_for_durable_wait(&parked.wait, parked.step_hash),
        parked.step_hash,
        "code-run wait",
    )?;
    register_wait(vault, &trap, now_ms)?;
    // The park and its wake binding commit together: a stop between them
    // would leave a park no delivery wakes.
    park_and_bind_wait_trap(
        vault,
        ParkDreamerAttempt {
            attempt_id: attempt.id,
            reason: WAITING_PARK_REASON.to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: trap_park_owner(&trap.trap_claim_id),
            now,
        },
        &parked.key,
        &trap,
        now_ms,
    )?;
    Ok(())
}
