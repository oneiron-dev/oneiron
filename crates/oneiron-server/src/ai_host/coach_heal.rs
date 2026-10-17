//! The host Coach (ARCH-0066 #coach, OF-418). It leases the `coach.heal`
//! queue, where each failure-ladder case the escalation hands to the Coach
//! and each Issues wake a blocked report raises wait, and runs the engine's
//! propose-only door for each on the host's decision ladder. What lands is a
//! proposed heal in the owner's run tray; nothing is repaired here. The
//! code-fix run a filed heal wakes (OF-380) and the answer to an agent-health
//! card's ask (OF-568) ride the same queue. Each code-fix run also replays
//! the publisher's pinned candidates the worker started with.
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::agent_health::COACH_AGENT_HEALTH_ASK_FACET;
use oneiron::dreamer_runner::maintenance::coach::{COACH_CODE_FIX_FACET, COACH_ISSUES_FACET};
use oneiron::dreamer_runner::maintenance::coach_heal::HealDecisions;
use oneiron::dreamer_runner::maintenance::code_fix::PublisherCandidate;
use oneiron::dreamer_runner::{
    AbortDreamerBudgetReservation, AdmitDreamerAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore, FailDreamerAttempt,
};
use oneiron::llm::decision::DecisionRung;

use crate::server::SyncServer;

/// The host's wording of the route question; the state carries the case or
/// the report.
const WORDING: &str = "Which fix does this agent need so its work can go on? \
    Choose skill_edit when the skill it ran is wrong, prompt_inject when it needs \
    a nudge and a fresh start from before it failed, environment when a tool, a \
    grant or a connector it needs is missing or broken, and person when none of \
    these fits or a person must look.";
const TICK: Duration = Duration::from_secs(5);
pub(super) const LEASE_OWNER: &str = "coach.host";
/// The Coach's own admission counter. Its questions spend on the decision
/// ladder's meters, so each lease reserves one unit and gives it back.
const BUDGET_ID: &str = "coach.heal";
const BUDGET_UNITS: u64 = 1 << 20;
/// Attempts one round runs.
const ROUND: usize = 8;
/// One question's budget.
const DECIDE_BUDGET: Duration = Duration::from_secs(20);

/// Starts the worker. Each round runs on a blocking thread: the ladder's
/// model rungs block on the server's runtime. `publisher` is
/// `FailureSignalsConfig::publisher_candidates`.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    publisher: Arc<[PublisherCandidate]>,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let publisher = Arc::clone(&publisher);
            match tokio::task::spawn_blocking(move || round(&server, &publisher)).await {
                // By kind only: an engine error can quote the vault.
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "the Coach's heal queue waits for the next round");
                }
                Err(error) => tracing::warn!(%error, "the Coach's heal round stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}

fn round(server: &SyncServer, publisher: &[PublisherCandidate]) -> oneiron::Result<()> {
    let vault = server.vault();
    let store = DreamerRunnerStore::new(vault);
    for _ in 0..ROUND {
        let now = vault.now_recorded_at();
        let admitted = match store.admit_next_coach_heal(AdmitDreamerAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now,
            budget_id: BUDGET_ID.to_owned(),
            budget_total_units: BUDGET_UNITS,
            reserve_units: 1,
            started_milestone: None,
        })? {
            DreamerAdmissionOutcome::Admitted(admitted) => admitted,
            _ => return Ok(()),
        };
        let ran = run_one(server, &admitted, publisher, now);
        settle(vault, &store, &admitted, ran, BUDGET_ID)?;
    }
    Ok(())
}

fn run_one(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    publisher: &[PublisherCandidate],
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let principal = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| oneiron::Error::InvalidConfig(format!("no owner principal: {error}")))?;
    if admitted.status.payload.attempt_type == COACH_CODE_FIX_FACET {
        return super::code_fix::run(server, admitted, principal, publisher, now);
    }
    if admitted.status.payload.attempt_type == COACH_AGENT_HEALTH_ASK_FACET {
        return super::coach_health::run(server, admitted, now);
    }
    let host = server.decision_host();
    let decisions = HealDecisions {
        ladder: host.ladder().ladder(),
        principal,
        dial: host.dial(DecisionRung::Big),
        bands: host.bands(),
        wording: WORDING.to_owned(),
        budget: DECIDE_BUDGET,
    };
    if admitted.status.payload.attempt_type == COACH_ISSUES_FACET {
        let run = vault.run_coach_issues(admitted, &decisions, now)?;
        tracing::debug!(
            proposed = run.proposed,
            deferred = run.deferred,
            "the Coach read the blocked reports"
        );
    } else {
        vault.run_coach_heal(admitted, &decisions, now)?;
    }
    Ok(())
}

/// Completes or fails the lease, then gives its unit back to `budget_id`.
pub(super) fn settle(
    vault: &oneiron::Vault,
    store: &DreamerRunnerStore<'_>,
    admitted: &DreamerAdmittedAttempt,
    ran: oneiron::Result<()>,
    budget_id: &str,
) -> oneiron::Result<()> {
    let attempt = &admitted.status.attempt;
    let now = vault.now_recorded_at();
    match ran {
        Ok(()) => {
            store.complete(CompleteDreamerAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })?;
        }
        Err(error) => {
            let facet = &admitted.status.payload.attempt_type;
            tracing::warn!(kind = ?error.kind(), %facet, "a Coach attempt failed");
            store.fail(FailDreamerAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: format!("{facet} failed: {:?}", error.kind()),
                now,
            })?;
        }
    }
    store.abort_budget_reservation(AbortDreamerBudgetReservation {
        budget_id: budget_id.to_owned(),
        child_attempt: attempt.id,
        now,
    })?;
    Ok(())
}
