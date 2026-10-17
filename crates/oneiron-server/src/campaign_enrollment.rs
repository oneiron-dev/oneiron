//! Campaign enrollment from saved queries (ARCH-0059, decide-host 1193).
//!
//! A saved query a campaign program names as its audience is swept by
//! detection: in the sweep's own bounded wake, each candidate's evaluation is
//! the detection pass, and each entry it records is queued as a campaign
//! enrollment attempt at the program's entry step ([`wake`]). Any other query
//! keeps verdict-only evaluation.
//!
//! Queued attempts are pumped by their own worker ([`spawn`]) under the
//! campaign's home-node designation, not the sweep's: the campaign home node
//! claims an attempt, runs its membership leg (`campaign.member`), and settles
//! it. The outward leg is not run here.
use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimOutcome, CompleteAttempt, FailAttempt,
};
use oneiron::campaign::enrollment::{
    CampaignEnrollmentClaim, CampaignEnrollmentRunner, EnrollmentExecution, audience_program,
    campaign_enrollment_event, campaign_home_node_designation, decode_enrollment_attempt_payload,
    elect_campaign_home_node_designation, enroll_audience_wake, local_campaign_home_node_candidate,
};
use oneiron::saved_query::{
    QueryScope, SavedQueryEvaluator, SavedQueryRecord, WakeEvaluationReport, read_saved_query,
    sweep_owner_read,
};
use oneiron::{EntityId, Vault};

use crate::ladder_poll::block_on;
use crate::server::SyncServer;

/// How long the pump rests between passes.
const PUMP: Duration = Duration::from_secs(30);
/// Attempts one pass claims; a pass that reaches it runs again at once.
const PUMP_ATTEMPTS: usize = 32;
const LEASE_OWNER: &str = "oneiron-server-campaign-enrollment";
/// Recorded on an attempt whose reason does not fit the queue's bound.
const FAILED: &str = "the campaign enrollment attempt failed";

/// One bounded wake of `record` over `page` under the sweep's `evaluator`. A
/// query an active campaign's program names as its audience detects and
/// queues enrollments in the same wake; any other query writes verdicts only.
pub(crate) async fn wake(
    evaluator: &SavedQueryEvaluator<'_>,
    record: &SavedQueryRecord,
    page: &[EntityId],
    now: u64,
) -> oneiron::Result<WakeEvaluationReport> {
    let Some(program) = audience_program(evaluator.vault, record)? else {
        return evaluator
            .evaluate_wake_batch(record.query_ref, page, now)
            .await;
    };
    let report = enroll_audience_wake(
        evaluator,
        record.definition.owner_actor,
        &program,
        page,
        now,
    )
    .await?;
    if report.recorded > 0 {
        tracing::debug!(
            query = %record.query_ref.to_hex(),
            program = %program.program_ref.to_hex(),
            recorded = report.recorded,
            enqueued = report.enqueued,
            "a saved query's wake recorded campaign entries"
        );
    }
    Ok(report.wake)
}

/// Starts the pump. Each pass runs on a blocking thread, held by `admit` (a
/// managed vault frozen for reap skips it), every [`PUMP`], or at once after
/// a pass that claimed its full [`PUMP_ATTEMPTS`].
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        loop {
            let more = {
                let Some(server) = weak.upgrade() else {
                    break;
                };
                match admit() {
                    None => false,
                    Some(pass) => {
                        let ran = tokio::task::spawn_blocking(move || {
                            let _pass = pass;
                            pump(server.vault())
                        })
                        .await;
                        match ran {
                            Ok(Ok(more)) => more,
                            Ok(Err(error)) => {
                                tracing::warn!(kind = ?error.kind(), "the campaign enrollment pump failed; it runs again next pass");
                                false
                            }
                            Err(error) => {
                                tracing::warn!(%error, "the campaign enrollment pump stopped");
                                false
                            }
                        }
                    }
                }
            };
            if !more {
                tokio::time::sleep(PUMP).await;
            }
        }
    })
}

/// One pass: on the campaign home node, claims up to [`PUMP_ATTEMPTS`]
/// attempts, runs each one's membership leg, and settles it. Returns whether
/// the bound stopped the pass with attempts possibly left.
fn pump(vault: &Vault) -> oneiron::Result<bool> {
    let now = vault.now_recorded_at();
    let Some(node) = campaign_home_node(vault, now)? else {
        return Ok(false);
    };
    let runner = CampaignEnrollmentRunner::new(vault);
    for _ in 0..PUMP_ATTEMPTS {
        let now = vault.now_recorded_at();
        let CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(attempt)) =
            runner.claim_if_home(node, LEASE_OWNER.to_owned(), now)?
        else {
            return Ok(false);
        };
        let executed = block_on(execute(vault, &runner, node, &attempt, now));
        if !settle(vault, &attempt, executed) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The local node's id while it holds the campaign home-node designation.
/// With none held, the local node elects itself as the always-on box, as
/// `decision_graph::at_home` does for the Dreamer's designation.
fn campaign_home_node(vault: &Vault, now: u64) -> oneiron::Result<Option<u64>> {
    let local = local_campaign_home_node_candidate(vault, true, true, false)?;
    let home = match campaign_home_node_designation(vault)? {
        Some(home) => Some(home),
        None => elect_campaign_home_node_designation(vault, &[local], now)?,
    };
    Ok(home
        .is_some_and(|home| home.node_id == local.node_id)
        .then_some(local.node_id))
}

/// Runs the membership leg of one claimed attempt, re-deriving its evidence
/// under the read the sweep evaluates the query under: its owner's, resolved
/// now as the owner's class. No judge is bound: evidence that still hashes to the event's is answered by the memo
/// detection wrote, and evidence that moved makes the attempt stale whatever
/// a judge would say.
async fn execute(
    vault: &Vault,
    runner: &CampaignEnrollmentRunner<'_>,
    node: u64,
    attempt: &AttemptRecord,
    now: u64,
) -> oneiron::Result<EnrollmentExecution> {
    let payload = decode_enrollment_attempt_payload(&attempt.payload)?;
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(oneiron::Error::EntityNotFound)?;
    let record = read_saved_query(vault, event.owner_actor, event.query_ref)?
        .ok_or(oneiron::Error::EntityNotFound)?;
    let read = sweep_owner_read(
        vault,
        record.definition.owner_actor,
        record.definition.owner_actor_class,
    )?
    .ok_or_else(|| {
        oneiron::Error::InvalidConfig("the saved query's owner has no usable read now".into())
    })?;
    // The owner's read is the authority; the scope axes stay as declared.
    let reach = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault,
        owner_grants: &reach,
        owner_read: &read,
        judge: None,
    };
    runner.execute_claimed(node, attempt, &evaluator, now).await
}

/// Completes or fails one executed attempt. An attempt whose membership leg
/// concluded (applied, already applied, or stale) completes; one awaiting the
/// owner's review, or one that errored, fails with its reason. When the
/// designation moved between claim and write the row is left leased for the
/// new home node once its lease lapses, and the pass stops: returns `false`.
fn settle(
    vault: &Vault,
    attempt: &AttemptRecord,
    executed: oneiron::Result<EnrollmentExecution>,
) -> bool {
    let result = match executed {
        Ok(
            EnrollmentExecution::Applied { .. }
            | EnrollmentExecution::AlreadyApplied { .. }
            | EnrollmentExecution::SkippedStale
            | EnrollmentExecution::RejectedStaleEpoch { .. },
        ) => Ok(()),
        Ok(EnrollmentExecution::ReviewRequired { cause }) => Err(format!(
            "a {} enrollment awaits the owner's review",
            cause.as_str()
        )),
        Ok(EnrollmentExecution::NotHomeNode(_) | EnrollmentExecution::NoHomeNode) => {
            return false;
        }
        // The reason is recorded on the attempt, not logged: it can quote
        // the vault.
        Err(error) => Err(error.to_string()),
    };
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let fail = |reason: String| {
        queue.fail(FailAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            reason,
            now,
        })
    };
    let settled = match result {
        Ok(()) => queue
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })
            .map(drop),
        Err(reason) => fail(reason).or_else(|_| fail(FAILED.to_owned())).map(drop),
    };
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "a campaign enrollment attempt was not settled");
    }
    true
}
