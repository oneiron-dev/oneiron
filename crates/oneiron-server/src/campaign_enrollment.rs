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
//! claims an attempt, runs its membership leg (`campaign.member`), then, when
//! the program step owes a send, its outward leg through the chokepoint
//! (FIX 2636), and settles it.
use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimOutcome, CompleteAttempt, FailAttempt, RetryAttempt,
};
use oneiron::campaign::enrollment::{
    CampaignEnrollmentClaim, CampaignEnrollmentRunner, EnrollmentExecution, EnrollmentLegDrive,
    audience_programs, campaign_enrollment_event, campaign_home_node_designation,
    decode_enrollment_attempt_payload, drive_enrollment_outbound_leg,
    elect_campaign_home_node_designation, enroll_audience_wake, local_campaign_home_node_candidate,
};
use oneiron::campaign::sender::CampaignChannelSender;
use oneiron::channel_identity_provider::stalwart::StalwartClient;
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
/// The built-in native mail pack connection whose checked credential opens
/// the host's Stalwart client for a campaign send (FIX 11642).
const NATIVE_MAIL_PACK: &str = "oneiron.native_mail";
const NATIVE_MAIL_CONNECTION: &str = "mail-server";

/// One bounded wake of `record` over `page` under the sweep's `evaluator`. A
/// query that active campaigns' programs name as their audience detects and
/// queues enrollments in the same wake, one per program a candidate enters;
/// any other query writes verdicts only.
pub(crate) async fn wake(
    evaluator: &SavedQueryEvaluator<'_>,
    record: &SavedQueryRecord,
    page: &[EntityId],
    now: u64,
) -> oneiron::Result<WakeEvaluationReport> {
    let programs = audience_programs(evaluator.vault, record)?;
    if programs.is_empty() {
        return evaluator
            .evaluate_wake_batch(record.query_ref, page, now)
            .await;
    }
    let report = enroll_audience_wake(
        evaluator,
        record.definition.owner_actor,
        record.query_ref,
        &programs,
        page,
        now,
    )
    .await?;
    if report.recorded > 0 {
        tracing::debug!(
            query = %record.query_ref.to_hex(),
            programs = programs.len(),
            recorded = report.recorded,
            enqueued = report.enqueued,
            "a saved query's wake recorded campaign entries"
        );
    }
    Ok(report.wake)
}

/// Starts the pump. Each pass runs on a blocking thread, held by `admit` (a
/// managed vault frozen for reap skips it), at once after a pass that
/// claimed its full [`PUMP_ATTEMPTS`], on the vault's post-commit attempt
/// signal (an enqueue), or every [`PUMP`] as a backstop.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    let signals = AttemptQueue::new(server.vault()).subscribe();
    tokio::spawn(async move {
        let mut signals = signals;
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
                            pump(&server)
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
                tokio::select! {
                    result = signals.recv() => {
                        if matches!(
                            result,
                            Err(tokio::sync::broadcast::error::RecvError::Closed)
                        ) {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(PUMP) => {}
                }
            }
        }
    })
}

/// One pass: on the campaign home node, claims up to [`PUMP_ATTEMPTS`]
/// attempts, runs each one's membership leg and, when it applied with a send
/// owed, its outward leg, and settles it. Returns whether the bound stopped
/// the pass with attempts possibly left.
fn pump(server: &SyncServer) -> oneiron::Result<bool> {
    let vault = server.vault();
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
        let settlement = match executed {
            // The membership leg applied, or a crash left it applied, and the
            // step owes a send: the outward leg runs before the attempt
            // completes. Its call is the consequence's own, so a re-drive
            // takes the stored intent and replays its frozen bytes.
            Ok(
                EnrollmentExecution::Applied {
                    outbound_intent: Some(_),
                }
                | EnrollmentExecution::AlreadyApplied {
                    outbound_intent: Some(_),
                },
            ) => outward(server, node, &attempt),
            executed => membership_settlement(executed),
        };
        let Some(settlement) = settlement else {
            return Ok(false);
        };
        settle(vault, &attempt, settlement);
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

/// Runs the outward leg of `attempt` on the campaign channel sender
/// (FIX 2636, FIX 11513, FIX 11642). `None` when the designation moved
/// before the send: the row stays leased for the new home node. A Gate hold
/// waits on the owner's press and fails the attempt with its digest, as a
/// review hold does.
fn outward(server: &SyncServer, node: u64, attempt: &AttemptRecord) -> Option<Settlement> {
    let vault = server.vault();
    let sender = CampaignChannelSender::new(
        Arc::clone(server.vault()),
        server.config.line.monthly_push_allowance(),
    );
    // FIX 11642: the stalwart branch sends through the host-owned client
    // built here per send; without one it fails closed, and every other
    // channel flows as before.
    let mut sender = match campaign_stalwart_client(server) {
        Some(client) => sender.with_stalwart(client),
        None => sender,
    };
    let now_ms = crate::runtime::wall_clock_ms();
    let drive = drive_enrollment_outbound_leg(vault, node, attempt, &mut sender, now_ms);
    Some(match drive {
        Ok(EnrollmentLegDrive::Dispatched | EnrollmentLegDrive::NothingOwed) => {
            Settlement::Complete
        }
        Ok(EnrollmentLegDrive::AwaitingApproval { approval_digest }) => Settlement::Fail(format!(
            "a campaign send awaits the owner's approval press on {approval_digest}"
        )),
        // FIX 12176: a paced send waits out its window, then resends.
        Ok(EnrollmentLegDrive::Paced { retry_at }) => Settlement::RetryAt(retry_at),
        Ok(EnrollmentLegDrive::NotHomeNode(_) | EnrollmentLegDrive::NoHomeNode) => return None,
        // The reason is recorded on the attempt, not logged: it can quote
        // the vault.
        Err(error) => Settlement::Fail(error.to_string()),
    })
}

/// The host-owned Stalwart client for one campaign send (FIX 11642), or
/// none when native mail is unconfigured, unchecked, or unreachable. Any
/// failure fails closed: the sender's stalwart branch answers
/// InvalidRequest without a client, and gmail/slack/line sends flow
/// untouched. Built per send inside the credential door, as the pack's own
/// connection check builds it (`builtin_host::checks`): the stored value is
/// the whole `Authorization` header or a bare bearer token, and the token
/// bytes never leave the closure. The pump runs on a blocking thread, so
/// the session discovery and domain read are safe here.
fn campaign_stalwart_client(server: &SyncServer) -> Option<StalwartClient> {
    let placement = server.config.native_mail.as_ref()?.stalwart().ok()?;
    let secret = server
        .vault()
        .verified_pack_connection_secret(NATIVE_MAIL_PACK, NATIVE_MAIL_CONNECTION)
        .ok()?;
    let mut connected = None;
    server
        .vault()
        .inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
            let value = std::str::from_utf8(value)
                .map_err(|_| {
                    oneiron::Error::InvalidConfig("the stored credential is not text".to_owned())
                })?
                .trim();
            let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
                value.to_owned()
            } else {
                format!("Bearer {value}")
            };
            let header = reqwest::header::HeaderValue::from_str(&header).map_err(|_| {
                oneiron::Error::InvalidConfig(
                    "the stored credential is not a header value".to_owned(),
                )
            })?;
            connected = StalwartClient::connect(placement.clone(), header).ok();
            Ok(())
        })
        .ok()?;
    connected
}

/// How one executed attempt settles.
enum Settlement {
    Complete,
    /// The member's saved pause falls due at this instant (FIX 9662).
    RetryAt(u64),
    Fail(String),
}

/// How an attempt whose membership leg owes no send settles. An attempt
/// whose membership leg concluded (applied, already applied, or stale)
/// completes; one deferred to a member's saved wake runs again at that
/// instant; one awaiting the owner's review, or one that errored, fails with
/// its reason. `None` when the designation moved between claim and write:
/// the row is left leased for the new home node once its lease lapses, and
/// the pass stops.
fn membership_settlement(executed: oneiron::Result<EnrollmentExecution>) -> Option<Settlement> {
    Some(match executed {
        Ok(
            EnrollmentExecution::Applied { .. }
            | EnrollmentExecution::AlreadyApplied { .. }
            | EnrollmentExecution::SkippedStale
            | EnrollmentExecution::RejectedStaleEpoch { .. },
        ) => Settlement::Complete,
        Ok(EnrollmentExecution::DeferredUntil { until }) => Settlement::RetryAt(until),
        Ok(EnrollmentExecution::ReviewRequired { cause }) => Settlement::Fail(format!(
            "a {} enrollment awaits the owner's review",
            cause.as_str()
        )),
        Ok(EnrollmentExecution::NotHomeNode(_) | EnrollmentExecution::NoHomeNode) => {
            return None;
        }
        // The reason is recorded on the attempt, not logged: it can quote
        // the vault.
        Err(error) => Settlement::Fail(error.to_string()),
    })
}

/// Completes, retries or fails one executed attempt as `settlement` says.
fn settle(vault: &Vault, attempt: &AttemptRecord, settlement: Settlement) {
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
    let settled = match settlement {
        Settlement::Complete => queue
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })
            .map(drop),
        Settlement::RetryAt(until) => queue
            .retry(RetryAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                backoff_until: until,
                last_error: None,
                now,
            })
            .map(drop),
        Settlement::Fail(reason) => fail(reason).or_else(|_| fail(FAILED.to_owned())).map(drop),
    };
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "a campaign enrollment attempt was not settled");
    }
}
