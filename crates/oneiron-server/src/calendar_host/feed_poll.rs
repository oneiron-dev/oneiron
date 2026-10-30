//! The host's ICS feed poll worker (FIX 7846): it claims each due
//! `calendar.ics.poll` row, polls the feed the row names as the vault's local
//! owner through the custody door, records the completion on the installed
//! feed, and settles the row. The poll itself queues the chain's next row
//! inside the feed's cadence window, so an installed feed keeps polling with
//! no owner call. A row whose feed is no longer installed as it names
//! completes unpolled; a poll that fails runs again one cadence step later.
//! A vault with no standing local owner (a managed one) leaves its rows
//! queued for the owner's own poll door.
//!
//! The same pass runs each due `calendar.ics.property_continuation` row
//! (FIX 11997): the next pass of an event's property admissions, read again
//! from the archived feed version, under the owner's CAL-09 dial as a poll
//! runs. One that fails runs again [`CONTINUATION_RETRY`] later.

use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    FailAttempt, RequeueAttempt,
};
use oneiron::calendar::ingest::feed_door::{self, CalendarIcsFeedRequest};
use oneiron::calendar::ingest::{
    CustodyDoorIcsFeedFetcher, ICS_POLL_ATTEMPT_KIND, ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND,
    IcsFeedPollConfig, IcsFeedPollPayload, IcsPropertyContinuationPayload,
    run_ics_property_continuation,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::{EdgeActorClass, Vault};

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often the worker looks for a due poll.
const POLL_TICK: Duration = Duration::from_secs(60);
/// Whom the worker claims poll rows as.
const LEASE_OWNER: &str = "oneiron-serve.calendar-ics-poll";
/// The custody effector a feed's secret URL is read for, as the owner's own
/// poll door names it.
const EFFECTOR: &str = "calendar.ics.poll";
/// Polls one pass runs before it waits for the next tick, and property
/// continuations likewise.
const PASS_LIMIT: usize = 16;
/// How long a property continuation that failed waits before it runs again.
const CONTINUATION_RETRY: u64 = 300;

/// Starts the worker. Each pass is admitted through `admit`, the way a
/// housekeeping pass is, so a vault frozen for reap polls nothing. Its first
/// pass returns to the queue every row a stopped host claimed and never
/// settled: this worker is the kind's only one.
pub(crate) fn spawn_ics_feed_polls(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(POLL_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut recovered = false;
        loop {
            interval.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let recover = !std::mem::replace(&mut recovered, true);
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                if recover {
                    recover_polls(server.vault())?;
                }
                run_due_polls(server.vault())
            })
            .await;
            let error = match pass {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => format!("{error:#}"),
                Err(error) => error.to_string(),
            };
            tracing::warn!(error = %error, "calendar feed poll pass failed");
        }
    })
}

fn recover_polls(vault: &Vault) -> anyhow::Result<()> {
    for kind in [
        ICS_POLL_ATTEMPT_KIND,
        ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND,
    ] {
        AttemptQueue::new(vault).cleanup_kind_leases(
            kind,
            CleanupAttemptLeases {
                now: vault.now_recorded_at(),
                lease_timeout_secs: 1,
            },
        )?;
    }
    Ok(())
}

/// Claims, polls and settles up to [`PASS_LIMIT`] due rows, then runs up to
/// [`PASS_LIMIT`] due property continuations.
fn run_due_polls(vault: &Arc<Vault>) -> anyhow::Result<()> {
    let owner = match crate::owner::local_owner(vault) {
        Ok(owner) => owner,
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "no local owner; feed polls stay queued");
            return Ok(());
        }
    };
    let queue = AttemptQueue::new(vault);
    for _ in 0..PASS_LIMIT {
        let claimed = queue.claim_kind(
            ICS_POLL_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?;
        let ClaimOutcome::Claimed(attempt) = claimed else {
            break;
        };
        settle(&queue, vault, &owner, &attempt)?;
    }
    for _ in 0..PASS_LIMIT {
        let claimed = queue.claim_kind(
            ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?;
        let ClaimOutcome::Claimed(attempt) = claimed else {
            break;
        };
        settle_continuation(&queue, vault, &owner, &attempt)?;
    }
    Ok(())
}

/// Runs one claimed property continuation and settles it: done, run again
/// [`CONTINUATION_RETRY`] later, or, for a payload that does not decode,
/// failed for good.
fn settle_continuation(
    queue: &AttemptQueue<'_>,
    vault: &Arc<Vault>,
    owner: &AuthenticatedOwner,
    attempt: &AttemptRecord,
) -> anyhow::Result<()> {
    let payload = match serde_json::from_slice::<IcsPropertyContinuationPayload>(&attempt.payload) {
        Ok(payload) => payload,
        Err(error) => {
            queue.fail(FailAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: format!("calendar property continuation payload did not decode: {error}"),
                now: vault.now_recorded_at(),
            })?;
            return Ok(());
        }
    };
    let ran = owner
        .actor_for_read(vault)
        .map_err(anyhow::Error::from)
        .and_then(|actor| {
            let memory = vault.memory(actor, EdgeActorClass::Human);
            let safeguard_enabled = feed_door::inbound_safeguard_enabled(&memory)?;
            run_ics_property_continuation(
                vault,
                super::calendar_body_screener(),
                safeguard_enabled,
                &payload,
            )
            .map_err(anyhow::Error::from)
        });
    match ran {
        Ok(()) => {
            queue.complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now: vault.now_recorded_at(),
            })?;
        }
        Err(error) => {
            let reason = format!("{error:#}");
            tracing::warn!(
                system = %payload.system,
                error = %reason,
                "calendar property continuation failed; it runs again later"
            );
            queue.requeue(RequeueAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason,
                due_at: vault.now_recorded_at().saturating_add(CONTINUATION_RETRY),
            })?;
        }
    }
    Ok(())
}

/// Polls one claimed row and settles it: done, run again one cadence step
/// later, or, for a payload that names no feed, failed for good.
fn settle(
    queue: &AttemptQueue<'_>,
    vault: &Arc<Vault>,
    owner: &AuthenticatedOwner,
    attempt: &AttemptRecord,
) -> anyhow::Result<()> {
    let config = match serde_json::from_slice::<IcsFeedPollPayload>(&attempt.payload) {
        Ok(payload) => payload.config,
        Err(error) => {
            queue.fail(FailAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: format!("calendar feed poll payload did not decode: {error}"),
                now: vault.now_recorded_at(),
            })?;
            return Ok(());
        }
    };
    match poll_installed_feed(vault, owner, &config) {
        Ok(()) => {
            queue.complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now: vault.now_recorded_at(),
            })?;
        }
        Err(error) => {
            let reason = format!("{error:#}");
            tracing::warn!(
                system = %config.system,
                error = %reason,
                "calendar feed poll failed; it runs again one cadence step later"
            );
            let now = vault.now_recorded_at();
            queue.requeue(RequeueAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason,
                due_at: config.jittered_next_poll_not_before(now, now),
            })?;
        }
    }
    Ok(())
}

/// One poll of `config` as `owner`, while the feed is still installed as
/// `config` names it; a feed installed no longer is not polled.
fn poll_installed_feed(
    vault: &Arc<Vault>,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
) -> anyhow::Result<()> {
    let memory = vault.memory(owner.actor_for_read(vault)?, EdgeActorClass::Human);
    let installed = feed_door::get(
        &memory,
        owner,
        &CalendarIcsFeedRequest {
            system: config.system.clone(),
        },
    )?;
    if installed.is_none_or(|row| row.config != *config) {
        tracing::info!(
            system = %config.system,
            "calendar feed poll row outlived its feed; completed unpolled"
        );
        return Ok(());
    }
    let transport = super::HttpIcsFeed::new(Arc::clone(vault), owner.clone(), config.clone())
        .map_err(anyhow::Error::msg)?;
    let fetcher = CustodyDoorIcsFeedFetcher::new(vault, EFFECTOR, transport);
    let completion = feed_door::run_installed_poll(
        &memory,
        owner,
        &fetcher,
        super::calendar_body_screener(),
        config,
        oneiron::EntityId::now().to_hex(),
    )?;
    tracing::debug!(
        system = %config.system,
        poll = %completion.poll_ref,
        "calendar feed polled"
    );
    Ok(())
}
