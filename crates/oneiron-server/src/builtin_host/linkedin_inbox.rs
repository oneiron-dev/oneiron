//! The served LinkedIn inbox sync (FIX 12328): every
//! [`LINKEDIN_INBOX_SYNC_EVERY`] the host queues one inbox poll for each
//! LinkedIn seat an installed LinkedIn connector serves, then claims each due
//! `linkedin_inbox_sync` row and runs it as the seat's agent over the
//! connector's tools. Each new message's words go to the provider-event
//! archive, where the connector reply responder reads them. A row whose seat
//! is served no longer completes unpolled; a poll that fails runs again one
//! interval later.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    FailAttempt, RequeueAttempt,
};
use oneiron::linkedin_connector::{LINKEDIN_INBOX_SYNC_ATTEMPT_KIND, LinkedInInboxSyncConfig};

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often each served LinkedIn seat's inbox is polled.
const LINKEDIN_INBOX_SYNC_EVERY: Duration = Duration::from_secs(300);
/// Whom the driver claims inbox sync rows as.
const LEASE_OWNER: &str = "oneiron-serve.linkedin-inbox-sync";
/// Polls one pass runs before it waits for the next interval.
const PASS_LIMIT: usize = 16;

/// Runs the inbox sync, one pass per interval, the first at once. Each pass
/// is admitted through `admit`, the way a housekeeping pass is, so a vault
/// frozen for reap reads nothing. Its first pass returns to the queue every
/// row a stopped host claimed and never settled: this driver is the kind's
/// only one.
pub(super) async fn sync_linkedin_inboxes(server: Arc<SyncServer>, admit: HousekeepingAdmission) {
    let mut interval = tokio::time::interval(LINKEDIN_INBOX_SYNC_EVERY);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut recovered = false;
    loop {
        interval.tick().await;
        let Some(admission) = admit() else {
            continue;
        };
        let recover = !std::mem::replace(&mut recovered, true);
        let vault = Arc::clone(server.vault());
        let pass = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            if recover {
                AttemptQueue::new(&vault).cleanup_kind_leases(
                    LINKEDIN_INBOX_SYNC_ATTEMPT_KIND,
                    CleanupAttemptLeases {
                        now: vault.now_recorded_at(),
                        lease_timeout_secs: 1,
                    },
                )?;
            }
            sync_pass(&vault)
        })
        .await;
        match pass {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "LinkedIn inbox sync pass failed"),
            Err(error) => tracing::warn!(%error, "LinkedIn inbox sync pass panicked"),
        }
    }
}

/// Queues a poll for every served seat without one pending, then claims,
/// runs and settles up to [`PASS_LIMIT`] due rows.
fn sync_pass(vault: &Vault) -> oneiron::Result<()> {
    let queued = vault.enqueue_served_linkedin_inbox_syncs(vault.now_recorded_at())?;
    if queued > 0 {
        tracing::debug!(queued, "LinkedIn inbox polls queued");
    }
    let queue = AttemptQueue::new(vault);
    for _ in 0..PASS_LIMIT {
        let claimed = queue.claim_kind(
            LINKEDIN_INBOX_SYNC_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?;
        let ClaimOutcome::Claimed(attempt) = claimed else {
            break;
        };
        settle(&queue, vault, &attempt)?;
    }
    Ok(())
}

/// Runs one claimed row and settles it: done, run again one interval
/// later, or, for a payload that names no seat, failed for good.
fn settle(queue: &AttemptQueue<'_>, vault: &Vault, attempt: &AttemptRecord) -> oneiron::Result<()> {
    let config = match serde_json::from_slice::<LinkedInInboxSyncConfig>(&attempt.payload) {
        Ok(config) => config,
        Err(error) => {
            queue.fail(FailAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: format!("LinkedIn inbox sync payload did not decode: {error}"),
                now: vault.now_recorded_at(),
            })?;
            return Ok(());
        }
    };
    match vault.run_served_linkedin_inbox_sync(&config, vault.now_recorded_at()) {
        Ok(report) => {
            match report {
                Some(report) if report.new_messages > 0 => tracing::info!(
                    admitted = report.new_messages,
                    pending_threads = report.pending_threads,
                    "LinkedIn messages admitted"
                ),
                Some(_) => {}
                None => tracing::info!(
                    "a LinkedIn inbox sync row outlived its seat; completed unpolled"
                ),
            }
            queue.complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now: vault.now_recorded_at(),
            })?;
        }
        Err(error) => {
            let reason = error.to_string();
            tracing::warn!(
                error = %reason,
                "LinkedIn inbox sync failed; it runs again one interval later"
            );
            queue.requeue(RequeueAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                reason,
                due_at: vault
                    .now_recorded_at()
                    .saturating_add(LINKEDIN_INBOX_SYNC_EVERY.as_secs()),
            })?;
        }
    }
    Ok(())
}
