//! The connector-call settler (ONE-2510): the served loop that re-enters
//! every held or pending-delivery connector call and answers its wait.
//!
//! A held call parks its code-mode run on a durable wait keyed by its call
//! ref. Neither the gate nor the consent doors send the call or answer the
//! wait when the owner decides; this loop does, at startup and every
//! [`CONNECTOR_SETTLE_INTERVAL`]. Each pass lists the engine's pending calls
//! and, on a blocking worker, resumes each one that is due: the send happens
//! there, never inside a write transaction. A terminal outcome's reply is
//! delivered to the wait its call ref names (the run parked on it, or a
//! caller that reads the settled wait later), and only then acknowledged, so
//! the engine keeps the row until that reply has committed. A crash in
//! between leaves a settled row, whose next pass delivers its receipt with no
//! reply body (`result_not_retained`); nothing is resent to rebuild one. A
//! resumed call whose connector asked for input delivers its questions and
//! their handle the same way, so the run or caller waiting on it answers
//! them through `connector.answer` (FIX 3839). Its row keeps the round for
//! its caller's polls and is never resumed again (FIX 3837). The
//! acknowledgement keeps who called it, so `connector.call_status` serves the
//! settled wait to that caller and the owner alone (FIX 2279). The reply is
//! delivered beside the rows the call's passes picked (FIX 5455), which the
//! resumed run and `connector.call_status` list.
//!
//! A call still held, or a send the ledger retries, stays pending. Each such
//! resume runs the call's gate again, so a call that stays held is retried
//! after a doubling delay, from [`CONNECTOR_SETTLE_INTERVAL`] up to
//! [`CONNECTOR_SETTLE_MAX_BACKOFF`], kept in memory and reset by a restart.
//! There is no notification of a consent answer to wake the loop sooner.
//! A call a full count-bound budget window paces skips its backoff: it waits
//! while the window is shut and goes in the first pass after it opens, and
//! the pass admits again the connector event wakes such a window paced
//! (FIX 8686).
//!
//! Each pass first takes up again the live exchanges a restart left with a
//! resume state on their calls' rows (FIX 9157), before it lists the pending
//! calls, which leave out every call waiting on its connector's questions.
//! Each pass then drives the approved, unsettled browser waits, which have
//! no connector row and no other driver (FIX 11498).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::code_run::WaitDeliveries;
use oneiron::outbound_intent_ledger::IntentLedgerError;
use oneiron::task_verb::sdk::ConnectorCallReply;

use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::{HousekeepingAdmission, SyncServer, admit_every_pass};

/// How often the settler drains the pending connector calls, after the pass
/// it runs at startup.
pub(crate) const CONNECTOR_SETTLE_INTERVAL: Duration = Duration::from_secs(30);

/// How long after its approving answer a held browser act that was never
/// admitted is driven by the settler (FIX 11498): one pass interval, so the
/// answer's own drive is never raced.
const BROWSER_WAIT_DRIVE_AFTER: Duration = CONNECTOR_SETTLE_INTERVAL;

/// The longest a call that stays held or undelivered waits between two of
/// its resumes.
pub(crate) const CONNECTOR_SETTLE_MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// When each call that stayed pending is next due, and its current delay;
/// and how often this run tried to take each call's live exchange up again
/// (FIX 9157).
#[derive(Default)]
struct Backoffs(
    HashMap<EntityId, (Instant, Duration)>,
    HashMap<EntityId, u32>,
);

impl Backoffs {
    fn due(&self, call_ref: EntityId, now: Instant) -> bool {
        self.0.get(&call_ref).is_none_or(|(due, _)| *due <= now)
    }

    fn defer(&mut self, call_ref: EntityId, now: Instant) {
        let delay = self
            .0
            .get(&call_ref)
            .map_or(CONNECTOR_SETTLE_INTERVAL, |(_, delay)| {
                delay.saturating_mul(2).min(CONNECTOR_SETTLE_MAX_BACKOFF)
            });
        self.0.insert(call_ref, (now + delay, delay));
    }
}

impl SyncServer {
    /// Starts the connector-call settler. It runs whatever the configured
    /// connectors, hooks or model slots: a held call may outlive the config
    /// that made it.
    pub(crate) fn spawn_connector_settler(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_connector_settler_admitted(admit_every_pass())
    }

    /// Starts the settler on a host with a write freeze: each pass is
    /// admitted through `admit` and holds that admission on its blocking
    /// thread through every expiry, repair, send and delivery it writes. A
    /// refused pass settles nothing and waits its interval.
    pub(crate) fn spawn_connector_settler_admitted(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(settle_forever(Arc::clone(self), admit))
    }
}

async fn settle_forever(server: Arc<SyncServer>, admit: HousekeepingAdmission) {
    let mut backoffs = Backoffs::default();
    loop {
        let Some(admission) = admit() else {
            tokio::time::sleep(CONNECTOR_SETTLE_INTERVAL).await;
            continue;
        };
        let pass = Arc::clone(&server);
        let mut held = std::mem::take(&mut backoffs);
        let outcome = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let settled =
                settle_connector_calls(&pass, &mut held).map_err(|error| error.to_string());
            (held, settled)
        })
        .await;
        match outcome {
            Ok((held, settled)) => {
                backoffs = held;
                if let Err(error) = settled {
                    tracing::warn!(%error, "connector settle pass failed");
                }
            }
            Err(error) => {
                tracing::error!(
                    panicked = error.is_panic(),
                    "connector settle pass ended; settler stopping"
                );
                return;
            }
        }
        tokio::time::sleep(CONNECTOR_SETTLE_INTERVAL).await;
    }
}

/// One pass over the pending connector calls; returns how many it settled.
/// Blocking: it sends, so run it on a blocking worker.
fn settle_connector_calls(
    server: &SyncServer,
    backoffs: &mut Backoffs,
) -> Result<usize, IntentLedgerError> {
    let vault = server.vault();
    // Expiry first, so a call past its deadline settles in this same pass;
    // then the owner asks a hold tried and failed to queue.
    if let Err(error) = vault.expire_connector_calls(now_ms()) {
        tracing::warn!(%error, "connector call expiry failed");
    }
    if let Err(error) = vault.repair_connector_call_owner_asks() {
        tracing::warn!(%error, "connector call owner ask repair failed");
    }
    // Connector event wakes a budget window paced are admitted again once
    // it opens (FIX 8686).
    if let Err(error) = vault.continue_paced_connector_wakes() {
        tracing::warn!(%error, "paced connector wakes not admitted");
    }
    crate::connector_call_host::resume_exchanges(server, &mut backoffs.1);
    let pending = vault.pending_connector_calls()?;
    backoffs
        .0
        .retain(|call_ref, _| pending.iter().any(|call| call.call_ref == *call_ref));
    let now = Instant::now();
    // A call a budget window paces waits for the window, and goes in the
    // first pass after it opens, whatever its backoff (FIX 8686).
    let due: Vec<_> = pending
        .into_iter()
        .filter(|call| match call.paced {
            _ if call.settled => true,
            Some(shut) => !shut,
            None => backoffs.due(call.call_ref, now),
        })
        .collect();
    if due.is_empty() {
        return Ok(0);
    }
    let mut host = ServedConnectorCallHost::new(server)?;
    let deliveries = WaitDeliveries::canonical(vault);
    let mut settled = 0;
    for call in due {
        // An answered code consent wait's call runs only on its host's
        // answered pass (DOOR-079 1a): its original caller's instrument
        // checked, then its own gate under the code-bound approval. The
        // engine settles the wait and wakes the run; a later pass here
        // acknowledges the settled call.
        match vault.answered_code_consent_wait_for_call(&call.call_ref) {
            Ok(None) => {}
            Ok(Some(wait_id)) => {
                if let Err(error) =
                    crate::code_consent_host::resume_answered(server, vault, wait_id)
                {
                    tracing::warn!(wait = %wait_id.to_hex(), %error, "code consent effect not settled");
                }
                backoffs.defer(call.call_ref, now);
                continue;
            }
            Err(error) => {
                tracing::warn!(call_ref = %call.call_ref.to_hex(), %error, "code consent wait not read");
                backoffs.defer(call.call_ref, now);
                continue;
            }
        }
        let (outcome, rows) = match vault.resume_connector_call_listing(&call.call_ref, &mut host) {
            Ok(resumed) => resumed,
            Err(error) => {
                tracing::warn!(call_ref = %call.call_ref.to_hex(), %error, "connector call resume failed");
                backoffs.defer(call.call_ref, now);
                continue;
            }
        };
        let reply = ConnectorCallReply::project(&call.name, &call.tool, outcome);
        if reply.wait_ref().is_some() {
            backoffs.defer(call.call_ref, now);
            continue;
        }
        // A connector that asked for input mid-call received the call: its
        // questions and their handle are the call's reply, delivered to the
        // wait like any other, so whoever waits on the call answers them
        // (FIX 3839). Its row keeps the round for its caller's polls
        // (FIX 3837), so the acknowledgement below leaves that row.
        let reply = serde_json::to_value(&reply)
            .map_err(|_| IntentLedgerError::InvalidRecord("connector call reply"))?;
        // The reply rides beside the rows the call's passes picked, kept
        // through every resume (FIX 5455): unknown stays unknown.
        deliveries.deliver_listing(call.call_ref, &reply, rows.as_deref(), now_ms())?;
        // Its caller stays bound once the row goes, so `connector.call_status`
        // reads the settled wait for that caller and the owner alone.
        vault.ack_connector_call_delivery_keeping_caller(&call.call_ref)?;
        backoffs.0.remove(&call.call_ref);
        settled += 1;
    }
    // A held browser act has no connector row, so the pass above never
    // visits it: an answered pass that failed before its admission (the
    // server stopping, a storage error) leaves it settling, and a second
    // identical answer drives nothing (FIX 11498). Each pass drives every
    // approved, unadmitted browser wait answered at least one interval ago
    // (so an answer's own drive is not raced) through the same answered
    // pass, which runs the act once.
    let drive_after_ms = BROWSER_WAIT_DRIVE_AFTER.as_secs().saturating_mul(1000);
    let answered_by_ms = now_ms().saturating_sub(drive_after_ms);
    match vault.approved_browser_code_consent_waits(answered_by_ms) {
        Ok(waits) => {
            for wait_id in waits {
                if let Err(error) =
                    crate::code_consent_host::resume_answered(server, vault, wait_id)
                {
                    tracing::warn!(
                        wait = %wait_id.to_hex(),
                        %error,
                        "code consent browser effect not settled"
                    );
                } else if !vault.code_consent_browser_wait_open(wait_id).unwrap_or(true) {
                    settled += 1;
                }
            }
        }
        Err(error) => tracing::warn!(%error, "browser code consent waits not listed"),
    }
    Ok(settled)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
