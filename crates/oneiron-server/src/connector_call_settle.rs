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
//! reply body (`result_not_retained`); nothing is resent to rebuild one.
//!
//! A call still held, or a send the ledger retries, stays pending. Each such
//! resume runs the call's gate again, so a call that stays held is retried
//! after a doubling delay, from [`CONNECTOR_SETTLE_INTERVAL`] up to
//! [`CONNECTOR_SETTLE_MAX_BACKOFF`], kept in memory and reset by a restart.
//! There is no notification of a consent answer to wake the loop sooner.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::code_run::WaitDeliveries;
use oneiron::outbound_intent_ledger::IntentLedgerError;
use oneiron::task_verb::sdk::ConnectorCallReply;

use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::SyncServer;

/// How often the settler drains the pending connector calls, after the pass
/// it runs at startup.
pub(crate) const CONNECTOR_SETTLE_INTERVAL: Duration = Duration::from_secs(30);

/// The longest a call that stays held or undelivered waits between two of
/// its resumes.
pub(crate) const CONNECTOR_SETTLE_MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// When each call that stayed pending is next due, and its current delay.
#[derive(Default)]
struct Backoffs(HashMap<EntityId, (Instant, Duration)>);

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
        tokio::spawn(settle_forever(Arc::clone(self)))
    }
}

async fn settle_forever(server: Arc<SyncServer>) {
    let mut backoffs = Backoffs::default();
    loop {
        let pass = Arc::clone(&server);
        let mut held = std::mem::take(&mut backoffs);
        let outcome = tokio::task::spawn_blocking(move || {
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
    let pending = vault.pending_connector_calls()?;
    backoffs
        .0
        .retain(|call_ref, _| pending.iter().any(|call| call.call_ref == *call_ref));
    let now = Instant::now();
    let due: Vec<_> = pending
        .into_iter()
        .filter(|call| call.settled || backoffs.due(call.call_ref, now))
        .collect();
    if due.is_empty() {
        return Ok(0);
    }
    let mut host = ServedConnectorCallHost::new(server)?;
    let deliveries = WaitDeliveries::canonical(vault);
    let mut settled = 0;
    for call in due {
        let outcome = match vault.resume_connector_call(&call.call_ref, &mut host) {
            Ok(outcome) => outcome,
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
        let reply = serde_json::to_value(&reply)
            .map_err(|_| IntentLedgerError::InvalidRecord("connector call reply"))?;
        deliveries.deliver(call.call_ref, &reply, now_ms())?;
        vault.ack_connector_call_delivery(&call.call_ref)?;
        backoffs.0.remove(&call.call_ref);
        settled += 1;
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
