//! The due sweep of the waits over AGENT children on every housekeeping pass
//! ([AGENT-WAIT-DEADLINE]): the engine settles each wait whose `until` has
//! passed and delivers it to the runs parked on it. The host lends only the
//! tick and the clock. Runs on a blocking worker, off the request path.

use std::sync::Arc;

use oneiron::Vault;

/// Unix milliseconds now, the clock a wait's `until` is on.
fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Settles every wait over AGENT children due now in `vault`, on the tick's
/// pass and the owner's run-now pass alike. A failure is logged by its kind
/// and the pass goes on.
pub(super) async fn settle_agent_waits(vault: Arc<Vault>) {
    let settled =
        tokio::task::spawn_blocking(move || vault.settle_due_agent_waits(unix_millis_now())).await;
    match settled {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(kind = ?error.kind(), "agent wait due sweep failed"),
        Err(error) => {
            tracing::warn!(
                panicked = error.is_panic(),
                "agent wait due sweep task failed"
            );
        }
    }
}
