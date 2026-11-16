//! Releases this machine's executor leases before it sleeps and takes them up
//! again when it wakes (L8-28).
//!
//! Both plain serve and embedded serve start through `start_desktop_workers`,
//! so both get it.

#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

/// How long `will_sleep` waits after releasing the leases (Engine call): the
/// device-sync link carries the release to the other machines while the OS
/// still waits, inside logind's default 5 s delay.
#[cfg(unix)]
const SLEEP_RELEASE_SYNC_GRACE: Duration = Duration::from_secs(2);

/// The hooks a serve host's sleep watch calls (L8-28, ruling L8-28-SLEEP = A): before the machine sleeps it releases
/// this machine's send and agent-run executor leases, as a closing serve does, so another machine's reaper takes
/// its runs at once ("I close PC1, and the sessions from PC1 should move to PC2"); when it wakes it takes leases up
/// again (`Vault::resume_executor_leases`).
#[cfg(unix)]
pub(crate) struct LeaseReleaseOnSleep {
    /// The vault whose leases are released and resumed.
    pub(crate) vault: Arc<oneiron::Vault>,
    /// Serving stops: a wake then resumes nothing, since the stop released the leases for good.
    pub(crate) stopped: tokio::sync::watch::Receiver<bool>,
}

#[cfg(unix)]
impl oneiron_vault_contract::host_adapters::SleepHooks for LeaseReleaseOnSleep {
    fn will_sleep(&self) {
        match self.vault.release_send_executor_leases() {
            Ok(0) => {}
            Ok(released) => {
                tracing::info!(
                    released,
                    "send executor leases released for another machine"
                );
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "send executor lease release failed");
            }
        }
        match self.vault.release_agent_run_leases() {
            Ok(0) => {}
            Ok(released) => {
                tracing::info!(
                    released,
                    "agent run executor leases released for another machine"
                );
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "agent run executor lease release failed");
            }
        }
        std::thread::sleep(SLEEP_RELEASE_SYNC_GRACE);
    }

    fn woke(&self) {
        if !*self.stopped.borrow() {
            self.vault.resume_executor_leases();
            tracing::info!("executor leases taken up again after sleep");
        }
    }
}
