//! Observed shared-vault runs with leave checks beside their connection attempts.

use super::SyncConnection;
use crate::sync::TransportError;
use crate::sync::client::{SyncEvent, SyncStatus};
use crate::sync::shared_leave::SharedLeaveReceipt;

pub(super) fn require_credential_transport(url: &reqwest::Url) -> Result<(), TransportError> {
    let loopback = url.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(TransportError::InvalidPayload(
            "leave notice credentials need HTTPS or numeric loopback",
        ))
    }
}

impl SyncConnection {
    /// Runs like [`Self::run_observed`], checking the configured member's leave
    /// notices beside the connection loop. The target names the shared
    /// vault this environment holds, just as for [`Self::check_shared_leave`].
    /// Only a notice verified against this environment's trusted home ends the
    /// lane. A failed or refused check never delays or refuses a connection.
    ///
    /// `on_leave` receives each completed check, including request failures and
    /// the actual confirmed receipt or purge error. A newer attempt during a
    /// check is retained for the next check. When the connection loop ends, an
    /// unverified request is cancelled; a verified leave finishes confirmation.
    /// The return value is the original connection loop's result.
    ///
    /// This future owns both activities. Dropping it cancels them, as dropping
    /// [`Self::run_observed`] cancels its connection loop.
    pub async fn run_observed_with_shared_leave(
        &self,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        vault_id: u64,
        member: &str,
        mut on_event: impl FnMut(SyncEvent) + Send,
        mut on_leave: impl FnMut(Result<Option<SharedLeaveReceipt>, TransportError>) + Send,
    ) -> crate::error::Result<()> {
        let (attempt_tx, mut attempt_rx) = tokio::sync::watch::channel(());
        let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);
        let run = async move {
            let result = self
                .run_observed(shutdown_rx, move |event| {
                    if matches!(&event, SyncEvent::StatusChanged(SyncStatus::Connecting)) {
                        attempt_tx.send_replace(());
                    }
                    on_event(event);
                })
                .await;
            done_tx.send_replace(true);
            result
        };
        let checks = async move {
            loop {
                tokio::select! {
                    biased;
                    _ = done_rx.wait_for(|done| *done) => return,
                    changed = attempt_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                let notice = tokio::select! {
                    biased;
                    _ = done_rx.wait_for(|done| *done) => return,
                    notice = self.fetch_shared_leave_notice(vault_id, member) => notice,
                };
                match notice {
                    Ok(Some(notice)) => {
                        on_leave(self.confirm_shared_leave_notice(&notice).await.map(Some));
                        return;
                    }
                    Ok(None) => on_leave(Ok(None)),
                    Err(error) => on_leave(Err(error)),
                }
            }
        };
        let (result, ()) = tokio::join!(run, checks);
        result
    }
}
