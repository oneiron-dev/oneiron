//! Cooperative shutdown handle and listener channels.
#[cfg(all(unix, feature = "voice"))]
use oneiron_server::managed::ManagedShutdown;
use tokio::sync::watch;

/// Requests a graceful supervisor stop. Cooperative ONLY (H-S5/R2): between
/// passes the loop exits immediately; mid-pass the running pass's
/// [`WakeCancellation`] flag is raised and the pass is awaited to its own
/// attempt-boundary stop — never aborted.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    pub(super) tx: watch::Sender<bool>,
    #[cfg(all(unix, feature = "voice"))]
    pub(super) voice: Option<ManagedShutdown>,
}

impl ShutdownHandle {
    /// Requests shutdown. Idempotent.
    pub fn shutdown(&self) {
        #[cfg(all(unix, feature = "voice"))]
        if let Some(shutdown) = &self.voice {
            shutdown.trigger();
        }
        let _ = self.tx.send(true);
    }
}

#[derive(Debug)]
pub(super) struct ShutdownListener {
    pub(super) rx: watch::Receiver<bool>,
    #[cfg(all(unix, feature = "voice"))]
    pub(super) voice: Option<ManagedShutdown>,
}

impl ShutdownListener {
    pub(super) fn requested(&self) -> bool {
        #[cfg(all(unix, feature = "voice"))]
        if self
            .voice
            .as_ref()
            .is_some_and(ManagedShutdown::is_triggered)
        {
            return true;
        }
        *self.rx.borrow()
    }

    /// Resolves once shutdown is requested. If every [`ShutdownHandle`] is
    /// dropped without a request, nothing can ever request one — this pends
    /// forever rather than reporting a spurious shutdown.
    pub(super) async fn triggered(&mut self) {
        #[cfg(all(unix, feature = "voice"))]
        if let Some(shutdown) = &self.voice {
            tokio::select! {
                biased;
                () = shutdown.triggered() => {},
                () = async {
                    if self.rx.wait_for(|stopped| *stopped).await.is_err() {
                        std::future::pending::<()>().await;
                    }
                } => {},
            }
            return;
        }
        if self.rx.wait_for(|stopped| *stopped).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}
