//! Cooperative shutdown handle and listener channels.
use std::sync::Arc;

use tokio::sync::watch;

use super::attachment::LinkedShutdown;

/// Requests a graceful supervisor stop. Cooperative ONLY (H-S5/R2): between
/// passes the loop exits immediately; mid-pass the running pass's
/// [`WakeCancellation`](oneiron::WakeCancellation) flag is raised and the pass is awaited to its own
/// attempt-boundary stop — never aborted.
#[derive(Clone)]
pub struct ShutdownHandle {
    pub(super) tx: watch::Sender<bool>,
    pub(super) linked: Option<Arc<dyn LinkedShutdown>>,
}

impl std::fmt::Debug for ShutdownHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownHandle")
            .field("requested", &*self.tx.borrow())
            .field("linked", &self.linked.is_some())
            .finish()
    }
}

impl ShutdownHandle {
    /// Requests shutdown. Idempotent.
    pub fn shutdown(&self) {
        if let Some(shutdown) = &self.linked {
            shutdown.trigger();
        }
        let _ = self.tx.send(true);
    }
}

pub(super) struct ShutdownListener {
    pub(super) rx: watch::Receiver<bool>,
    pub(super) linked: Option<Arc<dyn LinkedShutdown>>,
}

impl ShutdownListener {
    pub(super) fn requested(&self) -> bool {
        if self
            .linked
            .as_ref()
            .is_some_and(|shutdown| shutdown.is_triggered())
        {
            return true;
        }
        *self.rx.borrow()
    }

    /// Resolves once shutdown is requested. If every [`ShutdownHandle`] is
    /// dropped without a request, nothing can ever request one — this pends
    /// forever rather than reporting a spurious shutdown.
    pub(super) async fn triggered(&mut self) {
        let Self { rx, linked } = self;
        let own = async {
            if rx.wait_for(|stopped| *stopped).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        match linked {
            Some(shutdown) => {
                let linked = shutdown.triggered();
                tokio::select! {
                    biased;
                    () = linked => {},
                    () = own => {},
                }
            }
            None => own.await,
        }
    }
}
