//! The hand-off of a bound Dreamer's timer work (OF-506, FIX 1149). Serve
//! binds the standing-question pump and the due digests to the running
//! Dreamer's timer, so it starts neither sleeper. Should that Dreamer's
//! thread end before shutdown, the questions and digests would stop until a
//! restart: the watch here sees the end, already passed or still to come,
//! and starts both sleepers once, on the live server, each pass admitted
//! through the host's pass gate as it reads then (managed serve's reap
//! freeze). The Dreamer is not restarted and nothing polls. A planned
//! shutdown stops the watch before the Dreamer, so it starts nothing, and
//! stopping the watch aborts every sleeper it started.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::dreamer::PassAdmission;
use crate::server::{HousekeepingAdmission, SyncServer};

/// The watch on one bound Dreamer's thread, and the sleepers it started.
pub(super) struct DreamerFallback {
    stop: watch::Sender<bool>,
    monitor: Option<JoinHandle<()>>,
}

/// The sleepers a hand-off started: aborted with the watch, however it ends.
struct Sleepers(Vec<JoinHandle<()>>);

impl Drop for Sleepers {
    fn drop(&mut self) {
        for sleeper in &self.0 {
            sleeper.abort();
        }
    }
}

impl DreamerFallback {
    /// Watches `ended`, the bound Dreamer's end, on the serve runtime.
    /// Outside a runtime there is nothing to start the sleepers on, so it
    /// watches nothing (logged).
    pub(super) fn spawn(
        server: &Arc<SyncServer>,
        mut ended: watch::Receiver<bool>,
        admission: PassAdmission,
    ) -> Self {
        let (stop, mut stopping) = watch::channel(false);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                "no runtime watches the bound Dreamer; its timer work has no hand-off if it ends"
            );
            return Self {
                stop,
                monitor: None,
            };
        };
        let server = Arc::downgrade(server);
        let monitor = runtime.spawn(async move {
            tokio::select! {
                biased;
                _ = stopping.wait_for(|stop| *stop) => return,
                _ = ended.wait_for(|ended| *ended) => {}
            }
            if *stopping.borrow() {
                return;
            }
            let Some(server) = server.upgrade() else {
                return;
            };
            tracing::warn!(
                "the bound Dreamer stopped; its standing questions and due digests run on their own sleepers until shutdown"
            );
            let admit: HousekeepingAdmission = Arc::new(move || super::dreamer::admit(&admission));
            let sleepers = Sleepers(vec![
                crate::decision_graph::spawn(&server, Arc::clone(&admit)),
                super::home_digests::spawn(&server, admit),
            ]);
            drop(server);
            // Held until the watch stops, or its owner is gone.
            let _ = stopping.wait_for(|stop| *stop).await;
            drop(sleepers);
        });
        Self {
            stop,
            monitor: Some(monitor),
        }
    }

    /// Stops the watch: it starts nothing from here on, and every sleeper
    /// it started is aborted.
    pub(super) fn stop(&self) {
        self.stop.send_replace(true);
        if let Some(monitor) = &self.monitor {
            monitor.abort();
        }
    }
}
