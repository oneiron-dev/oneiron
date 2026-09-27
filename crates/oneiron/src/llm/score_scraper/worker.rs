//! Lifecycle-owned background score refresh: one immediate attempt, then the configured cadence.
use super::ModelScoreDiff;
use super::{ScoreFetch, ScoreScraper};
use crate::{
    Vault,
    error::{Error, Result},
};
use std::{
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Owns the scheduler thread and reports each attempt, including unchanged
/// snapshots and failures. Dropping the worker stops it and joins its thread.
pub struct ScoreScraperWorker {
    results: Receiver<Result<Vec<ModelScoreDiff>>>,
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl ScoreScraperWorker {
    pub(super) fn start<F: ScoreFetch + Send + 'static>(
        mut scraper: ScoreScraper<F>,
        vault: Arc<Vault>,
    ) -> Self {
        let interval = Duration::from_secs(scraper.config.fetch_interval_secs);
        let (result_tx, results) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                let attempt = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Io(std::io::Error::other("system clock predates epoch")))
                    .and_then(|time| scraper.refresh(&vault, time.as_secs()));
                if result_tx.send(attempt).is_err() {
                    break;
                }
                if stop_rx.recv_timeout(interval).is_ok() {
                    break;
                }
            }
        });
        Self {
            results,
            stop,
            thread: Some(thread),
        }
    }

    /// Each scheduled attempt emits a result. The caller can select or time out
    /// on this receiver; errors are not silently discarded by the scheduler.
    pub fn results(&self) -> &Receiver<Result<Vec<ModelScoreDiff>>> {
        &self.results
    }
}

impl Drop for ScoreScraperWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
