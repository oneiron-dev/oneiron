//! The blocking jobs a sync run's upkeep rounds start (FIX 12785).
//!
//! Aborting an async upkeep round does not stop a blocking job it started.
//! Each round runs inside [`UpkeepJobs::scope`], and each blocking job a
//! residence call starts in it through [`spawn_upkeep_blocking`] holds the
//! run's mark until it returns. The run's end waits until no job holds one.
//! Outside a round, [`spawn_upkeep_blocking`] is plain `spawn_blocking`.

use std::future::Future;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

tokio::task_local! {
    static UPKEEP_JOBS: UpkeepJobs;
}

/// The mark a sync run's upkeep jobs hold while they run.
#[derive(Clone)]
pub(crate) struct UpkeepJobs(mpsc::Sender<()>);

/// What a sync run's end waits on: it closes once no job holds the run's
/// mark.
pub(crate) struct UpkeepJobsEnded(mpsc::Receiver<()>);

impl UpkeepJobs {
    /// A new run's mark, and what its end waits on.
    pub(crate) fn for_run() -> (Self, UpkeepJobsEnded) {
        let (running, ended) = mpsc::channel(1);
        (Self(running), UpkeepJobsEnded(ended))
    }

    /// Runs `round` with every blocking job it starts through
    /// [`spawn_upkeep_blocking`] marked as this run's.
    pub(crate) async fn scope<F: Future>(self, round: F) -> F::Output {
        UPKEEP_JOBS.scope(self, round).await
    }
}

impl UpkeepJobsEnded {
    /// Waits until no job holds the run's mark. The run drops its own mark
    /// first.
    pub(crate) async fn wait(mut self) {
        // Nothing is sent: `recv` returns `None` once no mark is held.
        while self.0.recv().await.is_some() {}
    }
}

/// `tokio::task::spawn_blocking`, except that inside an upkeep round the job
/// holds the round's mark until it returns, so the run's end waits for it.
pub(crate) fn spawn_upkeep_blocking<T, F>(job: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let mark = UPKEEP_JOBS.try_with(UpkeepJobs::clone).ok();
    tokio::task::spawn_blocking(move || {
        let _mark = mark;
        job()
    })
}
