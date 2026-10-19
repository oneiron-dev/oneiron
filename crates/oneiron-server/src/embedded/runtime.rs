//! The runtime an embedded engine serves on, under the app's advisory CPU
//! share (FIX 2661, OF-237).
//!
//! `HostLimits::cpu_millis_per_second` is the embedder's setting, and it is
//! advisory: it sizes the Tokio worker pool the engine owns, one worker per
//! whole CPU second each second, rounded up, at least one and never more
//! than the CPUs available. It is no OS quota: blocking and native threads,
//! and the CPU time each worker takes, are not capped by it. An unbounded
//! share leaves the runtime as it was: the caller's, or Tokio's default size.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context as _;
use oneiron_vault_contract::host::HostLimits;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{Notify, oneshot};

use super::failure::{EngineErrorKind, cause};

/// The CPU milliseconds each second that one worker thread stands for.
const CPU_MILLIS_PER_WORKER: u32 = 1_000;

/// The name of the worker threads of a runtime the engine owns.
const ENGINE_THREAD_NAME: &str = "oneiron-engine";

/// The worker threads the app's CPU share in `limits` caps the engine's own
/// runtime at: the share in whole CPU seconds, rounded up, at least one and
/// at most the CPUs available. `None` for an unbounded share.
pub(super) fn worker_cap(limits: HostLimits) -> Option<usize> {
    if limits.cpu_millis_per_second == HostLimits::unbounded().cpu_millis_per_second {
        return None;
    }
    let wanted = limits.cpu_millis_per_second.div_ceil(CPU_MILLIS_PER_WORKER);
    let wanted = usize::try_from(wanted).unwrap_or(usize::MAX);
    let workers = match std::thread::available_parallelism() {
        Ok(available) => wanted.min(available.get()),
        Err(_) => wanted,
    };
    Some(workers.max(1))
}

/// A multi-thread runtime for the engine: `workers` worker threads when the
/// app's share caps it, Tokio's default otherwise.
pub(super) fn engine_runtime(workers: Option<usize>) -> std::io::Result<Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_name(ENGINE_THREAD_NAME);
    if let Some(workers) = workers {
        builder.worker_threads(workers);
    }
    builder.build()
}

/// Starts one serve run's body on a plain thread of its own, as `oneiron
/// serve` drives it on its main thread, so the app's host callbacks never
/// run on a runtime worker. With `workers` the thread builds a runtime of
/// its own capped at that many, serves on it and shuts it down once `serve`
/// returns, leaving no task of the run behind it. With `None` it enters the
/// caller's runtime, which must be current: an unbounded share, or a caller
/// whose own runtime already carries the cap (`BlockingEngine`).
///
/// The receiver takes the run's result; dropped unsent, the thread panicked.
pub(super) fn spawn_serving<F>(
    workers: Option<usize>,
    serve: impl FnOnce() -> F + Send + 'static,
) -> anyhow::Result<oneshot::Receiver<anyhow::Result<()>>>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let caller = workers.is_none().then(Handle::current);
    let (finished, done) = oneshot::channel();
    std::thread::Builder::new()
        .name("oneiron-engine-serve".to_owned())
        .spawn(move || {
            let served = match caller {
                Some(caller) => caller.block_on(serve()),
                None => engine_runtime(workers)
                    .context(cause(
                        EngineErrorKind::StartFailed,
                        "the embedded engine's runtime did not start",
                    ))
                    .and_then(|owned| {
                        let served = owned.block_on(serve());
                        owned.shutdown_background();
                        served
                    }),
            };
            let _ = finished.send(served);
        })
        .context(cause(
            EngineErrorKind::StartFailed,
            "the embedded engine's serve thread did not start",
        ))?;
    Ok(done)
}

/// A serve run's result, as its thread sent it.
pub(super) async fn served(done: oneshot::Receiver<anyhow::Result<()>>) -> anyhow::Result<()> {
    done.await.unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "the embedded engine's serve thread panicked"
        ))
    })
}

/// Stops a serve run through its host's stop handle when dropped, so a
/// caller that drops the future awaiting the run leaves no serving thread
/// behind: the run drains and stops in order on its own. After the run has
/// returned it does nothing.
pub(super) struct StopOnDrop(pub(super) Arc<Notify>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}
