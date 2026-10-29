//! One pass run under supervision: panic-caught, cooperatively cancellable,
//! and paused at its boundary by the host's pause.
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};

use oneiron::{Vault, WakeCancellation};
use tokio::sync::watch;

use super::config::{NowSeconds, WakeSupervisorConfig};
use super::factory::PassExecutorFactory;
use super::pass::{PassRunError, paused, run_one_pass};
use super::retry::PassOutcome;
use super::shutdown::ShutdownListener;
use crate::tick::Tick;

/// Runs one pass panic-caught and cooperatively cancellable: a shutdown
/// arriving mid-pass raises the pass's [`WakeCancellation`] flag and keeps
/// awaiting — the pass future is NEVER dropped mid-await (H-S5/R2), so a
/// gated write or off-record close in progress always runs to its boundary.
///
/// Factory/`Result` failures before `run_wake_pass` surface as
/// [`PassOutcome::PreAdmissionFailed`] so the supervisor can owe the tick
/// again; panics anywhere in the pass still map to [`PassOutcome::Panicked`].
pub(super) async fn run_pass_supervised<F: PassExecutorFactory>(
    vault: &Vault,
    config: &WakeSupervisorConfig,
    pass_budget_id: &str,
    now_secs: &NowSeconds,
    factory: &mut F,
    shutdown: &mut ShutdownListener,
    tick: &Tick,
) -> PassOutcome {
    let cancel = WakeCancellation::new();
    // The host's pause for this pass (FIX 6909), taken before the pass
    // borrows the factory.
    let mut pause = factory.pass_pause();
    let mut pass = CatchUnwind::new(run_one_pass(
        vault,
        config,
        pass_budget_id,
        now_secs,
        factory,
        tick,
        &cancel,
    ));
    loop {
        tokio::select! {
            biased;
            () = shutdown.triggered(), if !cancel.is_cancelled() => {
                // Cooperative preemption: flag only. The loop continues and
                // the next iteration awaits the pass to completion (this
                // branch disables itself once the flag is up).
                cancel.cancel();
            }
            // The host's pause flags the pass the same way, and the pass is
            // still awaited to its boundary: what it admitted parks Paused,
            // resumed once the pause lifts.
            () = pause_requested(&mut pause), if !cancel.is_cancelled() => {
                cancel.pause();
            }
            result = &mut pass => {
                return match result {
                    // A pause that came while the pass ran its timer work,
                    // where no arm above can see it, stopped that work too.
                    Ok(Ok(pass_report)) if cancel.is_paused() || paused(pause.as_ref()) => {
                        PassOutcome::Paused(pass_report)
                    }
                    Ok(Ok(pass_report)) => PassOutcome::Completed(pass_report),
                    Ok(Err(PassRunError::PreAdmission(error))) => {
                        PassOutcome::PreAdmissionFailed(error)
                    }
                    Ok(Err(PassRunError::Failed(error))) => PassOutcome::Failed(error),
                    Err(_panic) => PassOutcome::Panicked,
                };
            }
        }
    }
}

/// Resolves once the host's pause asks the pass to stop; pends with no pause,
/// and when its epoch closes without asking.
async fn pause_requested(pause: &mut Option<watch::Receiver<bool>>) {
    let asked = match pause {
        Some(pause) => pause.wait_for(|asked| *asked).await.is_ok(),
        None => false,
    };
    if !asked {
        std::future::pending::<()>().await;
    }
}

/// Converts a panicking poll into a value so one exploding pass cannot take
/// the supervisor down. Boxes the inner future — no unsafe pin projection.
struct CatchUnwind<Fut> {
    inner: Pin<Box<Fut>>,
}

impl<Fut> CatchUnwind<Fut> {
    fn new(inner: Fut) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<Fut: Future> Future for CatchUnwind<Fut> {
    type Output = std::thread::Result<Fut::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // `Pin<Box<Fut>>` is Unpin, so plain mutable access is sound.
        let this = self.get_mut();
        let inner = this.inner.as_mut();
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic) => Poll::Ready(Err(panic)),
        }
    }
}
