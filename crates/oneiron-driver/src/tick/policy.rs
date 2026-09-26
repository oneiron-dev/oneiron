//! One cancellable quiet sleep per tick source, driven by the vault's row policy.
use super::{NowMillis, Tick, TickSource, sleep_until_due};
use oneiron::{
    Vault,
    dreamer_wake::{WakeIdleState, WakePolicyDecision},
};
use std::sync::Arc;

/// Host liveness signal. It must report the latest inbound timestamp before
/// waking the inner source for an inbound turn. No process-global timer exists.
pub type IdleSample = Arc<dyn Fn() -> WakeIdleState + Send + Sync>;

/// A per-vault wake policy decorator: it re-reads rows on each genuine event,
/// or after its single quiet deadline. A push cancels the pending sleep; no
/// timer runs when there is no explicit work or when live work occupies the vault.
/// Compose `inner` with [`HybridTick`](crate::HybridTick) and
/// [`AttemptQueueDeadlines`](crate::AttemptQueueDeadlines): the policy writes a
/// durable maintenance attempt, and that deadline lane drives it after an
/// enqueue or a process restart. A bare push receiver cannot drain attempts.
pub struct WakePolicyTicks<'a, T> {
    inner: T,
    vault: &'a Vault,
    idle: IdleSample,
    now_ms: NowMillis,
}
impl<'a, T: TickSource> WakePolicyTicks<'a, T> {
    #[must_use]
    pub fn new(inner: T, vault: &'a Vault, idle: IdleSample, now_ms: NowMillis) -> Self {
        Self {
            inner,
            vault,
            idle,
            now_ms,
        }
    }
}
impl<T: TickSource> TickSource for WakePolicyTicks<'_, T> {
    async fn next_tick(&mut self) -> Option<Tick> {
        loop {
            let now = (self.now_ms)() / 1_000;
            let idle = (self.idle)();
            let decision = match self.vault.enqueue_due_dreamer_wake(idle, now) {
                Ok(outcome) => outcome.decision,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "wake policy read/enqueue failed; lane quiet until next event"
                    );
                    return self.inner.next_tick().await;
                }
            };
            match decision {
                WakePolicyDecision::Silent | WakePolicyDecision::Enqueue { .. } => {
                    return self.inner.next_tick().await;
                }
                WakePolicyDecision::ArmIdle { due_at } => {
                    let clock = Arc::clone(&self.now_ms);
                    tokio::select! {
                        biased;
                        tick = self.inner.next_tick() => return tick,
                        () = sleep_until_due(&clock, due_at.saturating_mul(1_000)) => continue,
                    }
                }
            }
        }
    }
    fn take_buffered_session_hint(&mut self) -> Option<(crate::SessionHint, Option<u64>, u64)> {
        self.inner.take_buffered_session_hint()
    }
    fn take_buffered_session_hint_carrier(&mut self) -> Option<super::SessionHintCarrier> {
        self.inner.take_buffered_session_hint_carrier()
    }
    fn take_delivered_session_hint_carrier(&mut self) -> Option<super::SessionHintCarrier> {
        self.inner.take_delivered_session_hint_carrier()
    }
}
