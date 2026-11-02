//! Scoped live outbound waits over the durable journals: a journaled model
//! call and an admitted effect send.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::{JournaledResumeStep, LiveWait, ShedCause, SlimState};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::outbound_intent_ledger::IntentLedgerRecord;

/// The host's long-outbound-wait policy. Resolves once with the observed wait
/// in seconds. This is a shed trigger, never a timeout on the provider call.
pub trait OutboundWaitHost: std::fmt::Debug + Send + Sync {
    fn long_wait(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>>;
}

impl Vault {
    /// Installs the host's wait policy. Embedded engines have none by default;
    /// their host may bind one without changing outbound or retry behavior.
    pub fn set_outbound_wait_host(&self, host: Option<Arc<dyn OutboundWaitHost>>) {
        *self
            .slim
            .wait_host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = host;
    }

    /// Called only after the durable step's Started row and budget admission.
    /// The provider future remains owned and polled here across the shed.
    pub(crate) async fn during_journaled_model_wait<F: Future>(
        &self,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        updated_ms: u64,
        operation: F,
    ) -> F::Output {
        let step = JournaledResumeStep::Model {
            attempt_id,
            step_hash,
            updated_ms,
        };
        let admission = {
            let mut state = self.slim.lock_state();
            *state = SlimState::Full;
            self.register_live_wait(step, true)
        };
        let host = self
            .slim
            .wait_host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut trigger = host.as_ref().map(|host| host.long_wait());
        let mut operation = std::pin::pin!(operation);
        let output = poll_fn(|cx| {
            // A ready reply wins over a ready shed trigger. The next code to
            // handle that reply sees FULL, with every rebuild still lazy.
            if let Poll::Ready(output) = operation.as_mut().poll(cx) {
                return Poll::Ready(output);
            }
            if let Some(wait) = trigger.as_mut()
                && let Poll::Ready(waited_secs) = wait.as_mut().poll(cx)
            {
                trigger = None;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| {
                        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                    });
                if let Err(error) =
                    self.shed_rebuildable_heap(ShedCause::LongOutboundWait, waited_secs, now_ms)
                {
                    // Shedding is optional; failure must not cancel or resend
                    // an admitted, possibly already paid provider request.
                    tracing::warn!(kind = ?error.kind(), "slim: long-wait shed failed");
                }
            }
            Poll::Pending
        })
        .await;
        drop(admission);
        output
    }

    /// Runs the one transport send of an admitted effect whose `Pending` row
    /// is durable, as a live wait a supervisor can observe (FIX 5186). `send`
    /// runs exactly as it would unwrapped: nothing here times, cancels or
    /// resends it, and residency is left to the send's completion resume.
    pub(crate) fn during_admitted_effect_send<R>(
        &self,
        record: &IntentLedgerRecord,
        send: impl FnOnce() -> R,
    ) -> R {
        let step = JournaledResumeStep::OutboundIntent {
            intent_id: record.id,
            attempt_id: record.attempt_id,
            call_seq: record.call_seq,
            updated_ms: record.updated_ms,
        };
        // Selection never reads an effect send's live wait, so it registers
        // without the transition lock and never waits behind a shed.
        let _live = self.register_live_wait(step, false);
        send()
    }

    /// Registers one live wait under a fresh id. A model wait's caller holds
    /// the controller's `state`.
    fn register_live_wait(
        &self,
        step: JournaledResumeStep,
        restores_full: bool,
    ) -> LiveWaitScope<'_> {
        let wait_id = self
            .slim
            .last_wait_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        self.slim.lock_live_waits().push(LiveWait {
            step,
            wait_id,
            started: Instant::now(),
        });
        LiveWaitScope {
            vault: self,
            wait_id,
            restores_full,
        }
    }
}

/// Completion, failure, unwind and cancellation all retire the live wait. A
/// model wait also restores logical FULL residency without opening any heap
/// component; an effect send leaves residency to its completion resume.
struct LiveWaitScope<'a> {
    vault: &'a Vault,
    wait_id: u64,
    restores_full: bool,
}

impl Drop for LiveWaitScope<'_> {
    fn drop(&mut self) {
        // A model wait retires under `state`, as it registered.
        let state = self.restores_full.then(|| self.vault.slim.lock_state());
        self.vault
            .slim
            .lock_live_waits()
            .retain(|wait| wait.wait_id != self.wait_id);
        if let Some(mut state) = state {
            *state = SlimState::Full;
            drop(state);
            // A retired model wait may let the owner's waiting shed decide
            // (FIX 10157): woken once both locks are released.
            self.vault.wake_owner_shed();
        }
    }
}
