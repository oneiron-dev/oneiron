//! A scoped live model wait over the durable step journal.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{JournaledResumeStep, ShedCause, SlimState};
use crate::Vault;
use crate::attempt_queue::AttemptId;

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
            self.slim
                .model_waits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(step);
            ModelWait { vault: self, step }
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
                if let Err(error) = self.shed_rebuildable_heap(
                    ShedCause::LongOutboundWait,
                    waited_secs,
                    now_ms,
                ) {
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
}

/// Completion, failure, unwind and cancellation all retire the live pointer
/// and restore logical FULL residency without opening any heap component.
struct ModelWait<'a> {
    vault: &'a Vault,
    step: JournaledResumeStep,
}

impl Drop for ModelWait<'_> {
    fn drop(&mut self) {
        let mut state = self.vault.slim.lock_state();
        let mut waits = self
            .vault
            .slim
            .model_waits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = waits.iter().position(|step| step.same_step(&self.step)) {
            waits.swap_remove(index);
        }
        *state = SlimState::Full;
    }
}
