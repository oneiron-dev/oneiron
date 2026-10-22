//! Transport retries for one durable model call: the ONE retry authority.
//!
//! The engine schedule paces the first retries; a caller's chosen count past
//! it reuses the schedule's last interval, so every requested attempt runs
//! (FIX 9930). The default stays four attempts on today's intervals, and no
//! deadline is added: a retry waits its interval, never a new clock.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use super::super::{LlmBackend, LlmError, LlmRequest, LlmResponse, LlmResult};
use super::types::DREAMER_STEP_RETRY_BACKOFF_MS;

/// The wait before retry `retry` (from zero): the schedule's own interval,
/// then its last one for every retry past it.
pub(super) fn retry_delay_ms(retry: usize) -> u64 {
    DREAMER_STEP_RETRY_BACKOFF_MS
        .get(retry)
        .or(DREAMER_STEP_RETRY_BACKOFF_MS.last())
        .copied()
        .unwrap_or(0)
}

pub(super) async fn generate_with_retry(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &super::BudgetLease,
    max_retries: usize,
) -> LlmResult<LlmResponse> {
    let mut retries = 0_usize;
    loop {
        match backend.generate(request.clone(), lease).await {
            Ok(response) => return Ok(response),
            Err(LlmError::Retryable(error)) => {
                if retries >= max_retries {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(retry_delay_ms(retries)).await;
                retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// std-only timer future (zero-new-deps pin, design D1): a helper thread
/// wakes the most recent waker once the deadline passes.
fn sleep_ms(ms: u64) -> SleepFuture {
    SleepFuture {
        deadline: Instant::now() + Duration::from_millis(ms),
        shared_waker: None,
    }
}

struct SleepFuture {
    deadline: Instant,
    shared_waker: Option<Arc<Mutex<Waker>>>,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }
        if let Some(shared) = &self.shared_waker {
            *shared.lock().expect("sleep waker mutex poisoned") = cx.waker().clone();
            return Poll::Pending;
        }
        let shared = Arc::new(Mutex::new(cx.waker().clone()));
        self.shared_waker = Some(Arc::clone(&shared));
        let deadline = self.deadline;
        std::thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
            shared
                .lock()
                .expect("sleep waker mutex poisoned")
                .wake_by_ref();
        });
        Poll::Pending
    }
}
