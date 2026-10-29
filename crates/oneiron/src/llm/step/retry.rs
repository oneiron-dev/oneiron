//! Transport retries for one durable model call: the ONE retry authority.
//!
//! The engine schedule paces the first retries; a caller's chosen count past
//! it reuses the schedule's last interval, so every requested attempt runs
//! (FIX 9930). The default stays four attempts on today's intervals, and no
//! deadline is added: a retry waits its interval, never a new clock.
//!
//! A provider limit that states its reset past every wait the schedule has
//! left, and spent credit, which only the owner's answer brings back (the
//! offer's park already asked it), are not retried (FIX 11226): each retry
//! could only meet the same refusal. The refusal returns at once, and the
//! attempt parks as its executor parks any limit refusal, for a later pass to
//! resume. A limit with no stated reset, or one the schedule reaches, keeps
//! today's retries.
//!
//! The reset a refusal states also rides out with it: the attempt's Retry
//! park comes due at that reset ([`stated_reset_at`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use super::super::{
    LlmBackend, LlmError, LlmRequest, LlmResponse, LlmResult, RetryableLlmError, SpentKind,
};
use super::types::DREAMER_STEP_RETRY_BACKOFF_MS;

/// The wait before retry `retry` (from zero): the schedule's own interval,
/// then its last one for every retry past it.
pub(super) fn retry_delay_ms(retry: usize) -> u64 {
    let last = DREAMER_STEP_RETRY_BACKOFF_MS.len().saturating_sub(1);
    DREAMER_STEP_RETRY_BACKOFF_MS
        .get(retry.min(last))
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
                if retries >= max_retries || waits_past_schedule(&error, retries, max_retries) {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(retry_delay_ms(retries)).await;
                retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Whether `error`, met before retry `retry` of `max_retries`, waits past every interval
/// the schedule has left: spent credit, or a rate limit or spent window whose stated reset
/// ([`stated_reset_secs`]) comes later than all of them. A refusal that states no reset
/// never does.
fn waits_past_schedule(error: &RetryableLlmError, retry: usize, max_retries: usize) -> bool {
    if matches!(
        error,
        RetryableLlmError::QuotaSpent {
            kind: SpentKind::Credit,
            ..
        }
    ) {
        return true;
    }
    let Some(reset_ms) = stated_reset_secs(error, unix_now()).map(|secs| secs.saturating_mul(1000))
    else {
        return false;
    };
    let mut left = 0_u64;
    for pending in retry..max_retries {
        left = left.saturating_add(retry_delay_ms(pending));
        if left >= reset_ms {
            return false;
        }
    }
    true
}

/// How many seconds after `now` (Unix seconds) a rate limit or a spent usage window says
/// it resets: its `retry_after`, else its first `resets_at` still ahead. None for a
/// refusal that states no reset, and for spent credit, which only the owner's answer
/// brings back.
fn stated_reset_secs(error: &RetryableLlmError, now: u64) -> Option<u64> {
    let (retry_after, resets_at) = match error {
        RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        }
        | RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
        } => (*retry_after, resets_at),
        _ => return None,
    };
    retry_after.or_else(|| resets_at.iter().find(|at| **at > now).map(|at| at - now))
}

/// When the provider limit `error` says it resets, in Unix seconds (FIX 11226): a Retry
/// park the refusal makes comes due then. None when it states none.
pub(super) fn stated_reset_at(error: &LlmError) -> Option<u64> {
    let LlmError::Retryable(error) = error else {
        return None;
    };
    let now = unix_now();
    stated_reset_secs(error, now).map(|secs| now.saturating_add(secs))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
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
