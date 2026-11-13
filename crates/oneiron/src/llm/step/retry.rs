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
//!
//! An attempt held unsent because its offer rests for its provider's health,
//! or because its one probation request is out, spends no attempt (FIX
//! 11226): the declared schedule counts sends. The call waits for the offer
//! back, within its rest wait, and asks again; the rest still holds every
//! other call off the offer. A rest past what is left of that wait returns at
//! once, unsent, and the step parks with the retries its sends spent
//! ([`TransportRetries::spent`]); its resume starts from them. A plan that
//! keeps its count ([`TransportRetries::keeping`]) keeps each failed send's
//! retry before its wait, so a stop mid-pass resumes with that send counted
//! too, and a retry that does not keep is not made.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// How often a call held unsent by its offer's health asks again when no
/// reset is stated (a probation request is out), and the least it waits for
/// one that is: the schedule's first interval.
const HEALTH_REST_POLL_MS: u64 = 250;

/// Keeps a step's spent retries where its next pass reads them (FIX 11226),
/// and answers whether they kept.
pub(super) type KeepSpent<'a> = &'a (dyn Fn(usize) -> bool + Send + Sync);

/// One durable call's transport retries: the retries its schedule makes
/// after the first send (FIX 9930), how long it waits in all, unsent, for its
/// offer back from a health rest, and the retries its failed sends have
/// spent, which a step that parked keeps for its resume (FIX 11226).
pub(super) struct TransportRetries<'a> {
    pub(super) max: usize,
    pub(super) rest_wait: Duration,
    spent: AtomicUsize,
    keep: Option<KeepSpent<'a>>,
}

impl<'a> TransportRetries<'a> {
    /// `max` retries on the schedule, and no wait for a health rest: a
    /// backend that walks its own ladder waits for its offers itself.
    pub(super) fn schedule(max: usize) -> Self {
        Self::resumed(max, Duration::ZERO, 0)
    }

    /// `max` retries, `spent` of them by the sends of an earlier pass that
    /// parked, and `rest_wait` for its offer back.
    pub(super) fn resumed(max: usize, rest_wait: Duration, spent: usize) -> Self {
        Self {
            max,
            rest_wait,
            spent: AtomicUsize::new(spent),
            keep: None,
        }
    }

    /// The same plan, each retry it spends kept by `keep` before the next
    /// send may use it: a stop mid-pass then resumes with every failed send
    /// counted, not only those of a pass that returned.
    pub(super) fn keeping(self, keep: KeepSpent<'a>) -> Self {
        Self {
            keep: Some(keep),
            ..self
        }
    }

    /// The retries spent so far: once the call parks unsent, the sends it
    /// made, an earlier pass's included.
    pub(super) fn spent(&self) -> usize {
        self.spent.load(Ordering::Acquire)
    }

    /// The same plan for another call of the step, a correction: its own
    /// count, from none, kept nowhere.
    pub(super) fn for_another_call(&self) -> Self {
        Self::resumed(self.max, self.rest_wait, 0)
    }

    /// Counts `spent` retries, kept where the plan keeps them. Whether they
    /// kept: a retry that did not keep is not made.
    fn spend(&self, spent: usize) -> bool {
        self.spent.store(spent, Ordering::Release);
        self.keep.is_none_or(|keep| keep(spent))
    }
}

pub(super) async fn generate_with_retry(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &super::BudgetLease,
    plan: &TransportRetries<'_>,
) -> LlmResult<LlmResponse> {
    let max_retries = plan.max;
    let mut retries = plan.spent();
    let mut rested = Duration::ZERO;
    loop {
        match backend.generate(request.clone(), lease).await {
            Ok(response) => return Ok(response),
            // Nothing went out: no attempt is spent (FIX 11226).
            Err(LlmError::Retryable(error @ RetryableLlmError::HealthRest { .. })) => {
                let wait = health_rest_wait(&error, unix_now_ms());
                if rested.saturating_add(wait) > plan.rest_wait {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)).await;
                rested = rested.saturating_add(wait);
            }
            Err(LlmError::Retryable(error)) => {
                if retries >= max_retries || waits_past_schedule(&error, retries, max_retries) {
                    return Err(LlmError::Retryable(error));
                }
                let delay = retry_delay_ms(retries);
                retries += 1;
                // The failed send's retry is spent before its wait, so a stop
                // there resumes with it counted.
                if !plan.spend(retries) {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// How long, from `now_ms` (Unix milliseconds), until the offer a health
/// rest names is back: to the start of the first second it states still
/// ahead, at least [`HEALTH_REST_POLL_MS`]. A probation request's end, which
/// no clock states, is asked for each [`HEALTH_REST_POLL_MS`].
fn health_rest_wait(error: &RetryableLlmError, now_ms: u64) -> Duration {
    let RetryableLlmError::HealthRest {
        retry_after,
        resets_at,
    } = error
    else {
        return Duration::from_millis(HEALTH_REST_POLL_MS);
    };
    let now = now_ms / 1000;
    let back_ms = resets_at
        .iter()
        .find(|at| **at > now)
        .map(|at| at.saturating_mul(1000).saturating_sub(now_ms))
        .or_else(|| retry_after.map(|secs| secs.saturating_mul(1000)))
        .unwrap_or(0);
    Duration::from_millis(back_ms.max(HEALTH_REST_POLL_MS))
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
            ..
        } => (*retry_after, resets_at),
        _ => return None,
    };
    retry_after.or_else(|| resets_at.iter().find(|at| **at > now).map(|at| at - now))
}

/// When the provider limit `error` says it resets, in Unix seconds (FIX 11226): a Retry
/// park the refusal makes comes due then. None when it states none.
pub(crate) fn stated_reset_at(error: &LlmError) -> Option<u64> {
    let LlmError::Retryable(error) = error else {
        return None;
    };
    let now = unix_now();
    stated_reset_secs(error, now).map(|secs| now.saturating_add(secs))
}

fn unix_now() -> u64 {
    unix_now_ms() / 1000
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
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
