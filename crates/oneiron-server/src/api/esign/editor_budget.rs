//! Router-owned admission for editor computation. A POST with no editor
//! header is public and capability-free: it takes a slot only when one is
//! free and meets a 60-per-minute window, or a 429. An owner's admitted
//! editor POST (FIX 5618, `editor_auth`) never meets either: it waits its
//! turn for one of the same two slots, with no queue length bound, for at
//! most `limits.queue_wait_timeout_ms`.
use super::*;
use axum::extract::Request;
use axum::middleware::Next;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) struct EditorBudget {
    window: Mutex<(Instant, u32)>,
    slots: Arc<Semaphore>,
}
impl EditorBudget {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            window: Mutex::new((Instant::now(), 0)),
            slots: Arc::new(Semaphore::new(2)),
        })
    }
    fn admit(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let mut window = self.window.lock().ok()?;
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        if window.1 >= 60 {
            return None;
        }
        window.1 += 1;
        Some(Arc::new(permit))
    }

    /// One of the two slots for an admitted editor POST, waited for at most
    /// `wait` (`limits.queue_wait()`). No queue length or count refuses it.
    pub(super) async fn queue(
        &self,
        wait: Duration,
    ) -> Result<OwnedSemaphorePermit, EditorWaitError> {
        match tokio::time::timeout(wait, self.slots.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(EditorWaitError::Closed),
            Err(_) => Err(EditorWaitError::TimedOut),
        }
    }
}

/// Why an admitted editor POST got no slot.
pub(super) enum EditorWaitError {
    /// It waited its whole deadline for its turn; nothing was started.
    TimedOut,
    /// The semaphore is closed, which nothing does while the router lives.
    Closed,
}

pub(super) async fn admit(
    State(budget): State<Arc<EditorBudget>>,
    mut request: Request,
    next: Next,
) -> Response {
    // An editor header is the owner's path: `EditorIngress` admits or
    // refuses it from the head and queues it for a slot, so it never meets
    // this window or its 429.
    if request
        .headers()
        .contains_key(super::editor_auth::EDITOR_HEADER)
    {
        return next.run(request).await;
    }
    let Some(permit) = budget.admit() else {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")]).into_response();
    };
    // Admit before body extraction. The geometry worker retains its own clone
    // even if the HTTP future is cancelled while parsing is still in progress.
    request.extensions_mut().insert(permit.clone());
    let response = next.run(request).await;
    drop(permit);
    response
}
