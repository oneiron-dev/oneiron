//! A request that never reached its upstream goes once more, on a fresh
//! connection (FIX 7113). A pooled connection the upstream closed while it
//! sat idle fails the next request on it at once, before the upstream read a
//! byte of it; that failure is the pool's, never the provider's, so it is no
//! cooldown strike. The second send's outcome is the exchange's own: a
//! provider that is down fails it too, and rests as before. A request the
//! upstream may have read is never sent twice.
use std::error::Error as _;
use std::time::{Duration, Instant};

use super::Sending;

/// How soon after its send an exchange whose connection closed with no reply
/// byte counts as one its upstream never read: far under any model's first
/// byte, so an upstream that read the request and then closed is not sent it
/// again.
const NEVER_READ_WINDOW: Duration = Duration::from_millis(250);

/// Sends `request`, and once more on `fresh`, a client that keeps no idle
/// connection, when the first send never reached its upstream.
pub(super) fn send(fresh: &reqwest::Client, request: reqwest::RequestBuilder) -> Sending {
    let fresh = fresh.clone();
    let again = request.try_clone();
    Box::pin(async move {
        let started = Instant::now();
        let error = match request.send().await {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        let Some(again) = again.filter(|_| never_reached(&error, started.elapsed())) else {
            return Err(error);
        };
        tracing::debug!(
            reason = "request_never_sent",
            "a request that never reached its provider goes once more on a fresh connection"
        );
        let (_, request) = again.build_split();
        fresh.execute(request?).await
    })
}

/// Whether the send that failed with `error`, `elapsed` after it began, never
/// reached its upstream: no connection was made, hyper never started the
/// request, or the connection closed with no reply byte inside
/// [`NEVER_READ_WINDOW`]. A timeout is the upstream's own.
fn never_reached(error: &reqwest::Error, elapsed: Duration) -> bool {
    if error.is_timeout() {
        return false;
    }
    if error.is_connect() {
        return true;
    }
    let mut cause = error.source();
    while let Some(inner) = cause {
        if let Some(hyper) = inner.downcast_ref::<hyper::Error>() {
            return hyper.is_canceled()
                || (hyper.is_incomplete_message() && elapsed < NEVER_READ_WINDOW);
        }
        cause = inner.source();
    }
    false
}
