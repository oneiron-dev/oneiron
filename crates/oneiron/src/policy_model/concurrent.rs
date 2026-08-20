//! Running both planes' classify calls at once.
//!
//! When the owner plane and a hosted legal plane both need a safeguard-model
//! verdict about the SAME content, the two calls are independent: neither
//! answer feeds the other, they run against different documents, and they land
//! in different machinery. Issuing them one after the other would spend two
//! round trips of latency to learn what one round trip could tell us, so they
//! are issued together.
//!
//! The join below is written out rather than pulled from a runtime crate on
//! purpose: the engine's classify path is `async` but runtime-agnostic — it
//! never assumes a reactor, a spawner or a thread pool, and a single-task join
//! is the one concurrency primitive it needs. Polling both children from one
//! task is real concurrency for I/O-bound work: whichever call is ready first
//! makes progress without waiting on the other.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

/// Drives `left` and `right` concurrently within one task and returns both
/// outputs. Each child is polled until it completes and then left alone.
pub(crate) async fn join2<L, R>(left: L, right: R) -> (L::Output, R::Output)
where
    L: Future,
    R: Future,
{
    let mut left = pin!(left);
    let mut right = pin!(right);
    let mut left_output = None;
    let mut right_output = None;
    poll_fn(|cx| {
        if left_output.is_none()
            && let Poll::Ready(output) = left.as_mut().poll(cx)
        {
            left_output = Some(output);
        }
        if right_output.is_none()
            && let Poll::Ready(output) = right.as_mut().poll(cx)
        {
            right_output = Some(output);
        }
        if left_output.is_some() && right_output.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // Both are `Some`: the `poll_fn` above only completes once each has been
    // filled, and nothing else can take them.
    (
        left_output.expect("left future completed"),
        right_output.expect("right future completed"),
    )
}
