//! A door's invocation claim held through a streamed reply (FIX 2004): the
//! reply is saved for each duplicate once the stream's producer ends, as
//! [`finish_door_claim`] saves a route's reply.

use super::*;

/// Holds `claim` until the producer behind a streamed reply sends its
/// outcome on `ended`, then saves the reply `reply` makes of it for each
/// request waiting on the claim, as [`finish_door_claim`] saves a route's
/// reply; a producer that stopped with no outcome gives `None`. The outcome
/// goes on to the stream through the returned receiver. The claim lives
/// with the producer, not with the stream's body: a client that goes away
/// leaves it held until the producer ends, and a duplicate gets the reply
/// within its own wait ([`claim_door_invocation`]).
pub(crate) fn finish_streamed_claim<T: Send + 'static>(
    claim: InvocationClaim,
    ended: tokio::sync::oneshot::Receiver<T>,
    reply: impl FnOnce(Option<&T>) -> Response + Send + 'static,
) -> tokio::sync::oneshot::Receiver<T> {
    let (forward, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let ended = ended.await.ok();
        let response = reply(ended.as_ref());
        // A stream whose client went away takes nothing; the reply is
        // saved all the same.
        match ended {
            Some(ended) => {
                let _ = forward.send(ended);
            }
            None => drop(forward),
        }
        let _ = finish_door_claim(claim, response).await;
    });
    forwarded
}
