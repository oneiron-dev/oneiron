//! A stream whose items an async producer pushes, polled in place. The
//! producer owns what the items come from (a rung's permit, and the stream
//! that borrows its lease) across awaits, which a hand-written stream state
//! could not hold. Nothing is spawned: dropping the stream drops the producer.
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::sync::mpsc::{Receiver, Sender, channel};

pub(super) struct Driven<T> {
    producer: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    items: Receiver<T>,
}

impl<T> Driven<T> {
    /// `produce` gets the sender and pushes items in order; the stream ends
    /// once it returns and every pushed item is read.
    pub(super) fn new<F, Fut>(produce: F) -> Self
    where
        F: FnOnce(Sender<T>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // One slot: the producer runs at most one item ahead of the reader.
        let (sender, items) = channel(1);
        Self {
            producer: Some(Box::pin(produce(sender))),
            items,
        }
    }
}

impl<T> Stream for Driven<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let this = self.get_mut();
        loop {
            if let Poll::Ready(item) = this.items.poll_recv(cx) {
                return Poll::Ready(item);
            }
            let Some(producer) = this.producer.as_mut() else {
                // Unreached: with the producer gone its sender is dropped,
                // so the receive above is ready.
                return Poll::Ready(None);
            };
            if producer.as_mut().poll(cx).is_pending() {
                // It may have pushed an item before it stopped.
                return this.items.poll_recv(cx);
            }
            // Done: its sender is dropped, and the receive drains what is left.
            this.producer = None;
        }
    }
}
