//! Request-body feeds from HTTP streams to blocking transfer workers.

use super::*;

/// Feeds `body` to the worker in copied pieces of at most `max_piece` bytes,
/// then its clean end. A frame that does not arrive within `idle` ends the
/// body with `TimedOut`; a worker that stopped reading ends the feed quietly.
///
/// Only the wait for the client is timed: a full channel is the worker's
/// backpressure, and the worker bounds its own waits.
pub(in crate::api) fn feed_body(
    body: Body,
    pieces: mpsc::Sender<BodyPiece>,
    idle: Duration,
    max_piece: usize,
) -> impl std::future::Future<Output = ()> {
    // Capture before a caller spawns this future on a different task.
    let revocation = crate::http_listener::current_body_revocation();
    feed_pieces(body, pieces, Some(idle), max_piece, revocation, None, None)
}

/// [`feed_body`] with no wait of its own on the client: only the listener's
/// body policy ends a body that goes quiet, as it does for a body read in
/// memory (an owner route's spooled body, FIX 8195).
pub(in crate::api) async fn feed_body_untimed(
    body: Body,
    pieces: mpsc::Sender<BodyPiece>,
    max_piece: usize,
) {
    feed_pieces(body, pieces, None, max_piece, None, None, None).await;
}

/// Feeds a spool worker, ending its memory wait before enqueueing a failed input.
pub(in crate::api) fn feed_body_stoppable(
    body: Body,
    pieces: mpsc::Sender<BodyPiece>,
    idle: Option<Duration>,
    max_piece: usize,
    stopped: Arc<AtomicBool>,
    admitted: tokio::sync::oneshot::Receiver<Arc<RawSpoolMemory>>,
) -> impl std::future::Future<Output = ()> {
    let revocation = idle.and_then(|_| crate::http_listener::current_body_revocation());
    async move {
        feed_pieces(
            body,
            pieces,
            idle,
            max_piece,
            revocation,
            Some(stopped.as_ref()),
            Some(admitted),
        )
        .await;
    }
}

async fn feed_pieces(
    body: Body,
    pieces: mpsc::Sender<BodyPiece>,
    idle: Option<Duration>,
    max_piece: usize,
    revocation: Option<crate::http_listener::BodyRevocation>,
    stopped: Option<&AtomicBool>,
    mut admitted: Option<tokio::sync::oneshot::Receiver<Arc<RawSpoolMemory>>>,
) {
    let mut memory = None;
    let mut stream = body.into_data_stream();
    let stop_failed_feed = || {
        if let Some(stopped) = stopped {
            stopped.store(true, Ordering::Relaxed);
        }
    };
    loop {
        let next = match idle {
            Some(idle) => match crate::http_listener::body_read_timeout(
                revocation.as_ref(),
                idle,
                stream.next(),
            )
            .await
            {
                Some(next) => next,
                None => {
                    stop_failed_feed();
                    let _ = pieces
                        .send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body stalled",
                        )))
                        .await;
                    return;
                }
            },
            None => stream.next().await,
        };
        let frame = match next {
            Some(Ok(frame)) => frame,
            None => {
                let _ = pieces.send(Ok(None)).await;
                return;
            }
            Some(Err(error)) => {
                stop_failed_feed();
                let _ = pieces.send(Err(body_failure(error))).await;
                return;
            }
        };
        // Copied, never sliced: a slice would keep a hostile giant backing
        // allocation alive for every queued small piece.
        for piece in frame.chunks(max_piece) {
            if let Some(admitted) = admitted.take() {
                let Ok(admitted) = admitted.await else {
                    return;
                };
                memory = Some(admitted);
            }
            let piece = Bytes::copy_from_slice(piece);
            if let Some(memory) = memory.as_deref() {
                memory.materialized(piece.len() as u64);
            }
            if pieces.send(Ok(Some(piece))).await.is_err() {
                stop_failed_feed();
                return;
            }
        }
    }
}

/// A body that failed, as the worker reads it. A body the listener ended
/// for going quiet is a stall like one this feed times out itself.
fn body_failure(error: axum::Error) -> io::Error {
    let stalled = error
        .into_inner()
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut);
    if stalled {
        io::Error::new(io::ErrorKind::TimedOut, "request body stalled")
    } else {
        io::Error::other("request body failed")
    }
}
