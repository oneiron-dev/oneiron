//! A connection's drain at its host's mesh stop (FIX 4756). Once the stop
//! begins, the service admits no new model call, and each connection serves
//! on until the calls it admitted have ended, the streams they started
//! included, or until the stop's one deadline comes; then what still runs
//! is cancelled. Each task keeps its staging charge until it ends. A stream
//! its asker no longer pulls holds the drain for [`UNPULLED_GRACE`] only
//! (FIX 11165).

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use oneiron_mesh_transport::{MeshConnection, MeshError, MeshStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::{Session, lock};

/// What a stopping node answers a new call.
pub(super) const STOPPING: &str = "this node is stopping";

/// How long after its start or its last pull a stream with no pull under
/// way holds a stopping connection's drain (FIX 11165).
const UNPULLED_GRACE: Duration = Duration::from_secs(2);

/// Whether the host's stop has begun.
pub(super) fn stopping(stop: Option<&watch::Receiver<Option<Instant>>>) -> bool {
    stop.is_some_and(|stop| stop.borrow().is_some())
}

/// One connection's place in its service's stop: none while the service
/// serves; once its host stops, the deadline its admitted calls drain by.
pub(super) struct Stop(Option<watch::Receiver<Option<Instant>>>);

impl Stop {
    pub(super) fn new(stop: Option<watch::Receiver<Option<Instant>>>) -> Self {
        Self(stop)
    }

    /// Whether the connection ends now: the stop has begun, and it is
    /// `idle`, every call it admitted ended, or the deadline has come.
    pub(super) fn ends(&self, idle: bool) -> bool {
        let deadline = self.0.as_ref().and_then(|stop| *stop.borrow());
        deadline.is_some_and(|deadline| idle || Instant::now() >= deadline)
    }

    /// Once the stop has begun, cancels each of `session`'s streams with no
    /// pull under way and none since [`UNPULLED_GRACE`], and returns when the
    /// next of the others would be; `None` before the stop, or with none.
    pub(super) fn cancel_unpulled(&self, session: &Session) -> Option<Instant> {
        if !stopping(self.0.as_ref()) {
            return None;
        }
        let now = Instant::now();
        let mut streams = lock(&session.streams);
        streams.retain(|_, held| !idle(held) || now < held.pulled + UNPULLED_GRACE);
        streams
            .values()
            .filter(|held| idle(held))
            .map(|held| held.pulled + UNPULLED_GRACE)
            .min()
    }

    /// Returns once the stop moves on: it begins, or its deadline comes.
    /// Never, for a service no host stops.
    async fn moved(&mut self) {
        let Some(stop) = &mut self.0 else {
            return std::future::pending().await;
        };
        let begun = *stop.borrow_and_update();
        match begun {
            Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
            // A host gone without a stop never stops this one.
            None => {
                if stop.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// Whether no pull is under way on `held`: a pull holds its own handle to
/// the stream.
fn idle(held: &super::Held) -> bool {
    Arc::strong_count(&held.running) == 1
}

/// What a connection's loop goes on with.
pub(super) enum Next {
    /// The peer opened a stream, or the connection closed.
    Stream(Result<Box<dyn MeshStream>, MeshError>),
    /// A task ended, or the stop moved on.
    Again,
}

/// Waits for the next of: the stop moving on or `recheck` coming, a task
/// ending, the peer opening a stream. The first two come first when they
/// are ready at once.
pub(super) async fn next(
    conn: &dyn MeshConnection,
    tasks: &mut JoinSet<()>,
    stop: &mut Stop,
    recheck: Option<Instant>,
) -> Next {
    let mut moved = pin!(stop.moved());
    let mut rechecked = pin!(async move {
        match recheck {
            Some(at) => tokio::time::sleep_until(at.into()).await,
            None => std::future::pending().await,
        }
    });
    let mut accepted = pin!(conn.accept_stream());
    std::future::poll_fn(|cx| {
        if moved.as_mut().poll(cx).is_ready() || rechecked.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Next::Again);
        }
        if !tasks.is_empty() && matches!(tasks.poll_join_next(cx), Poll::Ready(Some(_))) {
            return Poll::Ready(Next::Again);
        }
        accepted.as_mut().poll(cx).map(Next::Stream)
    })
    .await
}
