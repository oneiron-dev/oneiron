//! The mesh sync route's floor in its own pressure check (FIX 7737,
//! [`PoolPressure::mesh`]). A stream takes a place at once while one is
//! free; one that must wait in the floor's line raises the check for its
//! episode, and the check clears once nobody waits. Each stream counts from
//! its start until it closes, its upgrade included: every byte its peer
//! sends on it, under the MACHINE its connection proved, never a slip or
//! account key a request carries.
//!
//! Observation only: the floor, its line, the header timeout and the body
//! idle clock stay the listener's. Nothing here waits, cuts or refuses.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use oneiron::EntityId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::wire_telemetry::{
    BodyCredential, ObservedBody, ObservedSocket, PoolPressure, PressureCredentialKey, SocketHold,
    attach_body_credential, with_body_credential,
};

/// The streams the mesh sync route holds open at once, under the TCP
/// listener's connection floor, as a count of their own.
pub(super) struct MeshFloor {
    places: Arc<Semaphore>,
    bound: usize,
    pressure: Arc<PoolPressure>,
    waiting: Mutex<Waiting>,
}

#[derive(Default)]
struct Waiting {
    /// Streams waiting for a place now.
    count: usize,
    /// The latest episode: the latest time a first stream had to wait.
    episode: u64,
}

impl MeshFloor {
    pub(super) fn new(bound: usize, pressure: Arc<PoolPressure>) -> Arc<Self> {
        Arc::new(Self {
            places: Arc::new(Semaphore::new(bound)),
            bound,
            pressure,
            waiting: Mutex::default(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Waiting> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for one stream: at once when one is free, else in the
    /// floor's line, the check raised while it waits. `None` once the floor
    /// is closed.
    pub(super) async fn place(&self) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.places).try_acquire_owned() {
            Ok(place) => Some(place),
            Err(TryAcquireError::Closed) => None,
            Err(TryAcquireError::NoPermits) => {
                let _waiter = self.wait();
                Arc::clone(&self.places).acquire_owned().await.ok()
            }
        }
    }

    /// One more stream waits: the first of an episode raises the check.
    fn wait(&self) -> Waiter<'_> {
        let mut waiting = self.lock();
        waiting.count += 1;
        if waiting.count == 1 {
            waiting.episode += 1;
            self.pressure.raise(waiting.episode, self.bound as u64);
        }
        Waiter(self)
    }

    /// `stream`, counted in the check from now until it closes, and the
    /// handle its record's credential is attached through ([`keyed`]). The
    /// stream holds `place` until it closes, its upgrade included (FIX 11163).
    pub(super) fn observe<S>(
        &self,
        stream: S,
        place: OwnedSemaphorePermit,
    ) -> (CountedStream<S>, BodyCredential) {
        let socket = self.pressure.socket(SocketHold::Floor);
        let (body, credential) = socket.body();
        let counted = CountedStream {
            stream,
            body,
            _socket: socket,
            _place: place,
        };
        (counted, credential)
    }
}

/// One stream's wait for a place, until it gets one or stops waiting. The
/// last to go clears the check.
struct Waiter<'f>(&'f MeshFloor);

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let floor = self.0;
        let mut waiting = floor.lock();
        waiting.count = waiting.count.saturating_sub(1);
        if waiting.count == 0 {
            floor.pressure.drain(waiting.episode);
        }
    }
}

/// `serve`, run with its stream's record listed under `machine`, the
/// MACHINE its connection proved.
pub(super) fn keyed<F: Future>(
    credential: BodyCredential,
    machine: EntityId,
    serve: F,
) -> impl Future<Output = F::Output> {
    with_body_credential(Some(credential), async move {
        // Attached first: a request's own credential never replaces it.
        attach_body_credential(PressureCredentialKey::Machine {
            machine_id: machine.to_hex(),
        });
        serve.await
    })
}

/// A mesh stream whose peer's bytes count in the check as they arrive. It
/// goes with whoever holds the stream, the upgraded socket included, and
/// its record ends and its floor place frees when it is dropped.
pub(super) struct CountedStream<S> {
    stream: S,
    body: ObservedBody,
    _socket: ObservedSocket,
    _place: OwnedSemaphorePermit,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let read = Pin::new(&mut this.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = read {
            this.body.carried(buf.filled().len().saturating_sub(before));
        }
        read
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
