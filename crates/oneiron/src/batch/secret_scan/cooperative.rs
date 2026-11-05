//! Retain one native read stack while its async owner yields or cancels.
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::task::Poll;

use crate::error::{Error, Result};
use oneiron_store::batch::secret_scan::container::{
    ReadCancelled, ReadPacer, ReadPacing, ReadProgress,
};

struct NativeRead {
    checkpoints: tokio::sync::mpsc::UnboundedSender<ReadProgress>,
    resume: Mutex<mpsc::Receiver<()>>,
    cancelled: AtomicBool,
}

impl ReadPacer for NativeRead {
    fn checkpoint(&self, at: ReadProgress) -> std::result::Result<(), ReadCancelled> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(ReadCancelled);
        }
        let resumed = self.checkpoints.send(at).is_ok()
            && self
                .resume
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv()
                .is_ok();
        if resumed {
            Ok(())
        } else {
            self.cancelled.store(true, Ordering::Relaxed);
            Err(ReadCancelled)
        }
    }
}

/// The cursor owns both handshake ends on the async side. Dropping it closes
/// them, so a parked worker wakes and unwinds its own parser/reader/transaction.
/// It never moves a borrowed transaction or reparses a completed prefix.
struct ReadContinuation<T> {
    checkpoints: tokio::sync::mpsc::UnboundedReceiver<ReadProgress>,
    resume: mpsc::Sender<()>,
    worker: tokio::task::JoinHandle<Result<T>>,
}

impl<T> ReadContinuation<T> {
    async fn complete(mut self) -> Result<T> {
        loop {
            let completed = std::future::poll_fn(|cx| {
                if let Poll::Ready(result) = Pin::new(&mut self.worker).poll(cx) {
                    return Poll::Ready(Some(result));
                }
                match self.checkpoints.poll_recv(cx) {
                    Poll::Ready(Some(_at)) => Poll::Ready(None),
                    Poll::Ready(None) | Poll::Pending => Poll::Pending,
                }
            })
            .await;
            if let Some(result) = completed {
                return result
                    .map_err(|_| Error::InvariantViolation("cooperative read worker failed"))?;
            }
            // Use the executor's real work budget, not an invented wall deadline.
            tokio::task::coop::consume_budget().await;
            let _ = self.resume.send(());
        }
    }
}

/// Run one owned native read on a blocking worker. Every native checkpoint
/// resumes the same stack after the async owner consumes its executor budget.
/// Dropping the future closes both handshake ends; a parked worker wakes and
/// cancels at its next checkpoint. Opaque codec units are not preempted.
/// A final checkpoint prevents a swallowed local cancellation from returning
/// a successful value. The closure creates and drops its own borrowed state.
pub async fn read_cooperatively<T: Send + 'static>(
    read: impl FnOnce(ReadPacing) -> T + Send + 'static,
) -> Result<T> {
    let (checkpoint_tx, checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let pacing = ReadPacing::new(Arc::new(NativeRead {
        checkpoints: checkpoint_tx,
        resume: Mutex::new(resume_rx),
        cancelled: AtomicBool::new(false),
    }));
    let worker = tokio::task::spawn_blocking(move || {
        let value = read(pacing.clone());
        pacing
            .checkpoint(ReadProgress::Complete)
            .map_err(oneiron_store::batch::secret_scan::container::withheld)?;
        Ok(value)
    });
    ReadContinuation {
        checkpoints: checkpoint_rx,
        resume: resume_tx,
        worker,
    }
    .complete()
    .await
}
