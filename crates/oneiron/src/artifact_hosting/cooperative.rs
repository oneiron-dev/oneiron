//! One hosted read, retained on its native worker while the async owner yields.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};

use super::{ArtifactServedFile, ArtifactSnapshotSelector};
use crate::batch::secret_scan::ContainerReader;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
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
struct ReadContinuation {
    checkpoints: tokio::sync::mpsc::UnboundedReceiver<ReadProgress>,
    resume: mpsc::Sender<()>,
    worker: tokio::task::JoinHandle<Result<Option<ArtifactServedFile>>>,
}

impl ReadContinuation {
    async fn complete(mut self) -> Result<Option<ArtifactServedFile>> {
        while let Some(_at) = self.checkpoints.recv().await {
            // Use the executor's real work budget, not an invented wall deadline.
            tokio::task::coop::consume_budget().await;
            if self.resume.send(()).is_err() {
                break;
            }
        }
        self.worker
            .await
            .map_err(|_| Error::InvariantViolation("artifact read worker failed"))?
    }
}

impl Vault {
    /// Resolve the same authorized file as the synchronous door, off the async
    /// executor. Inline and file-backed masks cooperate at native checkpoints;
    /// retained repository projections keep their existing synchronous work.
    /// The owner receives one final answer, never partial bytes or a poll URL.
    /// There is no wall timeout or new content refusal. Dropping this future
    /// cancels at the next checkpoint; an opaque codec unit is not preempted.
    pub async fn resolve_authorized_artifact_file_cooperative(
        self: &Arc<Self>,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
        token: Option<&str>,
        principal: Option<EntityId>,
    ) -> Result<Option<ArtifactServedFile>> {
        let vault = Arc::clone(self);
        let artifact = artifact.to_owned();
        let path = path.to_owned();
        let token = token.map(str::to_owned);
        let (checkpoint_tx, checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let reader = ContainerReader {
            pacing: ReadPacing::new(Arc::new(NativeRead {
                checkpoints: checkpoint_tx,
                resume: Mutex::new(resume_rx),
                cancelled: AtomicBool::new(false),
            })),
        };
        let worker = tokio::task::spawn_blocking(move || {
            let result = vault.resolve_authorized_artifact_file_with_reader(
                &artifact,
                selector,
                &path,
                token.as_deref(),
                principal,
                &reader,
            );
            reader
                .pacing
                .checkpoint(ReadProgress::Complete)
                .map_err(oneiron_store::batch::secret_scan::container::withheld)?;
            result
        });
        ReadContinuation {
            checkpoints: checkpoint_rx,
            resume: resume_tx,
            worker,
        }
        .complete()
        .await
    }
}
