//! The queue's accepted-push candidate intake (FIX 6869, G4 PR2): the one
//! server port the checker's drain calls once a pass per enrolled store,
//! after the queue's own recovery and urgent steps. It opens nothing new:
//! the enrolled configuration proved this store, the queue's own rows give
//! its sealed green and Baseline, and matching creates Proposed work only.
use super::check_store::QueueCheckConfiguration;
use super::{MergeQueue, QueueSealTarget};
use crate::codebase::RepoRef;
use crate::error::Result;
use crate::git_wire::GitWire;
use crate::origin::CandidateQueue;

impl MergeQueue<'_> {
    /// Matches every retained received ref of this queue's store that has
    /// no resolved candidate yet, and answers how many durable transitions
    /// it wrote: an attachment or a changed hold. An unenrolled queue, or
    /// one with an unresolved landing or rollback intent, takes none; an
    /// unchanged hold counts nothing. Never enqueues, approves or moves a
    /// ref, and never changes a receive result.
    ///
    /// # Errors
    /// A store or object store failure reading the queue. One candidate's
    /// own failure is logged and leaves it pending.
    pub fn intake_received_code_candidates(&self) -> Result<usize> {
        let Some(config) = self
            .checker_configuration()?
            .filter(QueueCheckConfiguration::drives_queue)
        else {
            return Ok(0);
        };
        if self.queue()?.intent.is_some() {
            return Ok(0);
        }
        let RepoRef::LocalFolder { path, .. } = self.repo.repo_ref() else {
            return Ok(0);
        };
        let green = self.green_revision()?.ok().map(|green| green.revision);
        let baseline = self
            .seal_link(&config, &QueueSealTarget::Baseline)?
            .and_then(|link| link.sealed());
        let queue = CandidateQueue {
            folder: path.clone(),
            green,
            baseline,
        };
        let wire = GitWire::new(self.vault)?;
        let mut moved = 0_usize;
        for source in self
            .vault
            .pending_received_code_candidates(&self.repo.identity().as_hex())?
        {
            match self
                .vault
                .match_received_code_candidate(&wire, &self.repo, &queue, &source)
            {
                Ok(written) => moved += usize::from(written),
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a received push candidate did not match; it stays pending"
                    );
                }
            }
        }
        Ok(moved)
    }

    /// What this queue's intake knows of its own store, read as the drain
    /// reads it: its local folder, its sealed green and its sealed checked
    /// Baseline. `None` for a queue its checker does not drive. A pure
    /// read: an outside import resolves its exact base through it (FIX
    /// 6871).
    ///
    /// # Errors
    /// A store failure reading the queue.
    pub(crate) fn candidate_queue(&self) -> Result<Option<CandidateQueue>> {
        let Some(config) = self
            .checker_configuration()?
            .filter(QueueCheckConfiguration::drives_queue)
        else {
            return Ok(None);
        };
        let RepoRef::LocalFolder { path, .. } = self.repo.repo_ref() else {
            return Ok(None);
        };
        let green = self.green_revision()?.ok().map(|green| green.revision);
        let baseline = self
            .seal_link(&config, &QueueSealTarget::Baseline)?
            .and_then(|link| link.sealed());
        Ok(Some(CandidateQueue {
            folder: path.clone(),
            green,
            baseline,
        }))
    }
}
