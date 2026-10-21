//! Which part of its parent's clock a reader job runs to (FIX 7507 PR3), and
//! the parent attempt lease a scoped child borrows.
//!
//! A parent's clock is one [`RunDeadline`], fixed at its first spawn: its
//! outer cutoff and the fold reserve kept back of it. A read child and a
//! scoped child stop at the reserve (its child cutoff); a summary is the fold
//! the reserve is kept for, so it runs to the outer cutoff. No time is made
//! up here, and no reserve is taken twice.

use crate::attempt_queue::BorrowedAttemptLease;
use crate::code_run::{ReaderJob, ReaderJobKind, ReaderParent, RunDeadline};

/// `reader_job_cutoff` (CALLS, open): when a job of `kind` stops under its
/// parent's `deadline`. A read and a scoped child stop at the child cutoff,
/// before the fold reserve; a summary job may spend that reserve, up to the
/// outer cutoff, and never past it.
pub(crate) fn reader_job_cutoff(kind: &ReaderJobKind, deadline: &RunDeadline) -> u64 {
    match kind {
        ReaderJobKind::Summarize { .. } => deadline.cutoff_unix_ms,
        ReaderJobKind::Read | ReaderJobKind::ScopedAgent { .. } => deadline.child_cutoff(),
    }
}

/// `reader_wait_cutoff` (CALLS, open): how long a wait over `jobs`, the
/// named jobs `parent` spawned itself, may last. The latest of their own
/// cutoffs, never past the parent's outer cutoff: a wait over reads ends at
/// the child cutoff as before, one over a summary may wait into the fold
/// reserve, and a mixed one waits for its last job while each read still
/// stops at its own cutoff. With no job of the parent's named, the child
/// cutoff, as before.
pub(crate) fn reader_wait_cutoff(parent: &ReaderParent, jobs: &[ReaderJob]) -> u64 {
    let outer = parent.deadline.cutoff_unix_ms;
    jobs.iter()
        .map(|job| job.binding.child_cutoff_unix_ms)
        .max()
        .map_or(parent.deadline.child_cutoff(), |latest| latest.min(outer))
}

impl ReaderJob {
    /// The parent attempt's lease this job borrowed, when it is a scoped
    /// child whose host lent one (FIX 7507). A read and a summary never
    /// borrow one: they outlive their spawner as before.
    #[must_use]
    pub fn scoped_parent_lease(&self) -> Option<&BorrowedAttemptLease> {
        self.scoped_spec().and(self.binding.parent_lease.as_ref())
    }
}
