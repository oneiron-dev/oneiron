//! Doors for `tests/verb_vault_research_advance.rs` (LEARNING-09): seed one
//! research continuation at a chosen task list, as an earlier pass or a
//! selection round leaves it, so a host pass starts at that task without
//! first running the experimenter's and scorer's agents; and take one pass
//! step on a row as a caller read it, so a test can run a pass that read the
//! row before another pass moved it.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::research::{
    ResearchContinuation, ResearchTask, ResearchWork, seed_research_continuation,
    step_research_continuation,
};
use crate::error::Result;

/// Puts `root`'s continuation for `work`, open, with `pending` to run.
/// Refuses a key that already holds one.
pub fn seed_continuation(
    vault: &Vault,
    root: AttemptId,
    work: ResearchWork,
    pending: Vec<ResearchTask>,
    now: u64,
) -> Result<()> {
    seed_research_continuation(vault, root, work, pending, now)
}

/// One pass step of `root`'s campaign on `row` as the caller read it: what a
/// pass that read `row` takes next, with no failure handling and no further
/// step. A row another pass moved since refuses with `ConcurrentWrite`.
pub fn step(vault: &Vault, root: AttemptId, row: &ResearchContinuation, now: u64) -> Result<()> {
    step_research_continuation(vault, root, row, now)
}
