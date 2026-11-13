//! Door for `tests/verb_vault_research_advance.rs` (LEARNING-09): seeds one
//! research continuation at a chosen task list, as an earlier pass or a
//! selection round leaves it, so a host pass starts at that task without
//! first running the experimenter's and scorer's agents.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::research::{
    ResearchTask, ResearchWork, seed_research_continuation,
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
