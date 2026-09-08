//! TASKS section projections — intent rows, realizing jobs, and the
//! render-tier ack/cancel state helpers behind the `tasks.*` verb surface.
//!
//! Ack and cancel state is READ from, and WRITTEN as, the TASK's replicated
//! authority facts (`task_authority`). The UI tier never parses a fact body or
//! walks an edge: it reads these two bits and the stable
//! `TaskIntentPresence.acked` lens, exactly as it did when they were
//! node-local `vault_meta` rows.

mod authority_state;
mod projection;
mod render;

pub use self::projection::{
    CancelRejectionPathology, JobPresence, TaskBoardStatus, TaskIntentPresence, TaskRow,
    TasksSection, fold_up_status,
};
pub use self::render::{expand_task, failed_lane, render_tasks_section};

pub(crate) use self::authority_state::{
    ack_task_in_txn, cancel_task_in_txn, task_is_acked, task_is_cancelled,
};

#[cfg(test)]
mod tests;

// The flat tasks.rs module used to provide these names to the inline test
// module through `use super::*`: the TASKS items the tests name bare (via the
// child glob seam below) and the crate imports the old file header supplied.
// After the directory split the seam re-imports both so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use self::{authority_state::*, projection::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::consult_ladder::LadderTerminalDisposition;
#[cfg(test)]
use crate::outbound::ConnectorSendTask;
#[cfg(test)]
use crate::run_tree::RunTreeStatus;
#[cfg(test)]
use crate::task_verb::{ConsultResultPresence, TaskKind, TaskTerminalDisposition};
