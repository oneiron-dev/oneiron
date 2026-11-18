//! The job that advances a due check-in (ARCH-0082 #waits and "When nobody
//! answers"; ROLES-CHECKIN P2.3, piece 2e).
//!
//! The engine keeps no timer of its own (`housekeeping`): each open pending
//! check-in arms one row of [`CHECK_IN_DUE_JOB`] at its next due time, in the
//! write that stores it (`store_pending_in_txn`), and the schedule's runner
//! runs the rows due, in due order, each one transition a pass
//! ([`advance_pending_check_in_in_txn`]). The asker's `until` lets the ask
//! go, a delay window's end settles it, and a rung whose wait is over climbs,
//! or past the last rung canon's table "When nobody answers" settles it. The
//! job wakes its host, so a stopped vault wakes at the first due row
//! ([`Vault::housekeeping_wake_at`]; DESIGN 15-setting-primitive, stage 5b).
//!
//! The rows are durable and every pass reads them afresh, so a restart loses
//! nothing. A late pass delays a climb and never skips a rung: each rung's
//! wait starts when the ask enters it. A rung whose pinned people have all
//! lost the power ends early only when a call reads it (an answer, or the
//! inquiry's repeat); the pass reaches it at its due time.
//!
//! Each row advances in its own write, so one row's error leaves the others
//! to advance, and the row is tried again after the runner's backoff. An
//! agent holder's verdict has no producer yet: [`NoAgentVerdict`] passes the
//! ask up, which fails closed (canon #modes: "Unsure, refusal or error: ask").

use super::chain::{NoAgentVerdict, VerifiedChain};
use super::pending::pending_check_in_in_txn;
use super::waits::advance_pending_check_in_in_txn;
use crate::Vault;
use crate::error::Result;
use crate::schedule::{
    ArmBy, Armed, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran, When,
};

/// Each open pending check-in's next transition: a one-time row about the
/// check-in, armed at its next due time in every write of it. A run makes
/// the one transition due and answers the row's next due time, at which the
/// row stays armed; a final row disarms it in the same write.
pub(crate) static CHECK_IN_DUE_JOB: JobSpec = JobSpec {
    code: "check_in.due",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: true,
    at_open: false,
    once_per_pass: true,
    runs_here: crate::schedule::any_node,
    run: run_check_in_due,
};

/// Makes the transition due now for the check-in `armed` is about, in one
/// write, and answers its next due time: `None` once it is final or gone.
/// A row not due yet (a run asked for early) is left as it is.
fn run_check_in_due(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    let Some(id) = armed.subject else {
        return Ok(JobResult::of(Ran::Done));
    };
    let chain = VerifiedChain::new(&NoAgentVerdict);
    let due_by = vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let due =
            pending_check_in_in_txn(&vault.store, txn, &id)?.and_then(|row| row.next_due_at());
        if due.is_none_or(|at| at > now) {
            return Ok(due);
        }
        advance_pending_check_in_in_txn(vault, txn, &id, &chain, now)?;
        Ok(pending_check_in_in_txn(&vault.store, txn, &id)?.and_then(|row| row.next_due_at()))
    })?;
    Ok(JobResult {
        due_by,
        ..JobResult::of(Ran::Done)
    })
}

/// Every open pending check-in's armed due time, in due order: the test
/// door's view of the index.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn due_rows(vault: &Vault) -> Result<Vec<(u64, crate::entity_id::EntityId)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = crate::schedule::deadlines_in_txn(
        &vault.store,
        &rtxn,
        CHECK_IN_DUE_JOB.code,
        u64::MAX,
        usize::MAX,
    )?
    .into_iter()
    .map(|(id, at)| (at, id))
    .collect::<Vec<_>>();
    rows.sort_unstable();
    Ok(rows)
}
