//! A consult whose body arrived before its ConsultAssignee fact (FIX 10697,
//! Engine ruling (a), 30 Oct 06:36).
//!
//! Sync can deliver a consult's TASK body before the fact that names its
//! parties. The body never grants standing, so until the fact lands nobody
//! may write the consult's execution facts, and its executor waits rather
//! than meets an unaddressed-write refusal. The wait is a code run's
//! ordinary durable park (`tasks.wait` on the consult): no lease is held
//! while it is parked and nothing polls. The fact's own put wakes it through
//! the hook every TASK row's put passes, local or replicated (OF-533's
//! [`super::deliver_task_result_in_txn`]), once the fact reads through its
//! TASK. The task status names the wait ([`CONSULT_ASSIGNEE_FACT_WAIT`]).
//! The consult's own deadline bounds it: a consult whose deadline passes
//! while it still waits expires through the ordinary consult expiry with the
//! cause [`CONSULT_ASSIGNEE_MISSING`], and that settlement wakes the parked
//! run too.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::code_run::{SelfDurableWait, SelfEffect, peer_result_wait};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::task_authority::{
    TaskAuthorityFactKind, TaskAuthorityFacts, decode_task_authority_fact_body,
    is_task_authority_fact_in,
};

use super::TaskAskWait;
use super::consult_result::TaskVerbBody;
use super::lifecycle_facade::body_executor;
use super::verb_kind::TaskKind;
use super::wire_decode::task_verb_body_in;

/// The wait a consult with no ConsultAssignee fact yet shows on its status.
pub(super) const CONSULT_ASSIGNEE_FACT_WAIT: &str = "consult_assignee_fact";
/// The lapse cause of a consult whose deadline passed before its
/// ConsultAssignee fact landed.
pub(super) const CONSULT_ASSIGNEE_MISSING: &str = "consult_assignee_missing";

/// Domain of a consult's assignee-fact wait id. Parts: the consult TASK.
const CONSULT_ASSIGNEE_WAIT_DOMAIN: &[u8] = b"oneiron.tasks.consult_assignee_wait.v1";

/// Whether `body`, read beside `facts`, is a consult still waiting for its
/// ConsultAssignee fact.
pub(super) fn waits_for_assignee_fact(body: &TaskVerbBody, facts: &TaskAuthorityFacts) -> bool {
    body.task_kind() == TaskKind::Consult && !facts.has_consult_party_fact()
}

/// [`waits_for_assignee_fact`] for `task`, its facts read in `txn` only
/// when it is a consult.
pub(super) fn waits_for_assignee_fact_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    body: &TaskVerbBody,
) -> Result<bool> {
    Ok(body.task_kind() == TaskKind::Consult
        && waits_for_assignee_fact(body, &vault.task_authority_facts_in(txn, task)?))
}

/// The park of a run waiting for `task`'s ConsultAssignee fact: its own wait
/// id, never the TASK's, which a delegator's run waits on for the result.
fn assignee_park(task: EntityId) -> Result<SelfDurableWait> {
    let mut wait = peer_result_wait(EntityId::derive(
        CONSULT_ASSIGNEE_WAIT_DOMAIN,
        &[task.as_bytes()],
    )?);
    wait.effect = SelfEffect::TasksWait;
    Ok(wait)
}

/// Answers every run parked on `task`'s assignee wait, in the caller's
/// write: the TASK, whether its fact stands now and its terminal
/// disposition when it settled. A run that parks later gets the same reply.
fn deliver_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    body: &TaskVerbBody,
    landed: bool,
) -> Result<()> {
    let reply = serde_json::json!({
        "task_ref": task,
        "wait": CONSULT_ASSIGNEE_FACT_WAIT,
        "landed": landed,
        "disposition": body.terminal().map(|terminal| terminal.disposition),
    });
    let now_ms = vault.store.clock.now_recorded_at().saturating_mul(1000);
    let wait = assignee_park(task)?.wait_id;
    crate::code_run::deliver_wait_in_txn(vault, txn, wait, &reply, now_ms).map(drop)
}

/// Wakes the runs parked on a consult's assignee wait, in the transaction
/// that puts `row`: a ConsultAssignee fact, once it reads through its TASK,
/// or the consult TASK itself once it is terminal. Any other row, or a
/// consult nobody waits on, delivers nothing, so every TASK row's put may
/// pass it here.
pub(super) fn wake_assignee_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: EntityId,
) -> Result<()> {
    let task = if is_task_authority_fact_in(&vault.store, txn, &row)? {
        let raw = vault.get_raw_in(txn, &row)?;
        let Some(fact) = raw
            .as_deref()
            .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..))
            .and_then(|body| decode_task_authority_fact_body(body).ok())
        else {
            return Ok(());
        };
        if fact.kind != TaskAuthorityFactKind::ConsultAssignee {
            return Ok(());
        }
        fact.task_ref
    } else {
        row
    };
    if !crate::code_run::has_parked_run_in_txn(vault, txn, assignee_park(task)?.wait_id)? {
        return Ok(());
    }
    let Some(body) = task_verb_body_in(vault, txn, task)? else {
        return Ok(());
    };
    // A fold that does not read wakes the run too: it reads the refusal.
    let landed = !vault
        .task_authority_facts_in(txn, task)
        .is_ok_and(|facts| waits_for_assignee_fact(&body, &facts));
    if landed || body.terminal().is_some() {
        deliver_in_txn(vault, txn, task, &body, landed)?;
    }
    Ok(())
}

impl Memory<'_> {
    /// `tasks.wait` on consult `task` from a code run, in the caller's
    /// verified write: the park on its assignee wait. `None` when `task`
    /// names no consult, or one the body addresses to another executor, so
    /// an ask's own wait goes on. Who may park is read from the body, which
    /// grants no standing: the run lands only once the fact proves it. A
    /// consult whose fact already stands, or that has settled, is answered
    /// before the park, so the run resumes at once.
    pub(super) fn consult_assignee_wait_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        task: EntityId,
    ) -> MemoryResult<Option<TaskAskWait>> {
        let Some(body) = task_verb_body_in(self.vault(), &*txn, task)? else {
            return Ok(None);
        };
        if body.task_kind() != TaskKind::Consult
            || !body_executor(&body).is_ok_and(|executor| executor == self.actor())
        {
            return Ok(None);
        }
        let landed = !waits_for_assignee_fact_in(self.vault(), &*txn, task, &body)?;
        if landed || body.terminal().is_some() {
            deliver_in_txn(self.vault(), txn, task, &body, landed)?;
        }
        Ok(Some(TaskAskWait::Park(assignee_park(task)?)))
    }
}
