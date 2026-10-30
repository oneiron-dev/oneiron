//! Fan-out width checks and held-attempt settlement.
//! Entry: `record_ask_check_in`.
//! Stored launch vocabulary stays in `fanout_launch`.

use super::*;

/// The width check an ungated wave apply asked, beside the cut it landed.
pub(in crate::task_verb) struct WaveCheck<'a> {
    pub(in crate::task_verb) actor: EntityId,
    pub(in crate::task_verb) actor_class: EdgeActorClass,
    pub(in crate::task_verb) cut: &'a ValidatedWavePlan,
    pub(in crate::task_verb) origin: Option<&'a TaskCreateOrigin>,
    pub(in crate::task_verb) statement: &'a FanoutStatement,
    pub(in crate::task_verb) writes: &'a [WaveTaskWrite],
    pub(in crate::task_verb) now: u64,
}

/// Records the durable row an ungated wave apply's asked width check names,
/// in the apply's transaction, for the owner to acknowledge.
pub(in crate::task_verb) fn record_wave_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: WaveCheck<'_>,
) -> MemoryResult<()> {
    record_dispatched_check_in(
        vault,
        txn,
        DispatchedCheck {
            launch_ref: wave_launch_ref(check.actor, check.cut.plan_ref())?,
            actor: check.actor,
            actor_class: check.actor_class,
            payload: LaunchPayload::wave(check.cut, check.origin),
            statement: check.statement,
            scope: wave_scope(check.actor, check.cut.epic_task_ref()),
            task_refs: check.writes.iter().map(|write| write.task_ref).collect(),
            now: check.now,
        },
    )
}

/// The width check an ask admitted at once asked, beside its census.
pub(in crate::task_verb) struct AskCheck<'a> {
    pub(in crate::task_verb) group_ref: EntityId,
    pub(in crate::task_verb) actor: EntityId,
    pub(in crate::task_verb) actor_class: EdgeActorClass,
    pub(in crate::task_verb) request_digest: &'a str,
    pub(in crate::task_verb) question: String,
    pub(in crate::task_verb) recipients: &'a [EntityId],
    pub(in crate::task_verb) task_refs: Vec<EntityId>,
    pub(in crate::task_verb) statement: &'a FanoutStatement,
    pub(in crate::task_verb) scope: String,
    pub(in crate::task_verb) now: u64,
}

/// Records the durable row an ask's asked width check names, in the ask's
/// admission transaction, for the owner to acknowledge. It touches no
/// member TASK.
pub(in crate::task_verb) fn record_ask_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: AskCheck<'_>,
) -> MemoryResult<()> {
    record_dispatched_check_in(
        vault,
        txn,
        DispatchedCheck {
            launch_ref: check.group_ref,
            actor: check.actor,
            actor_class: check.actor_class,
            payload: LaunchPayload::AdmittedAsk {
                group_ref: check.group_ref,
                request_digest: check.request_digest.to_owned(),
                question: check.question,
                recipients: check.recipients.to_vec(),
            },
            statement: check.statement,
            scope: check.scope,
            task_refs: check.task_refs,
            now: check.now,
        },
    )
}

pub(super) struct DispatchedCheck<'a> {
    pub(super) launch_ref: EntityId,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) payload: LaunchPayload,
    pub(super) statement: &'a FanoutStatement,
    pub(super) scope: String,
    pub(super) task_refs: Vec<EntityId>,
    pub(super) now: u64,
}

/// A launch that went out with its width check asked. A launch already
/// recorded for the same payload keeps its rows and is marked launched; one
/// recorded for another payload is refused.
pub(super) fn record_dispatched_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: DispatchedCheck<'_>,
) -> MemoryResult<()> {
    let mut launch = match load_launch(vault, txn, check.launch_ref)? {
        Some(launch) if launch.payload != check.payload => return Err(reused_cut()),
        Some(launch) => launch,
        None => {
            let governed = policy_in(vault, txn, &ConsultFanOutScope::default())?;
            let plan = check
                .payload
                .plan(check.launch_ref, check.actor, governed.policy.mode)?;
            StoredLaunch {
                launch_ref: check.launch_ref,
                actor: TaskActor::Actor(check.actor),
                actor_class: check.actor_class as u8,
                approval_project: None,
                payload: check.payload,
                estimate: fanout_estimate(&plan)?,
                plan,
                statement: check.statement.clone(),
                policy_scope: ConsultFanOutScope::default(),
                scope: check.scope,
                pause: None,
                check_row: None,
                held_attempts: Vec::new(),
                dispatched_at: None,
                task_refs: Vec::new(),
                denied: false,
                choice_receipt_ref: None,
                shipped_policy_rows: governed.shipped_rows,
                requester: None,
            }
        }
    };
    if launch.check_row.is_none() {
        let mut row = fanout_width_check_row(
            &launch.plan,
            launch.check_row_ref(),
            check.now.saturating_mul(1000),
        )?;
        row.statement = Some(check.statement.clone());
        launch.check_row = Some(row);
    }
    if launch.dispatched_at.is_none() {
        launch.dispatched_at = Some(vault.now_recorded_at());
        launch.task_refs = check.task_refs;
    }
    save_launch(vault, txn, &launch)?;
    Ok(())
}

/// Re-leases and completes each planning attempt still parked under this
/// launch's hold, through the ordinary resume intervention, in the
/// approval's transaction. A row a person resumed or cancelled since is
/// theirs and stays as it is: a resumed one finds the cut landed and
/// completes on its own next apply.
pub(super) fn settle_held_attempts_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &StoredLaunch,
    owner_actor: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let queue = AttemptQueue::new(vault);
    for id in &launch.held_attempts {
        let Some(record) = queue.get_in_write_txn(txn, *id)? else {
            continue;
        };
        if !record.fanout_hold_for(launch.launch_ref) {
            continue;
        }
        queue.intervene_in_txn(
            txn,
            InterveneAttempt {
                id: *id,
                kind: AttemptInterventionKind::Resume,
                actor: format!("owner:{}", owner_actor.to_hex()),
                note: Some(format!(
                    "fanout launch {} approved",
                    launch.launch_ref.to_hex()
                )),
                now,
            },
        )?;
        let ClaimOutcome::Claimed(leased) = queue.claim_id_in_txn(
            txn,
            *id,
            ClaimAttempt {
                lease_owner: FANOUT_LAUNCH_LEASE_OWNER.to_owned(),
                now,
            },
        )?
        else {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "the held planning attempt could not be re-leased",
                "Retry the approval.",
            ));
        };
        queue.complete_in_txn(
            txn,
            CompleteAttempt {
                id: *id,
                lease_owner: FANOUT_LAUNCH_LEASE_OWNER.to_owned(),
                attempt_count: leased.attempt_count,
                now,
            },
        )?;
    }
    Ok(())
}
