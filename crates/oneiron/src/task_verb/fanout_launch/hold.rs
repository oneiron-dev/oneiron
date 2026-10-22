//! Held fan-out ask admission and release records.
//! Entry: `hold_ask_in`.
//! Stored launch vocabulary stays in `fanout_launch`.

use super::*;

/// ASK-3: whether an ask waits for its launch approval. Only the `manual`
/// approval mode holds an ask, and an ask whose every recipient is a
/// principal who would answer that approval, a live vault owner or a live
/// holder of `approval_project`'s lead or board, goes straight out: holding
/// it would ask the approver to approve asking them.
pub(in crate::task_verb) fn ask_launch_needs_approval(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recipients: &[EntityId],
    approval_project: Option<EntityId>,
) -> MemoryResult<bool> {
    if policy_in(vault, txn, &ConsultFanOutScope::default())?
        .policy
        .mode
        != ConsultFanOutMode::Manual
    {
        return Ok(false);
    }
    Ok(!recipients_approve_launch_in(
        vault,
        txn,
        recipients,
        approval_project,
    )?)
}

/// Whether every one of `recipients` is a principal who would answer the
/// ask's launch approval: a live vault owner, or a live holder of
/// `approval_project`'s lead or board. Such an ask is never held, in any
/// mode: holding it would ask the approver to approve asking them.
pub(in crate::task_verb) fn recipients_approve_launch_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recipients: &[EntityId],
    approval_project: Option<EntityId>,
) -> MemoryResult<bool> {
    let holders = launch_role_holders_in(vault, txn, approval_project)?;
    for recipient in recipients {
        let approver = (vault.get_entity_type_in_txn(txn, recipient)?
            == Some(crate::registry::ENTITY_TYPE_PERSON)
            && actor_is_vault_owner_in_txn(vault, txn, *recipient, EdgeActorClass::Human)?)
            || holders.iter().any(|holder| holder.actor == *recipient);
        if !approver {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The live holders of a launch's approval role beside the owner: the
/// current lead of `project`, then that project's own board, as the decision
/// ladder resolves them now. A parent's board and the owners are never
/// collected here; no project holds no one.
pub(super) fn launch_role_holders_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> MemoryResult<Vec<RoleHolder>> {
    let Some(project) = project else {
        return Ok(Vec::new());
    };
    let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
        return Ok(Vec::new());
    };
    let to = AskTo {
        role: AskRole::Responsible {
            actor: crate::llm::decision::AnswerActor::Actor(EntityId::from_hex(&effective.leader)?),
            project: Some(project),
        },
        ceiling: RoleRank::Board,
        act: AskAct::Judgment,
    };
    let board = AskRole::Board { project };
    let mut after: Option<AskRole> = None;
    let mut holders = Vec::new();
    while let Some(resolved) = vault.next_ask_role_in_txn(txn, &to, after.as_ref())? {
        if resolved.role == to.role {
            holders.extend(resolved.holders);
            after = Some(resolved.role);
        } else {
            // The project's own board ends the walk; a parent's board is
            // past it.
            if resolved.role == board {
                holders.extend(resolved.holders);
            }
            break;
        }
    }
    Ok(holders)
}

/// Whether `actor`, as `class`, is a live holder of the launch role bound to
/// `project`: a person as a human, a bound agent as an agent.
pub(super) fn launch_role_is_held_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    actor: EntityId,
    class: EdgeActorClass,
) -> MemoryResult<bool> {
    Ok(launch_role_holders_in(vault, txn, project)?
        .iter()
        .any(|holder| {
            holder.actor == actor
                && matches!(
                    (class, holder.kind),
                    (EdgeActorClass::Human, HolderKind::Person)
                        | (EdgeActorClass::Agent, HolderKind::Agent)
                )
        }))
}

/// The CALLS-row policy on a holder's launch ruling: a lead or board holder
/// approves once or denies; only the owner remembers a standing cap.
pub(super) fn require_holder_launch_choice(
    choice: ConsultFanOutChoice,
    remembered_cap: Option<u64>,
) -> MemoryResult<()> {
    if choice == ConsultFanOutChoice::ApproveAndRemember || remembered_cap.is_some() {
        return Err(consult_refusal(
            MEMORY_CODE_FORBIDDEN,
            "only the vault owner may remember a launch approval",
            "Approve once or deny; ask the owner to remember a cap.",
        ));
    }
    Ok(())
}

/// One ask the approval mode holds, as its admission froze it.
pub(in crate::task_verb) struct AskHold<'a> {
    pub(in crate::task_verb) group_ref: EntityId,
    /// The project whose lead and board may release it beside the owner.
    pub(in crate::task_verb) approval_project: Option<EntityId>,
    pub(in crate::task_verb) actor: EntityId,
    pub(in crate::task_verb) actor_class: EdgeActorClass,
    pub(in crate::task_verb) requested: &'a TaskAskSpec,
    pub(in crate::task_verb) effective: TaskAskSpec,
    pub(in crate::task_verb) holders: Vec<EntityId>,
    pub(in crate::task_verb) context_class: Option<TaskAskClass>,
    pub(in crate::task_verb) question_digest: [u8; 32],
    pub(in crate::task_verb) request_digest: &'a str,
    pub(in crate::task_verb) statement: FanoutStatement,
    pub(in crate::task_verb) scope: String,
    pub(in crate::task_verb) effect: Option<AskEffect>,
    pub(in crate::task_verb) now: u64,
}

/// Holds an ask for the owner's launch approval, in its admission
/// transaction: the whole request, census and composed effect are frozen
/// on a launch keyed by the ask's group, and the controller's pause row is
/// recorded. Nothing is minted. The receipt names the hold.
pub(in crate::task_verb) fn hold_ask_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    hold: AskHold<'_>,
) -> MemoryResult<TaskAskReceipt> {
    let governed = policy_in(vault, txn, &ConsultFanOutScope::default())?;
    let policy = &governed.policy;
    let payload = LaunchPayload::Ask {
        group_ref: hold.group_ref,
        requested: hold.requested.clone(),
        effective: hold.effective,
        holders: hold.holders,
        context_class: hold.context_class,
        question_digest: hold.question_digest,
        request_digest: hold.request_digest.to_owned(),
        created_at: hold.now,
        effect: hold.effect,
    };
    let plan = payload.plan(hold.group_ref, hold.actor, policy.mode)?;
    let mut launch = StoredLaunch {
        launch_ref: hold.group_ref,
        actor: TaskActor::Actor(hold.actor),
        actor_class: hold.actor_class as u8,
        approval_project: hold.approval_project,
        payload,
        estimate: fanout_estimate(&plan)?,
        plan: plan.clone(),
        statement: hold.statement,
        policy_scope: ConsultFanOutScope::default(),
        scope: hold.scope,
        pause: None,
        check_row: None,
        held_attempts: Vec::new(),
        dispatched_at: None,
        task_refs: Vec::new(),
        denied: false,
        choice_receipt_ref: None,
        shipped_policy_rows: governed.shipped_rows.clone(),
    };
    let admission = admit_fanout_with_history(
        &plan,
        Some(policy.approval_threshold),
        wave_launch_history(),
        &CachedAuto(FanoutAutoDisposition::SurfaceHuman),
        &mut LaunchSurface {
            vault,
            txn,
            launch: &mut launch,
            clearance: None,
        },
        hold.now.saturating_mul(1000),
    )?;
    let FanoutAdmission::Paused {
        estimate,
        surface_ref,
        ..
    } = admission
    else {
        return Err(Error::InvariantViolation("a held ask's approval mode did not hold it").into());
    };
    launch.estimate = estimate;
    record_hold_in(
        vault,
        txn,
        &mut launch,
        &surface_ref,
        policy.approval_threshold,
    )?;
    held_ask_receipt(&launch, false)
}

/// The receipt of an ask still held for its launch approval.
pub(super) fn held_ask_receipt(
    launch: &StoredLaunch,
    replay: bool,
) -> MemoryResult<TaskAskReceipt> {
    let pause = launch
        .pause
        .as_ref()
        .ok_or(Error::InvariantViolation("a held ask has no pause row"))?;
    Ok(TaskAskReceipt::new(
        TaskAskHandle {
            group_ref: launch.launch_ref,
        },
        Vec::new(),
        Some(TaskAskHoldReason::ApprovalRequired),
        replay,
        Some(launch.statement.clone()),
    )
    .with_launch(TaskAskLaunchHold {
        launch_ref: launch.launch_ref,
        plan_digest: bytes_to_hex_lower(&launch.estimate.plan_digest),
        surface_ref: pause.row_ref.clone(),
        denied: launch.denied,
    }))
}

/// The ask still held under `group_ref`, if one is.
pub(super) fn held_ask_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
) -> MemoryResult<Option<StoredLaunch>> {
    Ok(load_launch(vault, txn, group_ref)?.filter(|launch| {
        launch.dispatched_at.is_none() && matches!(launch.payload, LaunchPayload::Ask { .. })
    }))
}

/// A replay of a held ask: the same receipt, never a second hold. The same
/// intent key with other arguments, or from another actor, is refused.
pub(in crate::task_verb) fn held_ask_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
    actor: EntityId,
    request_digest: &str,
) -> MemoryResult<Option<TaskAskReceipt>> {
    let Some(launch) = held_ask_in(vault, txn, group_ref)? else {
        return Ok(None);
    };
    let LaunchPayload::Ask {
        request_digest: frozen,
        ..
    } = &launch.payload
    else {
        return Ok(None);
    };
    if !launch.actor.is(actor) || frozen != request_digest {
        return Err(MemoryError::bad_request(
            "ask intent key was used for different arguments",
        ));
    }
    held_ask_receipt(&launch, true).map(Some)
}

/// The asker of the ask still held under `group_ref`, if one is: status and
/// wait read a held ask before they fail an unknown group.
pub(in crate::task_verb) fn held_ask_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
) -> MemoryResult<Option<EntityId>> {
    Ok(held_ask_in(vault, txn, group_ref)?.and_then(|launch| launch.actor.id()))
}

/// A held ask as its approval releases it.
pub(in crate::task_verb) struct ReleasedAsk<'a> {
    pub(in crate::task_verb) requested: &'a TaskAskSpec,
    pub(in crate::task_verb) holders: &'a [EntityId],
    pub(in crate::task_verb) context_class: &'a Option<TaskAskClass>,
    pub(in crate::task_verb) question_digest: [u8; 32],
    pub(in crate::task_verb) request_digest: &'a str,
    pub(in crate::task_verb) statement: &'a FanoutStatement,
}

/// Parks the planning attempt a held launch waits on, in the writer that
/// recorded the hold, and remembers it for the approval to re-lease.
pub(in crate::task_verb) fn hold_planning_attempt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &mut StoredLaunch,
    attempt: &AttemptRecord,
    now: u64,
) -> MemoryResult<()> {
    let lease_owner = attempt
        .lease_owner
        .clone()
        .ok_or_else(|| MemoryError::bad_request("wave planner lease has no owner"))?;
    AttemptQueue::new(vault).hold_for_fanout_in_txn(
        txn,
        HoldAttemptForFanout {
            id: attempt.id,
            lease_owner,
            attempt_count: attempt.attempt_count,
            launch_ref: launch.launch_ref,
            resume_point: AttemptResumePoint::new(
                format!("fanout_launch:{}", launch.launch_ref.to_hex()),
                now,
            ),
            now,
        },
    )?;
    if !launch.held_attempts.contains(&attempt.id) {
        launch.held_attempts.push(attempt.id);
    }
    save_launch(vault, txn, launch)?;
    Ok(())
}

/// Marks a launch landed with the TASKs its cut minted. A replayed landing
/// keeps the first stamp.
pub(in crate::task_verb) fn mark_launched_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &mut StoredLaunch,
    writes: &[WaveTaskWrite],
) -> MemoryResult<()> {
    if launch.dispatched_at.is_some() {
        return Ok(());
    }
    launch.dispatched_at = Some(vault.now_recorded_at());
    launch.task_refs = writes.iter().map(|write| write.task_ref).collect();
    save_launch(vault, txn, launch)?;
    Ok(())
}
