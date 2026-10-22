//! Typed, actor-bound verbs over the Context Board TASKS section.
//!
//! Directory module: declarations, re-exports, and the typed ask entry point.
//! Sibling files own each ask implementation and its existing admission rules.

mod ask_band;
mod ask_effect;
mod ask_facade;
mod ask_guest;
mod ask_limits;
mod ask_option_link;
mod ask_policy;
mod ask_preflight;
mod ask_record;
mod ask_settlement;
mod ask_soft_confirm;
pub(crate) use ask_soft_confirm::validate_dispatch as validate_ask_soft_confirm_dispatch;
mod ask_soft_confirm_delivery;
mod ask_soft_confirm_types;
mod ask_types;
mod ask_world_hold;
mod attendee_answer;
mod board_task;
mod comm_widen;
pub(crate) use board_task::board_task_for_id;
mod brief;
mod brief_history;
pub(crate) use brief_history::settled_brief_in;
mod browser_workflow;
mod checkout_facts;
mod code_consent_word;
pub(crate) use checkout_facts::CheckoutTaskAccess;
pub(crate) use code_consent_word::code_consent_word_in_txn;
mod consts;
pub(crate) use consts::TASK_EXTERNAL_ATTEMPT_KIND;
mod consult_fanout_admission;
mod consult_fanout_facade;
mod consult_fanout_resume;
mod consult_fanout_store;
mod consult_fanout_types;
mod consult_ladder_facade;
mod consult_party_backfill;
mod consult_payload;
mod consult_result;
mod create_facade;
mod create_origin;
pub(crate) use create_origin::message_dispatch_in_txn;
mod create_spec;
mod create_validation;
mod decision_port;
mod dormant_magistrate;
mod entity_delta_facade;
mod external_attempt;
pub(crate) use external_attempt::decode as decode_external_task_attempt;
mod fanout_check;
mod fanout_launch;
mod follow_up;
mod highway;
mod highway_accept;
mod highway_block;
mod highway_post;
mod highway_redo;
mod highway_report;
pub(crate) mod highway_runner;
mod highway_status;
mod highway_types;
mod lifecycle_facade;
mod lifecycle_receipt;
pub(crate) use lifecycle_receipt::{
    erase_in_txn as erase_lifecycle_receipts_in_txn, erase_lifecycle_actor_in_txn,
    task_lifecycle_receipts,
};
mod linear_store;
mod mirror_edit;
mod office_origin;
#[expect(
    unused_imports,
    reason = "L12-A's office fork transaction consumes it (FIX 3551)"
)]
pub(crate) use office_origin::office_fork_origin_in_txn;
mod owner_index;
mod policy_change_followup;
mod presence_diagnostics;
mod presence_pages;
mod presence_scan;
mod project_ask;
mod project_tradeoff;
mod proposal_create;
mod query_facade;
mod rate_limit;
mod reconciliation;
mod refusal;
mod report_journal;
pub(crate) use report_journal::{
    erase_in_txn as erase_report_journal_in_txn, erase_report_actor_in_txn,
};
pub mod revoke_lands;
mod room_thread;
mod route_receipts;
pub mod run_cancel;
pub mod run_control;
pub mod run_doors;
mod runner_done;
mod scheduling;
mod subproject;
mod symbol_lease;
mod task_actor;
pub use task_actor::TaskActor;
pub(crate) use task_actor::{erase_launch_actor_in_txn, erase_wait_actor_in_txn};
mod task_continuation;
mod terminal_state;
mod training_offer_ask;
mod training_swap_ask;
mod verb_kind;
mod wave_port;
mod wire_decode;
pub(crate) use project_tradeoff::{project_tradeoff_routed_in, task_created_at_in};
pub(crate) use training_offer_ask::{
    OFFER_QUESTION_TYPE, issue_training_offer_asks, offer_question_key, offer_question_text,
    reserved_offer_question_in, training_offer_ask_key, void_training_offer_asks_in,
};
pub(crate) use training_swap_ask::{
    SWAP_QUESTION_TYPE, is_training_swap_ask_intent, issue_training_swap_asks,
    pending_swap_question_in, swap_question_key, training_swap_ask_key, void_training_swap_asks_in,
};
pub use training_swap_ask::{SwapAskState, TrainingSwapAskView, training_swap_asks};
pub(crate) use wire_decode::{
    TaskBinding, done_task_evidence_in, leader_task_body_in, leader_task_brief_in, task_binding,
    task_is_blocked_in, task_stored_brief_in, task_text_with_source_in,
};
mod wire_encode;
mod world_privacy_wait;
pub use world_privacy_wait::{WorldPrivacyWaitResult, WorldPrivacyWaitStatus};
pub(crate) use world_privacy_wait::{
    deliver_world_privacy_wait_for_in_txn, deliver_world_privacy_wait_in_txn,
};

#[cfg(test)]
mod tests;

pub use consts::TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED;
pub use consult_fanout_types::{
    ConsultFanOutChoice, ConsultFanOutEstimate, ConsultFanOutMeter, ConsultFanOutMode,
    ConsultFanOutPause, ConsultFanOutPolicy, ConsultFanOutRate, ConsultFanOutScope, FanoutMeterRow,
};
pub use consult_ladder_facade::{
    CrossActorRoute, LadderTransitionReceipt, project_consult_ladder_state,
};
pub use consult_payload::{ConsultPayload, ConsultPayloadRef, ConsultRecovery};
pub use consult_result::{
    ConsultDigestRoute, ConsultExpiryReport, ConsultFanOutReceipt, ConsultFanOutSpec,
    ConsultMeasuredSpend, ConsultResultInput, ConsultResultKind, TaskResultReceipt,
};
pub use create_spec::{TaskCreateRateLimit, TaskCreateSpec};
pub use create_validation::check_task_label;
pub use dormant_magistrate::{
    apply_magistrate_verdict, decide_magistrate, decode_human_verdict, enqueue_magistrate,
    human_verdict_value, ladder_terminal_from_task_terminal, project_consult_task_to_a2a,
    record_magistrate_overturn,
};
pub use follow_up::{decode_consult_expiry_recovery, task_follow_up_dedupe_key};
pub use refusal::{SelfRefusalInput, SelfRefusalReceipt, TaskRefusalRecord};
pub(crate) use room_thread::{
    context_refs as room_thread_context_refs, open_thread_tasks_in as room_open_thread_tasks_in,
    task_ids_in as room_thread_task_ids_in, task_roster_in as room_thread_task_roster_in,
    thread_tasks as room_thread_tasks,
};
pub use route_receipts::{
    DEFAULT_TASK_CANCEL_MODE, TaskCancelMode, TaskCancelReceipt, TaskCancelTarget,
    TaskCreateReceipt, TaskDescription, TaskResultInput, TaskRouteLane, TaskRouteOutcome,
    TaskStartedReceipt, TaskUpdateReceipt,
};
pub use terminal_state::{
    ConsultResultPresence, ConsultResultSummary, TaskExecutionState, TaskTerminalDisposition,
    TaskTerminalRecord, board_status_for_disposition, merge_task_terminal_register,
};
pub use verb_kind::{TaskAssignee, TaskKind, TaskTtl};

pub use brief::{
    BriefConstraints, BriefContext, BriefIntent, BriefStamp, Care, ComposerStamp, Criterion,
    DoneMeans, EscalationRule, EscalationTrigger, PinnedPack, PinnedRef, QueueTaskBrief, SpawnPins,
    StoredBrief, TypeRef, WorkflowBinding, brief_digest,
};
pub(crate) use browser_workflow::erase_task_workflows_in_txn;
pub use browser_workflow::{
    TaskWorkflowAttempt, TaskWorkflowCheck, TaskWorkflowPin, TaskWorkflowReport,
    TaskWorkflowUnavailable, mark_task_workflow_started, record_task_workflow_outcome,
    task_run_done_means, task_workflow_binding, task_workflow_binding_in_txn,
};
pub use decision_port::TaskDecisions;
pub(crate) use highway_post::settle_task_proposal_in_txn;
pub use highway_types::{
    AttemptHandle, AttemptView, HostBinding, TaskAccept, TaskCall, TaskCallReceipt, TaskHandle,
    TaskLifecycleRecord, TaskOutcome, TaskPhase, TaskPost, TaskRedo, TaskReport, TaskReportBody,
    TaskStatusQuery, TaskStatusView, TaskVia, TaskWorkflowHandoff, TaskWorkflowOutcome,
    TaskWorkflowStatus,
};
pub use runner_done::{
    RunnerDoneAnswer, RunnerDoneQuestion, runner_done_question, runner_workflow_done_answer,
};

pub(crate) use create_validation::{
    completed_task_at_in_txn, reject_born_expired_task_deadline, reject_incoherent_task_terminal,
    settled_task_result_binding, task_human_assignee, task_is_terminal,
};
pub(crate) use rate_limit::task_create_owner;
pub(crate) use task_continuation::{
    FailedTaskContinuation, TaskContinuationOutcome, continue_failed_task_in_txn,
    task_settled_at_in,
};

/// The objectives a run realizing `task` confesses against (OF-544): its
/// brief's done-means question, each criterion that must hold, then each
/// that must not as `none of: <text>`. `None` for a TASK with no brief, or
/// a brief that names none.
pub fn task_confession_objectives(
    vault: &crate::Vault,
    task: crate::EntityId,
) -> crate::Result<Option<Vec<String>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(wire_decode::task_verb_body_in(vault, &txn, task)?
        .and_then(|body| body.brief)
        .map(|stored| stored.brief.confession_objectives())
        .filter(|objectives| !objectives.is_empty()))
}

/// What one TASK's own row says of how it stands for the work that waits on it (OF-418 L4):
/// how it settled, if it did, and its STUCK report (OF-220), while it is blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskImpactFacts {
    /// How the TASK settled; `None` while it is unfinished.
    pub(crate) terminal: Option<TaskTerminalDisposition>,
    /// When its executor reported STUCK and what it waits on, while it is blocked.
    pub(crate) stuck: Option<(u64, Vec<crate::EntityId>)>,
}

/// [`TaskImpactFacts`] of `task` at `txn`'s revision, from the one body every task door
/// decodes. `None` when the row is no typed TASK.
pub(crate) fn task_impact_facts_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: crate::EntityId,
) -> crate::Result<Option<TaskImpactFacts>> {
    let Some(body) = wire_decode::task_verb_body_in(vault, txn, task)? else {
        return Ok(None);
    };
    let terminal = body.terminal().map(|record| record.disposition);
    let stuck = match body.state {
        Some(TaskExecutionState::Blocked { since, on }) => Some((since, on)),
        _ => None,
    };
    Ok(Some(TaskImpactFacts { terminal, stuck }))
}

/// A terminal typed TASK cannot be newly bound to a room thread.
pub(crate) fn thread_task_is_open_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: crate::EntityId,
) -> crate::Result<bool> {
    let body =
        wire_decode::task_verb_body_in(vault, txn, task)?.ok_or(crate::Error::EntityNotFound)?;
    if body.terminal().is_some()
        || body
            .ttl
            .is_some_and(|ttl| ttl.deadline_at <= vault.store.clock.now_recorded_at())
        || vault
            .task_authority_state_in(txn, task)?
            .is_none_or(|state| state.cancelled)
    {
        return Ok(false);
    }
    if let Some(consult) = &body.consult
        && let Some(group) = ask_record::read_group(vault, txn, consult.correlation_ref)?
        && group
            .members
            .iter()
            .any(|member| member.task == task.to_hex())
        && ask_settlement::read_result(vault, txn, consult.correlation_ref)?.is_some()
    {
        return Ok(false);
    }
    Ok(true)
}

/// Stored execution holder of a live typed TASK, if one exists.
pub(crate) fn open_thread_task_holder_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: crate::EntityId,
    fallback: crate::gate::TaskHolderFallback,
) -> crate::Result<Option<crate::EntityId>> {
    let body =
        wire_decode::task_verb_body_in(vault, txn, task)?.ok_or(crate::Error::EntityNotFound)?;
    if !thread_task_is_open_in(vault, txn, task)? {
        return Ok(None);
    }
    match body.assignee.and_then(TaskAssignee::entity_ref) {
        Some(holder) => Ok(Some(holder)),
        None => match fallback {
            crate::gate::TaskHolderFallback::AssigneeThenOwner => {
                Ok(Some(crate::EntityId::from_hex(&body.owner_ref)?))
            }
            crate::gate::TaskHolderFallback::AssigneeOnly => Ok(None),
        },
    }
}

/// The PERSON a typed TASK is assigned to as a human, in the caller's
/// snapshot: [`task_human_assignee`] for a reader that already holds one.
/// `None` for any other assignee, for none, and for a row that is no typed
/// TASK.
pub(crate) fn task_human_assignee_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: crate::EntityId,
) -> crate::Result<Option<crate::EntityId>> {
    Ok(
        wire_decode::task_verb_body_in(vault, txn, task)?.and_then(|body| match body.assignee {
            Some(TaskAssignee::Human { actor_ref }) => Some(actor_ref),
            None
            | Some(
                TaskAssignee::Dreamer
                | TaskAssignee::AgentDef { .. }
                | TaskAssignee::Peer { .. }
                | TaskAssignee::Child { .. },
            ) => None,
        }),
    )
}

/// Whether a device-local world in `kept` keeps one of the rows the ask
/// `task` is a member of answers from (FIX 7209): each member TASK, the TASK
/// its class came from, its question and its context, the cut its handle's
/// verbs read the group under. Each such row is listed as a producer of the
/// read. `false` when `task` is no member of a stored ask group.
pub(crate) fn ask_rows_kept_in(
    memory: &crate::memory::Memory<'_>,
    txn: &heed::RoTxn<'_>,
    kept: &std::collections::BTreeSet<crate::EntityId>,
    task: crate::EntityId,
) -> crate::Result<bool> {
    let vault = memory.vault();
    let Some(consult) =
        wire_decode::task_verb_body_in(vault, txn, task)?.and_then(|body| body.consult)
    else {
        return Ok(false);
    };
    let Some(group) = ask_record::read_group(vault, txn, consult.correlation_ref)? else {
        return Ok(false);
    };
    if !group
        .members
        .iter()
        .any(|member| member.task == task.to_hex())
    {
        return Ok(false);
    }
    let rows = group.answer_rows();
    memory.produced_from(rows.iter().copied());
    for row in rows {
        if crate::settings::device_local_keeps_among(&vault.store, txn, kept, &row)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) use owner_index::{index_owner_fact, indexed_tasks_of_in};
pub(crate) use policy_change_followup::{
    enqueue_policy_change_digest_followup_in_txn, enqueue_policy_change_followup_in_txn,
};

pub use symbol_lease::{SymbolLease, SymbolLeaseFence, SymbolLeaseOutcome, SymbolLeaseRun};
pub(crate) use symbol_lease::{acquire_symbols, symbols_ready};
pub(crate) use symbol_lease::{
    declaration_holds_in_txn, declare_symbols_for_run_in_txn, release_symbols_for_run_in_txn,
    renew_symbols_for_run_in_txn, run_declaration_in_txn, symbol_blockers_in_txn,
};

#[cfg(test)]
pub(crate) use scheduling::terminal_success_from_body;
pub(crate) use scheduling::{acquire_task_symbols, task_dispatch_ready, terminal_success_in_store};

#[cfg(test)]
mod symbol_lease_tests;

pub use fanout_launch::{FanoutCheckChoice, FanoutLaunchReceipt};
pub use wave_port::{VaultWaveTaskPort, WaveDispatchGeneration, WaveDispatchPage};

pub use linear_store::VaultLinearTaskStore;
pub(crate) use linear_store::{
    drop_mirror_link_in, forget_task_mirror, linear_effect_state_in_txn, linear_issue_task_in,
    mark_mirror_dirty_in, note_task_write, put_mirror_link_in,
};
pub(crate) use mirror_edit::prove_task_owner_in;

#[cfg(test)]
mod production_ports_tests;

pub(crate) use symbol_lease::forget_symbols;

pub(crate) mod fanout_batch;
pub(crate) mod recall_door;
// FIX 8907: the agent SDK lives at `crate::verbs`; `task_verb::sdk` is its
// public path, and the task-owned items its files reach are re-exported
// here for it.
pub use crate::verbs as sdk;
pub(crate) use ask_world_hold::admit_ask_references;
pub(crate) use brief::{decode_hex, hex32};
pub(crate) use create_origin::task_create_origin_in_txn;
pub(crate) use highway::forbidden;
pub(crate) use presence_scan::superseded_attempt_ids;
pub(crate) use rate_limit::task_create_owner_in;

pub mod verb_hook_boundary;

#[cfg(test)]
mod ask_outcome_tests;
#[cfg(test)]
mod ask_tests;

pub(crate) use ask_facade::settle_waiting_asks;
pub(crate) use ask_guest::{ask_guest_grant_in, ask_member_task_in};
pub(crate) use ask_option_link::deliver_ask_change_in_txn;
pub(crate) use ask_option_link::{
    ack_option_void_generation, has_option_link_void, option_void_generation,
};
#[cfg(feature = "sync")]
pub(crate) use ask_record::waits_for_ask_group;
pub(crate) use ask_record::{
    AttendeeEntryFact, admit_attendee_entry_in_txn, admit_unasked_attendee_entry_in_txn,
    ask_notice_at_in, attendee_entry_id, guard_ask_fact_put, read_attendee_entry_in,
};
pub(crate) use ask_settlement::{
    AskStanding, ask_settlement_in, ask_standing_in, settle_ask_if_due,
};
pub(crate) use lifecycle_facade::deliver_task_result_in_txn;

pub(crate) use ask_effect::ProjectWidenRoute;
pub use ask_option_link::{TaskAskOptionLink, TaskAskOptionLinkView};

pub use ask_soft_confirm_types::{
    TaskAskConfirmation, TaskAskConfirmationDecision, TaskAskSoftConfirmDelivery,
    TaskAskSoftConfirmNotice,
};

pub use ask_types::{
    AskAuthorityScope, TaskAskAnswer, TaskAskBranch, TaskAskClass, TaskAskCoverage, TaskAskDecide,
    TaskAskDecision, TaskAskDefault, TaskAskDisagree, TaskAskEffectAuthorization,
    TaskAskElectorate, TaskAskEvidence, TaskAskEvidenceReason, TaskAskFallback, TaskAskGuest,
    TaskAskHandle, TaskAskHoldReason, TaskAskLadderPrediction, TaskAskLaunchHold, TaskAskNeed,
    TaskAskOptionId, TaskAskPersonEvidence, TaskAskPersonKind, TaskAskPreflight,
    TaskAskPreflightRecipient, TaskAskProvisional, TaskAskQuestion, TaskAskReceipt, TaskAskResult,
    TaskAskSettlement, TaskAskSettlementReason, TaskAskSource, TaskAskSpec, TaskAskStatus,
    TaskAskSurface, TaskAskTarget, TaskAskWait, TaskAskWord,
};
