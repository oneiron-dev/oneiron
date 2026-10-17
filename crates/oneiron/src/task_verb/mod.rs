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
mod attendee_answer;
mod board_task;
pub(crate) use board_task::board_task_for_id;
mod brief;
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
mod highway_report;
pub(crate) mod highway_runner;
mod highway_status;
mod highway_types;
mod lifecycle_facade;
mod linear_store;
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
pub(crate) use report_journal::erase_in_txn as erase_report_journal_in_txn;
mod room_thread;
mod route_receipts;
mod runner_done;
mod scheduling;
mod subproject;
mod symbol_lease;
mod terminal_state;
mod verb_kind;
mod wave_port;
mod wire_decode;
pub(crate) use project_tradeoff::{project_tradeoff_routed_in, task_created_at_in};
pub(crate) use wire_decode::{
    TaskBinding, done_task_evidence_in, leader_task_body_in, leader_task_brief_in, task_binding,
    task_is_blocked_in, task_text_in,
};
mod wire_encode;

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
    open_thread_tasks_in as room_open_thread_tasks_in, task_ids_in as room_thread_task_ids_in,
    task_roster_in as room_thread_task_roster_in, thread_tasks as room_thread_tasks,
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
    StoredBrief, TypeRef, brief_digest,
};
pub use decision_port::TaskDecisions;
pub(crate) use highway_post::settle_task_proposal_in_txn;
pub use highway_types::{
    AttemptHandle, AttemptView, HostBinding, TaskAccept, TaskCall, TaskCallReceipt, TaskHandle,
    TaskLifecycleRecord, TaskOutcome, TaskPhase, TaskPost, TaskReport, TaskReportBody,
    TaskStatusQuery, TaskStatusView, TaskVia,
};
pub use runner_done::{RunnerDoneAnswer, RunnerDoneQuestion, runner_done_question};

pub(crate) use create_validation::{
    completed_task_at_in_txn, reject_born_expired_task_deadline, reject_incoherent_task_terminal,
    settled_task_result_binding, task_human_assignee, task_is_terminal,
};
pub(crate) use rate_limit::task_create_owner;

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

pub(crate) use owner_index::{index_owner_fact, indexed_tasks_of_in};
pub(crate) use policy_change_followup::{
    enqueue_policy_change_digest_followup_in_txn, enqueue_policy_change_followup_in_txn,
};

pub use symbol_lease::{SymbolLease, SymbolLeaseOutcome};
pub(crate) use symbol_lease::{acquire_symbols, symbols_ready};

#[cfg(test)]
pub(crate) use scheduling::terminal_success_from_body;
pub(crate) use scheduling::{acquire_task_symbols, task_dispatch_ready, terminal_success_in_store};

#[cfg(test)]
mod symbol_lease_tests;

pub use fanout_launch::{FanoutCheckChoice, FanoutLaunchReceipt};
pub use wave_port::{VaultWaveTaskPort, WaveDispatchGeneration, WaveDispatchPage};

pub use linear_store::VaultLinearTaskStore;
pub(crate) use linear_store::{forget_task_mirror, linear_effect_state_in_txn, note_task_write};

#[cfg(test)]
mod production_ports_tests;

pub(crate) use symbol_lease::forget_symbols;

mod recall_door;
pub mod sdk;
mod sdk_catalog_fragment;
mod sdk_connector;
mod sdk_connector_call;
mod sdk_courtesy_delete;
mod sdk_diary;
mod sdk_disclosure;
mod sdk_embedding_space;
mod sdk_explain;
mod sdk_fanout_launch;
mod sdk_guest_revoke;
mod sdk_host;
mod sdk_legal_hold;
mod sdk_mesh;
mod sdk_record_erase;
mod sdk_research;
mod sdk_scratchpad;
mod sdk_secret;
mod sdk_secret_use;
mod sdk_self;
mod sdk_share;
mod sdk_shared;
mod sdk_shared_members;
pub mod verb_hook_boundary;

#[cfg(test)]
mod ask_outcome_tests;
#[cfg(test)]
mod ask_tests;

pub(crate) use ask_facade::settle_waiting_asks;
pub(crate) use ask_guest::ask_guest_grant_in;
pub(crate) use ask_option_link::deliver_ask_change_in_txn;
pub(crate) use ask_option_link::{
    ack_option_void_generation, has_option_link_void, option_void_generation,
};
#[cfg(feature = "sync")]
pub(crate) use ask_record::waits_for_ask_group;
pub(crate) use ask_record::{
    AttendeeEntryFact, admit_attendee_entry_in_txn, ask_notice_at_in, attendee_entry_id,
    guard_ask_fact_put, read_attendee_entry_in,
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
