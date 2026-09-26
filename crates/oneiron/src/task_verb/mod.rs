//! Typed, actor-bound verbs over the Context Board TASKS section.
//!
//! Directory module: declarations, re-exports, and the typed ask entry point.
//! Sibling files own each ask implementation and its existing admission rules.

mod ask_facade;
mod ask_preflight;
mod ask_record;
mod ask_settlement;
mod ask_types;
mod consts;
mod consult_fanout_admission;
mod consult_fanout_facade;
mod consult_fanout_resume;
mod consult_fanout_store;
mod consult_fanout_types;
mod consult_ladder_facade;
mod consult_payload;
mod consult_result;
mod create_facade;
mod create_spec;
mod create_validation;
mod dormant_magistrate;
mod entity_delta_facade;
mod follow_up;
mod lifecycle_facade;
mod linear_store;
mod owner_index;
mod presence_diagnostics;
mod presence_scan;
mod query_facade;
mod rate_limit;
mod reconciliation;
mod route_receipts;
mod scheduling;
mod symbol_lease;
mod terminal_state;
mod verb_kind;
mod wave_port;
mod wire_decode;
mod wire_encode;

#[cfg(test)]
mod tests;

pub use consts::TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED;
pub use consult_fanout_types::{
    ConsultFanOutChoice, ConsultFanOutMeter, ConsultFanOutMode, ConsultFanOutPause,
    ConsultFanOutPolicy, ConsultFanOutRate,
};
pub use consult_ladder_facade::{
    CrossActorRoute, LadderTransitionReceipt, project_consult_ladder_state,
};
pub use consult_payload::{ConsultPayload, ConsultPayloadRef, ConsultRecovery};
pub use consult_result::{
    ConsultDigestRoute, ConsultExpiryReport, ConsultFanOutReceipt, ConsultFanOutSpec,
    ConsultResultInput, ConsultResultKind, TaskResultReceipt,
};
pub use create_spec::{TaskCreateRateLimit, TaskCreateSpec};
pub use create_validation::check_task_label;
pub use dormant_magistrate::{
    apply_magistrate_verdict, decide_magistrate, decode_human_verdict, enqueue_magistrate,
    human_verdict_value, ladder_terminal_from_task_terminal, project_consult_task_to_a2a,
    record_magistrate_overturn,
};
pub use follow_up::{decode_consult_expiry_recovery, task_follow_up_dedupe_key};
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

pub(crate) use create_validation::{
    completed_task_at_in_txn, reject_born_expired_task_deadline, reject_incoherent_task_terminal,
    settled_task_result_binding, task_human_assignee, task_is_terminal,
};
pub(crate) use rate_limit::task_create_owner;

pub(crate) use owner_index::index_owner_fact;

#[cfg(test)]
mod owner_index_tests;

pub use symbol_lease::{SymbolLease, SymbolLeaseOutcome};
pub(crate) use symbol_lease::{acquire_symbols, symbols_ready};

pub(crate) use scheduling::{acquire_task_symbols, task_dispatch_ready, terminal_success_in_store};

#[cfg(test)]
mod symbol_lease_tests;

pub use wave_port::VaultWaveTaskPort;

pub use linear_store::VaultLinearTaskStore;
pub(crate) use linear_store::{forget_task_mirror, note_task_write};

#[cfg(test)]
mod production_ports_tests;

pub(crate) use symbol_lease::forget_symbols;

pub mod sdk;

#[cfg(test)]
mod ask_outcome_tests;
#[cfg(test)]
mod ask_tests;

pub(crate) use ask_facade::settle_waiting_asks;
pub(crate) use ask_record::{ask_notice_at_in, guard_ask_fact_put};
pub(crate) use ask_settlement::settle_ask_if_due;

pub use ask_types::{
    AskAuthorityScope, TaskAskAnswer, TaskAskBranch, TaskAskClass, TaskAskCoverage, TaskAskDecide,
    TaskAskDecision, TaskAskDefault, TaskAskDisagree, TaskAskElectorate, TaskAskEvidence,
    TaskAskEvidenceReason, TaskAskFallback, TaskAskHandle, TaskAskHoldReason, TaskAskNeed,
    TaskAskOptionId, TaskAskPersonEvidence, TaskAskPersonKind, TaskAskPreflight,
    TaskAskPreflightRecipient, TaskAskProvisional, TaskAskQuestion, TaskAskReceipt, TaskAskResult,
    TaskAskSettlement, TaskAskSettlementReason, TaskAskSource, TaskAskSpec, TaskAskStatus,
    TaskAskSurface, TaskAskTarget, TaskAskWait, TaskAskWord,
};
