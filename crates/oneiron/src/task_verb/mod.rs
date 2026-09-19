//! Typed, actor-bound verbs over the Context Board TASKS section.
//!
//! Directory module: this file holds declarations and re-exports only. Each
//! sibling file owns one concern; the `crate::task_verb::*` surface below
//! reproduces the pre-split flat-module surface verbatim.

mod consts;
mod consult_fanout_facade;
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
mod presence_scan;
mod query_facade;
mod rate_limit;
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
pub use consult_ladder_facade::{
    CrossActorRoute, LadderTransitionReceipt, project_consult_ladder_state,
};
pub use consult_payload::{ConsultPayload, ConsultPayloadRef, ConsultRecovery};
pub use consult_result::{
    ConsultDigestRoute, ConsultExpiryReport, ConsultFanOutReceipt, ConsultFanOutSpec,
    ConsultResultInput, ConsultResultKind, TaskResultReceipt,
};
pub use create_spec::{TaskCreateRateLimit, TaskCreateSpec};
pub use dormant_magistrate::{
    apply_magistrate_verdict, decide_magistrate, decode_human_verdict, enqueue_magistrate,
    human_verdict_value, ladder_terminal_from_task_terminal, project_consult_task_to_a2a,
    record_magistrate_overturn,
};
pub use follow_up::{decode_consult_expiry_recovery, task_follow_up_dedupe_key};
pub use route_receipts::{
    DEFAULT_TASK_CANCEL_MODE, TaskAckReceipt, TaskCancelMode, TaskCancelReceipt, TaskCancelTarget,
    TaskCreateReceipt, TaskResultInput, TaskRouteLane, TaskRouteOutcome, TaskStartedReceipt,
};
pub use terminal_state::{
    ConsultResultPresence, ConsultResultSummary, TaskExecutionState, TaskTerminalDisposition,
    TaskTerminalRecord, board_status_for_disposition, merge_task_terminal_register,
};
pub use verb_kind::{TASKS_VERBS, TaskAssignee, TaskKind, TaskTtl, TasksVerb};

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
