//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

pub mod actions;
pub mod blocked;
pub mod consent;
pub mod live_run;
pub mod vault_read;

// The guest authoring request is decoded at the typed component bridge, and
// a verb hook's rewrite of it as the guest's own.
mod agent_authoring;
mod codec;
mod coordination_codec;
mod dispatcher;
mod payload;
mod reader;
mod reader_fold;
mod replay;
mod result_read;
pub(crate) mod run_verb_call;
mod run_verbs;
mod storage;
mod support;
mod types;

#[cfg(test)]
mod tests;

pub(crate) use self::agent_authoring::{agent_put_draft, parse_agent_put_request};
pub(crate) use self::codec::encode_code_run_replay_value;
pub use self::codec::{
    CODE_RUN_ABI_LAYOUT_CHECK_KEYS, CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS,
    CODE_RUN_OUTPUT_PREVIEW_KEYS, CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS,
    CODE_RUN_STEP_CHECKPOINT_KEYS, decode_code_run_replay_record, encode_code_run_replay_record,
};
pub(crate) use self::dispatcher::{ExecutorCallSite, check_write_gate_against_vault};
pub use self::dispatcher::{
    GatedActorWrite, HostPlannerBinding, HostPlannerDecisions, HostSelfDispatcher,
    SELF_MEMORY_SEARCH_MAX_RESULTS,
};
pub use self::replay::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
    CODE_RUN_REPLAY_HASH_LEN, CODE_RUN_REPLAY_SCHEMA_VERSION, CODE_RUN_RNG_SEED_LEN,
    CodeRunAbiLayoutCheck, CodeRunBridgeCall, CodeRunDeterminism, CodeRunHistoryTurn,
    CodeRunOutputKind, CodeRunOutputPreview, CodeRunRawOutput, CodeRunReplayCursor,
    CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunResultBinding, CodeRunStepCheckpoint,
    ResultOccurrence, code_run_replay_abi_layout_checks,
};
pub(crate) use self::replay::{CODE_RUN_OUTPUT_PREVIEW_WITHHELD, agent_verb_rows_of};
pub use self::result_read::ResultFacet;
pub(crate) use self::result_read::{
    Reply as ResultReply, ResultRead, cannot as result_cannot, card as result_card,
    refusal as result_refusal, resolve as resolve_result, unknown_handle,
};
pub(crate) use self::storage::{
    CodeRunCompactionCoverage, ExecutorOutputSpan, ExecutorStorage, executor_compaction_session_id,
    executor_speech_message_id_in_run, executor_speech_turn_id_for_run,
};
pub use self::storage::{
    CodeRunModelHealCount, CodeRunSecretLiftProposal, WaitDeliveries, WaitDelivery, WaitKey,
    bind_wait_trap, park_and_bind_wait_trap,
};
pub(crate) use self::storage::{FinishedOutput, code_run_body_file_of_row, deliver_wait_in_txn};
pub(crate) use self::storage::{
    OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding, ReceiptPartial,
    ReceiptSource, ReceiptTree,
};
pub use self::storage::{SummaryMember, SummaryRead};
pub(crate) use self::storage::{
    canonical_wait_ids, deliver_changed_wait_in_txn, has_parked_run_in_txn, observe_wait_change,
};
// ONE-1686: a canonical run's transcript identity is DERIVED from its run ref,
// so the tests that assert where its bubbles landed derive it the same way
// rather than hard-coding a hash.
pub use self::reader::{
    ClaimOutcome, DEFAULT_READER_FOLD_RESERVE_MS, DEFAULT_READER_WINDOW_TOKENS, DelegatedSource,
    ReaderActor, ReaderFindingRef, ReaderJob, ReaderJobKind, ReaderJobRunner, ReaderJobState,
    ReaderJobWake, ReaderParent, ReaderReportReceipt, ReaderRoute, ReaderRunEnd,
    ReaderSpawnReceipt, ReaderSpend, RunDeadline, SUMMARY_GROUP_EXCEEDS_WINDOW,
    SUMMARY_READ_BYTES_PER_TOKEN, SUMMARY_WINDOW_DIVISOR, SelfReaderReportCall,
    SelfReaderSpawnCall, SelfSummarizeCall, SpawnHostSeat, SpawnParentBinding, SummarizeEffort,
    SummarizeRecipe, SummarizeReply, TaskWaitFailure, TaskWaitFinding, TaskWaitPolicy, TaskWaitSet,
    TaskWaitSetCall, TaskWaitSetResult, reader_task_brief, summary_exceeds_window,
    summary_exceeds_window_bytes, summary_token_budget,
};
pub(crate) use self::reader::{
    reader_attempt_id, reader_run_id, reader_task_id, reader_wait_id, reduce_task_wait_set,
    summary_memo_key, summary_task_id, valid_reader_key, vault_ref,
};
pub use self::reader_fold::{summarize_input, summarize_prompt};
pub use self::storage::ReaderJobs;
pub(crate) use self::storage::SpendBook;
#[cfg(test)]
use self::storage::canonical_speech_conversation_id;
#[cfg(test)]
pub(crate) use self::storage::executor_speech_message_id;
#[cfg(test)]
pub(crate) use self::storage::require_facet_placement_in;
pub use self::types::{
    SelfAgentDefinitionPutCall, SelfAgentDefinitionPutResult, SelfAgentSpawnCall,
    SelfAgentSpawnResult, SelfAskCall, SelfCall, SelfContextCall, SelfContextResult,
    SelfDeniedResult, SelfDispatchOutcome, SelfDispatcher, SelfDurableWait, SelfDurableWaitReason,
    SelfEffect, SelfFailedResult, SelfFixtureEffectCall, SelfLeaderCall, SelfMemoryEdgeWriteResult,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult, SelfSkillCall,
    SelfSkillCallResult, SelfSpawnAsk, SelfSpeechCall, SelfSpeechResult, SelfTaskRefusalResult,
    SelfTaskRefuseCall, SelfWakePolicyWriteCall, peer_result_wait,
};
pub use run_verbs::{
    AgentSpawnInput, JS_SAFE_INTEGER, LeaderAdviceInput, LeaderPatternInput, MemoryClaimInput,
    MemoryEdgeInput, MemorySearchInput, MemorySupersedeInput, MemoryTimeRange, ReaderSpawnInput,
    SkillCallInput, SpawnCare, SpawnKnob, SpawnPattern, SummarizeInput, SummarizeInputEffort,
    TaskRefuseDomain, TaskRefuseInput, TaskWaitSetRequest,
};
pub use run_verbs::{
    AgentSpawnKind, AgentSpawnOutput, LeaderPatternFile, LeaderPatternOutput, MemoryEdgeOutput,
    MemorySearchHit, MemorySearchOutput, MemoryWriteOutput, TaskRefuseOutput,
};
pub use types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbDoor,
    AgentVerbRefusal, RunCall, SelfAgentVerbCall,
};

// The flat code_run.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the sibling `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::dispatcher::{SELF_PROVENANCE_CALL_KEY, edge_operation_gate_id};
#[cfg(test)]
use self::payload::{
    decode_self_dispatch_outcome, self_call_request_value, self_dispatch_outcome_value,
};
#[cfg(test)]
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, EdgeKind, EntityId,
    Error, Result, TimeRange, Vault,
};
