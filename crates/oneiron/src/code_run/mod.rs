//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

pub mod actions;
pub mod blocked;
pub mod consent;
pub mod vault_read;

// The guest authoring request is decoded only at the typed component bridge.
#[cfg(any(test, feature = "code-sandbox-wasmtime"))]
mod agent_authoring;
mod codec;
mod coordination_codec;
mod dispatcher;
mod payload;
mod reader;
mod replay;
mod result_read;
mod run_verbs;
mod storage;
mod support;
mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) use self::agent_authoring::parse_agent_put_request;
pub(crate) use self::codec::encode_code_run_replay_value;
pub use self::codec::{
    CODE_RUN_ABI_LAYOUT_CHECK_KEYS, CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS,
    CODE_RUN_OUTPUT_PREVIEW_KEYS, CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS,
    CODE_RUN_STEP_CHECKPOINT_KEYS, decode_code_run_replay_record, encode_code_run_replay_record,
};
pub(crate) use self::dispatcher::{ExecutorCallSite, check_write_gate_against_vault};
pub use self::dispatcher::{GatedActorWrite, HostSelfDispatcher, SELF_MEMORY_SEARCH_MAX_RESULTS};
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
pub use self::storage::{CodeRunModelHealCount, CodeRunSecretLiftProposal};
pub(crate) use self::storage::{FinishedOutput, code_run_body_file_of_row};
// ONE-1686: a canonical run's transcript identity is DERIVED from its run ref,
// so the tests that assert where its bubbles landed derive it the same way
// rather than hard-coding a hash.
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
    SelfEffect, SelfFailedResult, SelfFixtureEffectCall, SelfMemoryEdgeWriteResult,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult, SelfSkillCall,
    SelfSkillCallResult, SelfSpeechCall, SelfSpeechResult, SelfTaskRefusalResult,
    SelfTaskRefuseCall, SelfWakePolicyWriteCall, peer_result_wait,
};
pub(crate) use self::reader::{
    READER_KEY_MAX_BYTES, reader_attempt_id, reader_run_id, reader_task_id, reader_wait_id,
    reduce_task_wait_set, valid_reader_key, vault_ref,
};
pub use self::reader::{
    ClaimOutcome, DEFAULT_READER_FOLD_RESERVE_MS, DelegatedSource, ReaderActor, ReaderFindingRef,
    ReaderJob, ReaderJobRunner, ReaderJobState, ReaderJobWake, ReaderParent, ReaderReportReceipt,
    ReaderRoute, ReaderRunEnd, ReaderSpawnReceipt, RunDeadline, SelfReaderReportCall,
    SelfReaderSpawnCall, SpawnHostSeat, SpawnParentBinding, TaskWaitFailure, TaskWaitFinding,
    TaskWaitPolicy, TaskWaitSet, TaskWaitSetCall, TaskWaitSetResult, reader_task_brief,
};
pub use self::storage::ReaderJobs;
pub(crate) use self::storage::SpendBook;
pub use run_verbs::{
    JS_SAFE_INTEGER, MemoryClaimInput, MemoryEdgeInput, MemorySearchInput, MemorySupersedeInput,
    MemoryTimeRange, ReaderSpawnInput, SkillCallInput, TaskRefuseDomain, TaskRefuseInput,
    TaskWaitSetRequest,
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
