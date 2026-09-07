//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

pub mod consent;
pub mod vault_read;

mod codec;
mod dispatcher;
mod payload;
mod replay;
mod storage;
mod support;
mod types;

#[cfg(test)]
mod tests;

pub(crate) use self::codec::encode_code_run_replay_value;
pub use self::codec::{
    CODE_RUN_ABI_LAYOUT_CHECK_KEYS, CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS,
    CODE_RUN_OUTPUT_PREVIEW_KEYS, CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS,
    CODE_RUN_STEP_CHECKPOINT_KEYS, decode_code_run_replay_record, encode_code_run_replay_record,
};
pub(crate) use self::dispatcher::check_write_gate_against_vault;
pub use self::dispatcher::{GatedActorWrite, HostSelfDispatcher, SELF_MEMORY_SEARCH_MAX_RESULTS};
pub use self::replay::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
    CODE_RUN_REPLAY_HASH_LEN, CODE_RUN_REPLAY_SCHEMA_VERSION, CODE_RUN_RNG_SEED_LEN,
    CodeRunAbiLayoutCheck, CodeRunBridgeCall, CodeRunDeterminism, CodeRunHistoryTurn,
    CodeRunOutputPreview, CodeRunRawOutput, CodeRunReplayCursor, CodeRunReplayGeneration,
    CodeRunReplayRecord, CodeRunStepCheckpoint, code_run_replay_abi_layout_checks,
};
pub use self::storage::CodeRunModelHealCount;
pub(crate) use self::storage::ExecutorStorage;
// ONE-1686: a canonical run's transcript identity is DERIVED from its run ref,
// so the tests that assert where its bubbles landed derive it the same way
// rather than hard-coding a hash.
#[cfg(test)]
pub(crate) use self::storage::{
    canonical_speech_conversation_id, canonical_speech_conversation_id_for_run,
    executor_speech_message_id,
};
pub use self::types::{
    SelfAskHumanCall, SelfCall, SelfContextCall, SelfContextResult, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfFailedResult, SelfFixtureEffectCall, SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall,
    SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult,
    SelfSpeechCall, SelfSpeechResult, peer_result_wait,
};

// The flat code_run.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the sibling `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::dispatcher::{SELF_PROVENANCE_CALL_KEY, edge_operation_gate_id};
#[cfg(test)]
use self::payload::{
    decode_self_dispatch_outcome, durable_wait_reason_from_str, durable_wait_reason_str,
    self_call_request_value, self_dispatch_outcome_value, self_effect_from_str,
};
#[cfg(test)]
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, EdgeKind, EntityId,
    Error, Result, TimeRange, Vault,
};
