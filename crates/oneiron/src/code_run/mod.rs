//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

pub mod actions;
pub mod blocked;
pub mod consent;
pub mod fold_api;
pub mod live_run;
pub mod vault_read;

mod action_inputs;
pub(crate) mod activity;
// The guest authoring request is decoded at the typed component bridge, and
// a verb hook's rewrite of it as the guest's own.
mod agent_authoring;
mod codec;
mod compaction_fork;
mod compaction_home;
mod consent_wait;
mod contribution;
mod coordination_codec;
mod dispatcher;
mod payload;
mod reader;
mod reader_brief;
mod reader_clock;
mod reader_fold;
mod replay;
mod replay_capsule;
mod replay_parts;
mod repo_calls;
mod result_read;
pub(crate) mod run_verb_call;
mod run_verbs;
mod scoped_child;
mod scoped_child_io;
pub mod shadow_runner;
mod spawn_replay;
mod storage;
mod support;
mod team_submit;
mod type_diagnostics;
mod types;
mod wait_rows;

#[cfg(test)]
mod tests;

pub(crate) use self::action_inputs::self_call_inputs;
pub(crate) use self::agent_authoring::{agent_put_draft, parse_agent_put_request};
pub(crate) use self::codec::encode_code_run_replay_value;
pub use self::codec::{
    CODE_RUN_ABI_LAYOUT_CHECK_KEYS, CODE_RUN_BRIDGE_CALL_KEYS, CODE_RUN_DETERMINISM_KEYS,
    CODE_RUN_OUTPUT_PREVIEW_KEYS, CODE_RUN_RAW_OUTPUT_KEYS, CODE_RUN_REPLAY_RECORD_KEYS,
    CODE_RUN_STEP_CHECKPOINT_KEYS, decode_code_run_replay_record, encode_code_run_replay_record,
};
pub use self::compaction_fork::{
    AdmittedLiveFork, CACHE_BOUNDARIES_KEY, CacheBoundary, HOST_PROVIDER_OPTIONS,
    LiveCompactionFork, LiveForkRung, cache_boundaries, live_fork_offer_digest,
    main_prefix_boundary, mark_cache_boundary, shift_cache_boundaries,
};
pub use self::compaction_home::{
    CompactionHome, CompactionHostBinding, CompactionIdentity, RenderedHome,
    bind_compaction_caller, compaction_home_budget, load_compaction_home,
    resolve_compaction_identity,
};
pub use self::consent_wait::{
    AdmittedBrowserAct, CodeConsentAnswerInput, CodeConsentBrowserAction,
    CodeConsentBrowserOutcome, CodeConsentChoice, CodeConsentEffectHost,
    CodeConsentSavedCredential, CodeConsentSettleOutcome, CodeConsentWaitState,
    CodeConsentWaitView,
};
pub(crate) use self::consent_wait::{
    CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, CodeConsentCallSite, CodeConsentConnectorCall,
    CodeConsentDraft, CodeConsentPendingEffect, CodeConsentPrincipal, CodeConsentRememberOffer,
    CodeConsentResume, CodeConsentWaitRow, ParkedWait, attach_code_consent_ask_in_txn,
    code_consent_admission_in_txn, code_consent_resume_evidence, consume_code_consent_wait_in_txn,
    mint_code_consent_wait_in_txn, offered_choices, original_authority_holds_in_txn,
    read_code_consent_wait_in_txn, record_code_consent_admission_in_txn,
    refuse_code_consent_wait_in_txn, seal_parked_code_consent_in_txn,
    settle_code_consent_wait_listing_in_txn, verify_code_consent_consumed,
    verify_parked_code_consent,
};
pub(crate) use self::contribution::matched_contribution_facts_in_txn;
pub use self::contribution::{
    ContributionForkModel, ContributionForkReceipt, ContributionForkScorer,
    ContributionReplayUnavailable, ForkMismatch, ForkScoring, ForkTreatment, ReplayAnchor,
    ScoredFork, contribution_fork_receipts, run_contribution_forks,
};
pub(crate) use self::dispatcher::{
    ExecutorCallSite, check_write_gate_against_vault, recorded_verb_call,
};
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
pub use self::replay_capsule::{
    CapsuleContent, CapsuleHost, CapsuleRequest, CapsuleRungBinding, ExecutorStepStart,
    ExposureKind, ExposureSlot, ReplayRoutePin, StepReplayCapsule, StoredSpan, TaskExposure,
    capture_workflow_step, finalize_step_captures, note_answering_route_pin, note_answering_rung,
};
pub(crate) use self::replay_capsule::{StepCapture, StepStartBody, StepStartCapture, capture_step};
pub use self::repo_calls::RepoRunCall;
pub use self::result_read::ResultFacet;
pub(crate) use self::result_read::{
    Reply as ResultReply, ResultRead, cannot as result_cannot, card as result_card,
    refusal as result_refusal, resolve as resolve_result, unknown_handle,
};
pub use self::storage::step_replay_capsules;
pub(crate) use self::storage::undecodable_step_capsule_in_txn;
pub(crate) use self::storage::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, RESPONSE_ERASED, WaitReply,
    erase_settled_reply_of_erased_run_in_txn, replay_carriage, replay_owners,
    response_erased_error, retire_actor_responses_in_txn, wait_reply_in_txn,
};
pub(crate) use self::storage::{
    CodeRunCompactionCoverage, ExecutorOutputSpan, ExecutorStorage, ResultSpeech,
    executor_compaction_session_id, executor_speech_message_id_in_run,
    executor_speech_turn_id_for_run,
};
pub use self::storage::{
    CodeRunModelHealCount, CodeRunSecretLiftProposal, WaitDeliveries, WaitDelivery, WaitKey,
    bind_wait_trap, park_and_bind_wait_trap,
};
pub(crate) use self::storage::{
    CodeRunResultBodyReader, OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding,
    ReceiptPartial, ReceiptSource, ReceiptTree,
};
pub(crate) use self::storage::{
    ProgramCheckpointTail, ProgramResumeCall, ProgramResumeCommit, ProgramResumeHead,
    ProgramResumeWait, ProgramRowAnswer, load_program_checkpoint_tail, program_resume_call,
    program_resume_calls_in_txn, program_resume_head_in_txn, wait_delivered_in_txn,
};
pub(crate) use self::storage::{
    ReadWorldSeal, ReadWorldSnapshot, ReadWorldUnknown, read_world_snapshot_in_txn,
};
pub(crate) use self::storage::{
    StagedSinks, code_run_body_file_of_row, code_run_body_held_in_txn, code_run_body_row_key,
    code_run_inline_body_of_row, code_run_row_inline, deliver_wait_in_txn,
    deliver_wait_listing_in_txn, lift_code_run_file_hold_in_txn, settled_wait_reply_in_txn,
};
pub(crate) use self::storage::{
    StepKey, StoredStepFeedback, erase_spawn_targets_in_txn, erase_type_diagnostics_actor_in_txn,
};
pub(crate) use self::storage::{
    StoredRunContinuation, capsule_request, capsule_start_body, erase_capsule_actor_in_txn,
    put_run_continuation_row_in_txn, run_continuation_in_txn, seed_continuation_run,
    step_replay_capsules_in_txn,
};
pub use self::storage::{SummaryMember, SummaryRead};
pub(crate) use self::storage::{
    canonical_wait_ids, deliver_changed_wait_in_txn, has_parked_run_in_txn, observe_wait_change,
};
// FIX 9180 (coord-b slice d): a replay row's and a step start's parts in
// checkpoint images, as row-held responses.
pub(crate) use self::replay_parts::{
    ReplayPart, ReplayParts, RequestPart, recompose_replay_row, recompose_step_start,
    recomposed_len, replay_row_parts, retire_replay_row_parts, retire_step_start_parts,
    step_start_parts,
};
pub(crate) use self::storage::{
    drop_step_start_in_rows, kept_step_start_in_txn, kept_step_starts_in_txn,
    release_step_start_in_txn, republish_step_start_in_rows, republish_step_start_in_txn,
    settle_start_bodies_in_rows, step_capsule_row, step_start_body_row, step_start_owners_in_txn,
};
// FIX 6588: a wait's replies in checkpoint images, as row-held responses.
pub(crate) use self::storage::{
    settled_reply_held_in_txn, settled_wait_key, wait_delivery_owners, wait_reply_erased,
    wait_reply_scan, wait_settled_owners,
};
pub(crate) use self::team_submit::TEAM_DELIVERABLE_REVIEW_PREDICATE;
pub use self::team_submit::{TeamSubmitAnswer, TeamSubmitInput};
pub use self::type_diagnostics::{
    DiagnosticCollection, DiagnosticMeasures, FeedbackWithheldReason, KeptProgramSteps,
    ProgramPreparationNote, ProgramStepFeedback, ProgramStepFeedbackRelease, ProgramStepIdentity,
    TYPE_CHECK_INTERRUPTED, TYPE_CHECK_NOT_ATTACHED, TYPE_CHECK_NOT_LOADED, TYPE_CHECK_NOT_STARTED,
    TYPE_CHECK_OFF, TYPE_FEEDBACK_NOT_KEPT, TypeCheckFacts, TypeCheckState, TypeDiagnostic,
    TypeDiagnostics,
};
pub(crate) use self::type_diagnostics::{measure, parse_check_ref};
pub(crate) use self::wait_rows::{keep_wait_rows, parks_on};
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
    TaskWaitSetCall, TaskWaitSetResult, summary_exceeds_window, summary_exceeds_window_bytes,
    summary_token_budget,
};
pub(crate) use self::reader::{
    reader_attempt_id, reader_run_id, reader_task_id, reader_wait_id, reduce_task_wait_set,
    summary_memo_key, summary_task_id, valid_reader_key, vault_ref,
};
pub use self::reader_brief::reader_task_brief;
pub(crate) use self::reader_clock::{reader_job_cutoff, reader_wait_cutoff};
pub use self::reader_fold::{summarize_input, summarize_prompt};
pub(crate) use self::scoped_child::scoped_child_read_refusal;
pub use self::scoped_child::{
    SCOPED_CHILD_AUTHORITY_LAPSED, SCOPED_CHILD_PARENT_LEASE_LOST,
    SCOPED_CHILD_PORT_EXCEEDS_PARENT, SCOPED_CHILD_PORT_NOT_LENT, SCOPED_CHILD_SERVICE_UNBOUND,
    ScopedChildCallContext, ScopedChildLoan, ScopedChildPorts, ScopedChildSpec, ScopedInputRead,
    scoped_child_authority,
};
pub use self::scoped_child_io::{
    HostInput, ScopedChildHosts, ScopedChildProfile, ScopedChildStop, collect_scoped_child,
    commit_host_inputs, host_run_recorded, read_host_output, read_scoped_finding,
    scoped_child_task, stage_host_output,
};
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
    AgentSpawnInput, JS_SAFE_INTEGER, LeaderAdviceInput, LeaderPatternInput, LeaderSplitInput,
    MemoryClaimInput, MemoryEdgeInput, MemorySearchInput, MemorySupersedeInput, MemoryTimeRange,
    ReaderSpawnInput, ReportBlockedInput, SkillCallInput, SpawnCare, SpawnKnob, SpawnPattern,
    SummarizeInput, SummarizeInputEffort, TaskRefuseDomain, TaskRefuseInput, TaskWaitInput,
    TaskWaitSetRequest, TaskWaitWorldRequest,
};
pub use run_verbs::{
    AgentSpawnKind, AgentSpawnOutput, LeaderPatternFile, LeaderPatternOutput, LeaderSplitOutput,
    MemoryEdgeOutput, MemorySearchHit, MemorySearchOutput, MemoryWriteOutput, ReportBlockedOutput,
    TaskRefuseOutput, TaskWaitOutput,
};
pub use types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbDoor,
    AgentVerbRefusal, AgentVerbRefusalWords, RunCall, SelfAgentVerbCall, SessionHookDisposition,
    SessionHookNotKept, SessionHookPhase, SessionHookReceipt, SessionHookState,
    SessionWriteAdmission, SessionWriteCeiling,
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
