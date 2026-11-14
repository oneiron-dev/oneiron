use super::consts::*;
use super::consult_ladder_facade::*;
use super::consult_result::*;
use super::create_validation::*;
use super::dormant_magistrate::*;
use super::follow_up::*;
use super::presence_scan::*;
use super::rate_limit::*;
use super::wire_decode::*;
use super::wire_encode::*;
use super::*;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    DispatchAgent, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AcceptAttemptLanding, AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, CancelMode, CancelStanding, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, FailAttempt, ForceCancelGrounds, InterveneAttempt,
    LandingOutcome, LandingTrigger, RejectAttemptCancel, RequestAttemptCancel, RetryAttempt,
    RetryOutcome, SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
};
use crate::claim::PREDICATE_CONFLICT_OPEN;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::consult_ladder::{
    AuthorityEvidence, CaseCriticality, DeltaShapeFingerprint, GraduationLookup, GraduationScope,
    InterruptedState, InterruptionKind, MagistrateRecusal, PolicyEvidence, WorkingState,
    terminal_for_human_verdict,
};
use crate::consult_ladder::{
    ConsultLadderState, ConsultLineage, ConsultLineageRelation, ConsultPurpose,
    EntityDeltaArtifact, EntityDeltaShape, HumanVerdict, LadderTerminalDisposition,
    LadderTerminalState, LadderTransition, MagistrateCase, MagistrateOverturnRecord,
    MagistrateVerdict,
};
use crate::context_board::{
    TaskBoardStatus, TasksSection, ack_task_in_txn, cancel_task_in_txn, task_is_acked,
    task_is_cancelled,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::GateOutcome;
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::habit::TaskRole;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, OutboundDraftInput};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::run_tree::RunTreeStatus;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate as EnvelopeClaimCandidate;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{Vault, unix_seconds_now};
use rmpv::Value;

// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-BOARD-ACK]: the lib test target's type check fails here (2 errors: E0061 x1, E0063 x1); port it, then drop this gate
#[cfg(any())]
mod board_ack;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CANCEL]: the lib test target's type check fails here (4 errors: E0061 x3, E0063 x1); port it, then drop this gate
#[cfg(any())]
mod cancel;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CONSULT-FANOUT]: the lib test target's type check fails here (2 errors: E0639 x2); port it, then drop this gate
#[cfg(any())]
mod consult_fanout;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CONSULT-LADDER]: the lib test target's type check fails here (1 errors: E0599 x1); port it, then drop this gate
#[cfg(any())]
mod consult_ladder;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CONSULT-LIFECYCLE]: the lib test target's type check fails here (7 errors: E0599 x4, E0063 x2, E0639 x1); port it, then drop this gate
#[cfg(any())]
mod consult_lifecycle;
mod consult_party;
mod consult_party_generation;
mod consult_party_migration;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CREATE-ADMISSION]: the lib test target's type check fails here (1 errors: E0061 x1); port it, then drop this gate
#[cfg(any())]
mod create_admission;
mod magistrate_route_result;
mod presence_scan;
pub(crate) mod support;

// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-ADDRESSABLE-CONSULTS]: the lib test target's type check fails here (1 errors: E0063 x1); port it, then drop this gate
#[cfg(any())]
mod addressable_consults;

// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-AUTHORITY-ASKS]: the lib test target's type check fails here (4 errors: E0063 x2, E0061 x2); port it, then drop this gate
#[cfg(any())]
mod authority_asks;
// FIX [LIBTEST-QUARANTINE-TASK-VERB-TESTS-CODE-LEAD]: the lib test target's type check fails here (5 errors: E0063 x2, E0308 x2, E0027 x1); port it, then drop this gate
#[cfg(any())]
mod code_lead;
