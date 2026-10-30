//! State and export seam for the host-bound first-party dispatcher.
//! Entry type: `HostSelfDispatcher`.
//! Child modules own behavior; call definitions are forwarded from `code_run::types`.

mod admission;
mod agent_verb;
mod binding;
mod browser_admission;
mod connector_answer;
mod coordination;
mod dispatch;
mod emission;
mod envelope;
mod fold_verbs;
mod host_doors;
mod human_speech;
mod inference_defaults;
mod leader;
mod memory_verbs;
mod program_step;
mod read_worlds;
mod reader_spawn;
mod repo;
mod repo_sources;
mod routed_entry;
mod session_verbs;
mod spawn_capture;
mod summarize;
mod team_submit;
mod team_submit_output;
mod team_verbs;
mod verb_hooks;
mod wake_policy;
mod workflow_dispatch;
mod world_privacy_set;
mod world_privacy_wait;

use std::cell::{Cell, RefCell};

use crate::claim::ScopedReadActorKey;
use crate::code_run::consent;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::{ExecutorStorage, RunAssertionCollector};
use crate::code_run::types::{
    AgentVerbRefusal, RunCall, SelfCall, SelfContextCall, SelfContextResult, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfDurableWaitReason, SelfEffect,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::TrapRef;
use crate::off_record::OffRecordSession;
use crate::vault::VaultId;
use crate::{ClaimSource, Vault, WriteActor};

use self::admission::gate_rejection;
pub(crate) use self::agent_verb::recorded_call as recorded_verb_call;
pub(crate) use self::envelope::check_write_gate_against_vault;
#[cfg(test)]
pub(super) use self::envelope::{SELF_PROVENANCE_CALL_KEY, edge_operation_gate_id};
pub(super) use self::envelope::{SELF_PROVENANCE_SURFACE_KEY, lineage_for_run};
use self::human_speech::HumanWaitDispatchTarget;
pub use self::leader::{HostPlannerBinding, HostPlannerDecisions};
pub use self::memory_verbs::SELF_MEMORY_SEARCH_MAX_RESULTS;
pub(crate) use self::reader_spawn::ReaderChildBinding;

/// Host-bound dispatcher for one first-party code run.
///
/// The actor and source are bound at construction time by the host. Individual
/// [`SelfCall`] values carry only operation arguments, so guest-authored code
/// cannot spoof actor, source, or approval fields through this skeleton.
pub struct HostSelfDispatcher<'a> {
    pub(super) agent_parent: Option<crate::attempt_queue::AttemptId>,
    pub(super) agent_lease: Option<crate::agent_def::AgentAuthorLease>,
    /// The run's binding on its vault's attempt activity witness (OF-568
    /// L5), held while it lives; `None` unless a lease binds the run.
    pub(super) activity: Option<crate::code_run::activity::AttemptActivityBinding>,
    /// The run's own vault as the host holds it, lent to the callable skills
    /// its program calls (OF-353): a foreign-tier skill's egress relay keeps
    /// it past the call.
    pub(super) skill_vault: Option<std::sync::Arc<Vault>>,
    pub(super) storage: ExecutorStorage<'a>,
    pub(super) actor: WriteActor,
    pub(super) run_ref: String,
    pub(super) human_wait_target: Option<HumanWaitDispatchTarget>,
    pub(super) code_emission:
        Option<(consent::CodeEmissionContext, Option<consent::ReviewContext>)>,
    /// Host-authenticated owner for a single governed agent action. No guest
    /// call, transcript, or replay row can mint or carry this proof.
    pub(super) owner_proof: Option<&'a crate::consent::AuthenticatedOwner>,
    /// Where that owner's say-so reached the host, for the owner's act an
    /// owner setting records (WILL-PLAN L13 row 01). Audit only.
    pub(super) owner_surface: Option<crate::authority::ActSurface>,
    /// The credential lineage the host admitted this run under (FIX 4705):
    /// its verified slip and that slip's parent. A request the run opens
    /// carries it, and the answering door walks it to its delegation root, so
    /// no answer from it or a fork of it settles that request (FIX 5064).
    /// Only [`Self::with_opener_credential`] sets it, from a slip the
    /// verifier produced; no guest call reaches it. A run no credential
    /// admitted (a pumped agent run) has none.
    opener_lineage: Vec<[u8; 32]>,
    /// ONE-1314. Whether this run's effect history is already known to carry
    /// an EXTERNAL effect, so the memory writes it seals afterwards must be
    /// stamped with tool-output lineage rather than bare `Generated`.
    ///
    /// Host-internal by construction: the only way to set it is
    /// [`Self::observe_bridge_history`], which takes a recorded bridge-call
    /// history (never a lineage value), and no `SelfCall` payload, public
    /// constructor, or API argument reaches it. It is a `Cell` because the
    /// executor holds the dispatcher by SHARED reference and the observation
    /// has to land before the write it describes dispatches. Monotone: once
    /// set it is never cleared, so a later step cannot launder an earlier
    /// external effect out of the run.
    pub(super) external_effect_seen: Cell<bool>,
    /// The host's door onto the SDK verb table, if it binds one.
    pub(super) agent_verbs: Option<std::sync::Arc<dyn crate::code_run::AgentVerbDoor>>,
    /// The guest's view of the last call's result when a verb hook changed
    /// it (ARCH-0080 §3): a Redact, or a blocking hook that hid it. The
    /// executor's host takes it for its reply; the run records the result.
    pub(super) hook_view: RefCell<Option<serde_json::Value>>,
    /// The calls a verb hook's ask parked, as the run's history shows them,
    /// with the invocation each ask waits under and the ask's handle, which
    /// the same call names as the pause it resumes (FIX 5526).
    pub(super) parked_hooks: RefCell<
        Vec<(
            verb_hooks::ParkedCall,
            crate::runtime_hooks::InvocationId,
            Option<EntityId>,
        )>,
    >,
    /// The seat the host lent the run to spawn reader children under, if
    /// any (ARCH-0079 #reader-forks).
    pub(super) reader_spawn: Option<crate::code_run::SpawnHostSeat>,
    /// The reader child's job this run is, when it is one.
    pub(super) reader_child: Option<ReaderChildBinding>,
    /// The ports a scoped child's host registered for it (FIX 7507), when
    /// it is one. Host configuration; no guest call reaches it.
    pub(super) scoped_ports: Option<std::sync::Arc<dyn crate::code_run::ScopedChildPorts>>,
    /// The run its host bound this dispatcher to, whose own seat and first
    /// start the host reads through it on its route (FIX 2594, FIX 7507);
    /// `None` until a host binds one. No guest call reaches it.
    bound_run: Option<EntityId>,
    /// The host's planner (OF-541, OF-389): what a planned spawn and the
    /// leader's calls read. Host configuration; no guest call reaches it.
    pub(super) planner: Option<HostPlannerBinding<'a>>,
    /// The host's slip issuer, which signs the leader's subproject spawn
    /// (OF-389). Host configuration; no guest call reaches it.
    pub(super) slip_issuer: Option<&'a crate::authority::HostSlipIssuer>,
    /// The skill bodies the host put in the run's task (FIX 3028), which the
    /// first step's replay capsule tags. Host configuration; no guest call
    /// reaches it.
    pub(super) replay_exposures: Vec<crate::code_run::TaskExposure>,
    /// The committed-write refs the next speech bubble asserts (FIX 11456).
    pub(super) assertions_created: RefCell<RunAssertionCollector>,
    /// The model provider the host's ladder says answered the run's last
    /// turn, whose program is the one running (OF-560). Host-internal: only
    /// [`Self::observe_model_provider`] sets it, from the served receipt,
    /// and every verb call's origin carries it. `None` when no ladder
    /// stamped the turn.
    pub(super) model_provider: RefCell<Option<String>>,
    /// The model request the run's executor bound before its latest call
    /// (FIX 2343), which a blocked report the run files keeps for its code
    /// fix's replay. Host-internal: only [`Self::observe_run_request`] sets
    /// it, from the request the executor assembled. No guest call reaches it.
    pub(super) run_request: RefCell<Option<crate::self_heal::blocked_reports::BlockedRunRequest>>,
    /// Whose log the fold verbs reach (OF-181): the executor call's own run,
    /// unless a host action bound the live run it acts for.
    fold_log: fold_verbs::FoldLog,
    /// The turn program this run is (DOOR-141 PR2), when the host bound one:
    /// only [`Self::for_turn_program`] sets it, from the program's own
    /// leased try. No guest call reaches it.
    program: Option<program_step::ProgramBinding>,
    /// The run's read-world capture (FIX 6130): the capture epoch its entry
    /// holds, whether every ledger write of it landed, and whether the last
    /// call's own capture noted its answer. Host-internal: no guest call
    /// reaches it.
    read_worlds: Cell<read_worlds::ReadWorldLive>,
    /// Whether the run's task is its caller's own text (FIX 6130): only
    /// [`Self::with_caller_task`] sets it, as the host binds the run. No
    /// guest call reaches it.
    caller_task: bool,
    /// The host's review policy for the run's repo proposals (FIX 6867):
    /// only [`Self::with_repo_review_policy`] binds it. No guest call
    /// reaches it.
    pub(super) repo_review_policy:
        Option<std::sync::Arc<dyn crate::memory::repo_doors::RepoReviewPolicy>>,
    /// The seats each open spawn call resolved (FIX 9180): host-only, one
    /// frame per call, taken by the recorder of the call's row.
    spawn_capture: spawn_capture::SpawnCapture,
}

/// One bridge call's place in a durable engine-executor run.
#[derive(Clone, Copy)]
pub(crate) struct ExecutorCallSite<'h> {
    pub(crate) run_id: EntityId,
    /// The call's bridge position.
    pub(crate) seq: u64,
    /// The first bridge position of the step the call belongs to.
    pub(crate) step_start: u64,
    /// This attempt's earlier calls in the step, as recorded.
    pub(crate) earlier: &'h [CodeRunBridgeCall],
}

/// Explicit first-party GatedActorWrite trap surface for engine-native code.
///
/// This is a type alias for [`HostSelfDispatcher`], whose public `vault.*` run-row
/// variants stamp host-owned actor/provenance and run per-operation gate checks
/// before any write commits.
pub type GatedActorWrite<'a> = HostSelfDispatcher<'a>;
