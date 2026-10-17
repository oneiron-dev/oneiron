mod agent_verb;
mod coordination;
mod emission;
mod envelope;
mod fold_verbs;
mod human_speech;
mod leader;
mod memory_verbs;
mod reader_spawn;
mod summarize;
mod team_verbs;
mod verb_hooks;
mod wake_policy;

use std::cell::{Cell, RefCell};

use crate::claim::ScopedReadActorKey;
use crate::code_run::consent;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
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
    /// with the invocation each ask waits under.
    pub(super) parked_hooks:
        RefCell<Vec<(verb_hooks::ParkedCall, crate::runtime_hooks::InvocationId)>>,
    /// The seat the host lent the run to spawn reader children under, if
    /// any (ARCH-0079 #reader-forks).
    pub(super) reader_spawn: Option<crate::code_run::SpawnHostSeat>,
    /// The reader child's job this run is, when it is one.
    pub(super) reader_child: Option<ReaderChildBinding>,
    /// The host's planner (OF-541, OF-389): what a planned spawn and the
    /// leader's calls read. Host configuration; no guest call reaches it.
    pub(super) planner: Option<HostPlannerBinding<'a>>,
    /// The model provider the host's ladder says answered the run's last
    /// turn, whose program is the one running (OF-560). Host-internal: only
    /// [`Self::observe_model_provider`] sets it, from the served receipt,
    /// and every verb call's origin carries it. `None` when no ladder
    /// stamped the turn.
    pub(super) model_provider: RefCell<Option<String>>,
    /// Whose log the fold verbs reach (OF-181): the executor call's own run,
    /// unless a host action bound the live run it acts for.
    fold_log: fold_verbs::FoldLog,
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

impl<'a> HostSelfDispatcher<'a> {
    /// Creates a dispatcher for a first-party run.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn new(vault: &'a Vault, actor: WriteActor, run_ref: impl Into<String>) -> Result<Self> {
        Self::bound(ExecutorStorage::Canonical(vault), actor, run_ref)
    }

    pub fn with_code_emission_context(
        vault: &'a Vault,
        actor: WriteActor,
        run_ref: impl Into<String>,
        emission: consent::CodeEmissionContext,
        review: Option<consent::ReviewContext>,
    ) -> Result<Self> {
        let mut dispatcher = Self::bound(ExecutorStorage::Canonical(vault), actor, run_ref)?;
        dispatcher.code_emission = Some((emission, review));
        Ok(dispatcher)
    }

    /// Creates the canonical dispatcher for a workflow step waiting on a real,
    /// human-assigned TASK. The task body remains authoritative for responder
    /// identity; dispatch resolves it when `ask` mints the wait.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn for_human_task(
        vault: &'a Vault,
        actor: WriteActor,
        run_ref: impl Into<String>,
        task_ref: EntityId,
        trap: TrapRef,
    ) -> Result<Self> {
        let mut dispatcher = Self::new(vault, actor, run_ref)?;
        dispatcher.human_wait_target = Some(HumanWaitDispatchTarget { task_ref, trap });
        Ok(dispatcher)
    }

    /// Creates a dispatcher bound to an already-acquired live off-record
    /// session (ONE-1729/P4b).
    ///
    /// This is RUN ENTRY for the session path: the run's one
    /// `SessionWriteRoute` and its conversation shell are captured here,
    /// before any read or write, and every later apply goes through them.
    /// The host binds `off_record_session_ref` once, upstream; what arrives
    /// here is the typed handle, never an unchecked string and never a second
    /// [`Vault`] clone.
    ///
    /// # Errors
    ///
    /// Propagates the session's own typed refusals when the room is closing
    /// or gone, or `actor` is not in the stretch's room, plus
    /// [`crate::Error::InvalidClaimBody`] for a blank `run_ref`.
    pub fn for_off_record_session(
        session: &'a OffRecordSession<'a>,
        actor: WriteActor,
        run_ref: impl Into<String>,
    ) -> Result<Self> {
        Self::bound(
            ExecutorStorage::for_session(session, actor.entity_ref())?,
            actor,
            run_ref,
        )
    }

    fn bound(
        storage: ExecutorStorage<'a>,
        actor: WriteActor,
        run_ref: impl Into<String>,
    ) -> Result<Self> {
        let run_ref = run_ref.into();
        if run_ref.trim().is_empty() {
            return Err(crate::Error::InvalidClaimBody(
                "self dispatcher missing run ref",
            ));
        }

        Ok(Self {
            agent_parent: None,
            agent_lease: None,
            skill_vault: None,
            storage,
            actor,
            run_ref,
            human_wait_target: None,
            code_emission: None,
            owner_proof: None,
            external_effect_seen: Cell::new(false),
            agent_verbs: None,
            hook_view: RefCell::new(None),
            parked_hooks: RefCell::new(Vec::new()),
            reader_spawn: None,
            reader_child: None,
            planner: None,
            model_provider: RefCell::new(None),
            fold_log: fold_verbs::FoldLog::Site,
        })
    }

    /// Binds the host's door onto the SDK verb table, so each verb-table call
    /// runs each verb with that host's ceiling and gate.
    ///
    /// A host that binds a door runs one attempt of a run at a time, as the
    /// MCP code host's single-flight does: the door's rulings on a step's kept
    /// answers and that step's checkpoint are separate records, so two
    /// attempts of one step at once could close it past a refusal.
    #[must_use]
    pub fn with_agent_verb_door(
        mut self,
        door: std::sync::Arc<dyn crate::code_run::AgentVerbDoor>,
    ) -> Self {
        self.agent_verbs = Some(door);
        self
    }

    /// Asks the bound door to admit one call the run serves itself. A run
    /// whose host binds no door admits it as its own.
    ///
    /// # Errors
    ///
    /// A refusal spelled as a gate's outcome word is that gate's
    /// [`crate::error::GateError::GateWriteRejected`]: replay tells a door's
    /// refusal, which the guest handles, from a gate's, which halts the run's
    /// bridge, by that word alone.
    pub(crate) fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal>> {
        let Some(door) = &self.agent_verbs else {
            return Ok(Ok(None));
        };
        let admitted = door.admit_run_call(call);
        if let Err(refusal) = &admitted
            && let Some(rejected) = gate_rejection(&refusal.code)
        {
            return Err(rejected);
        }
        Ok(admitted)
    }

    /// Asks the bound door whether a result the run retained, produced from
    /// `rows`, stays on this device for its caller now. A run whose host
    /// binds no door withholds nothing.
    pub(crate) fn withholds_retained(
        &self,
        rows: Option<&[EntityId]>,
    ) -> std::result::Result<bool, AgentVerbRefusal> {
        match &self.agent_verbs {
            Some(door) => door.withholds_retained(rows),
            None => Ok(false),
        }
    }

    /// Binds a host-authenticated owner proof to one agent action dispatch.
    /// The guest payload has no field from which it could construct this.
    pub(crate) fn with_authenticated_owner(
        mut self,
        owner: &'a crate::consent::AuthenticatedOwner,
    ) -> Self {
        self.owner_proof = Some(owner);
        self
    }

    /// Records what this run's effect history already contains.
    ///
    /// The HOST calls this with the run's recorded bridge calls — the durable
    /// replay record's history plus the current step's — before dispatching a
    /// write. It accepts a bridge-call history, never a lineage: the mapping
    /// from history to lineage is [`lineage_for_run`], owned here, so no
    /// caller can assert a narrower history than the one it recorded.
    ///
    /// The same history names the calls a verb hook's ask parked, so the
    /// same call made again resumes its ask.
    pub(crate) fn observe_bridge_history(&self, bridge_calls: &[CodeRunBridgeCall]) {
        if lineage_for_run(bridge_calls).contains(ClaimSource::ToolOutput) {
            self.external_effect_seen.set(true);
        }
        self.observe_parked_hooks(bridge_calls);
    }

    /// The HOST calls this with each turn's answer before its program runs:
    /// the provider its ladder served the turn from, or `None` when no ladder
    /// stamped it. Each verb call the program makes carries it on its origin.
    pub(crate) fn observe_model_provider(&self, provider: Option<&str>) {
        *self.model_provider.borrow_mut() = provider.map(str::to_owned);
    }

    /// The provider [`Self::observe_model_provider`] last recorded.
    pub(super) fn model_provider(&self) -> Option<String> {
        self.model_provider.borrow().clone()
    }

    /// The bound session ref, or `None` for a canonical run.
    pub(crate) fn session_ref(&self) -> Option<&str> {
        self.storage.session_ref()
    }

    /// Identity of the vault this dispatcher writes into.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.storage.vault_id()
    }

    /// The participant a session-bound dispatcher acts as, or `None` for a
    /// canonical run.
    pub(crate) fn participant(&self) -> Option<EntityId> {
        self.storage.participant()
    }

    /// The session-owned conversation container for K-EXEC turns, created by
    /// the session machinery at session ENTRY (one shell per live session,
    /// enforced there — R-20260807-02 rider 1) and read from the session's
    /// in-memory registry entry. Never minted per bind; never `session_ref`.
    #[allow(
        dead_code,
        reason = "the identity pin's consumer is the branch-store oracle; an executor turn takes \
                  the container from the binding it already holds, never through a second lookup"
    )]
    pub(crate) fn session_container_id(&self) -> Option<&EntityId> {
        match &self.storage {
            ExecutorStorage::Canonical(_) => None,
            ExecutorStorage::Session(binding) => Some(&binding.container),
        }
    }

    /// Host-stamped actor for writes from this dispatcher.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Host-stamped source for first-party generated code effects.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        ClaimSource::Generated
    }

    /// Stable host run reference included in write provenance.
    #[must_use]
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }

    /// Dispatches one call on behalf of a durable engine-executor replay run.
    ///
    /// The ordinary [`SelfDispatcher`] implementation intentionally has no run
    /// id and preserves the standalone run-ref-only speech identity. The engine
    /// executor owns the durable id and the call's place in the run, so it
    /// enters through this crate-private door and binds them only to
    /// transcript identity and to the receipt a verb write keeps; guest
    /// payloads still cannot name or forge either.
    pub(crate) fn dispatch_for_executor_run(
        &self,
        site: ExecutorCallSite<'_>,
        call: SelfCall,
    ) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, Some(site))
    }

    fn dispatch_bound(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        // A hook's view of an earlier call is never this call's.
        *self.hook_view.borrow_mut() = None;
        // The descriptor bridge answers before the policy probe and the door:
        // a descriptor is no effect, so neither rules on it. Its own verb
        // hooks run around it on canonical storage, reading as the run's
        // actor; with none bound to it, it performs no read.
        if matches!(call, SelfCall::Context(_)) {
            return self.dispatch_hooked(call, site, None);
        }
        // The halt rule and the door rule inside the bracket: a run whose
        // participant left the room hears `NotInRoom`, never their verdict.
        self.storage.answered(|| {
            self.enforce_off_record_effect_policy(call.effect())?;
            // A reader child reads its source and reports; it makes no other
            // call.
            if let Some(refused) = self.reader_child_refusal(call.effect()) {
                return Ok(refused);
            }
            // A step that can no longer close commits nothing more.
            if let Some(site) = site
                && let Some(refused) = self.refusal_past_an_unmet_write(site, Some(&call))?
            {
                return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                    effect: call.effect(),
                    ..refused
                }));
            }
            // A bound door rules on every call the run serves itself, not only
            // on the verb calls it runs, so its ceiling and credential hold at
            // each. A verb call meets it in `dispatch_agent_verb`: at the
            // door's own call, or before a kept receipt answers it.
            let read_as = if matches!(call, SelfCall::AgentVerb(_)) {
                None
            } else {
                match self.admit_run_call(RunCall::Bridge(call.effect()))? {
                    Ok(read_as) => read_as,
                    Err(refusal) => {
                        return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                            effect: call.effect(),
                            outcome: refusal.code,
                            reason_codes: Vec::new(),
                        }));
                    }
                }
            };
            self.dispatch_hooked(call, site, read_as)
        })
    }

    fn dispatch_effect(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let run_id = site.map(|site| site.run_id);
        match call {
            SelfCall::AgentsSpawn(call) => self.dispatch_agents_spawn(*call),
            SelfCall::AgentsPut(call) => {
                let disposition = self.put_agent_definition(
                    &call.id,
                    &call.definition,
                    call.occurred,
                    call.learned_at,
                )?;
                Ok(SelfDispatchOutcome::AgentDefinitionPut(
                    crate::code_run::SelfAgentDefinitionPutResult {
                        id: call.id,
                        disposition,
                    },
                ))
            }
            SelfCall::TasksAsk(call) => self.dispatch_tasks_ask(*call),
            SelfCall::TasksWait(call) => self.dispatch_tasks_wait(call, run_id),
            SelfCall::TasksRefuse(call) => self.dispatch_tasks_refuse(call),
            SelfCall::SkillsCall(_) => Ok(Self::dispatch_skills_call_unhosted()),
            SelfCall::MemorySearch(call) => self.dispatch_memory_search(call, read_as),
            SelfCall::MemoryWriteFixture(call) => self.dispatch_memory_write_fixture(call),
            SelfCall::MemoryPutClaim(call) => self.dispatch_memory_put_claim(call),
            SelfCall::MemorySupersedeClaim(call) => self.dispatch_memory_supersede_claim(call),
            SelfCall::MemoryPutEdge(call) => self.dispatch_memory_put_edge(call, read_as),
            SelfCall::Ask(call) => self.dispatch_ask(call),
            SelfCall::DestructiveFixture(call) => Ok(self.durable_wait(
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
                Some(call.label),
            )),
            SelfCall::OutboundFixture(call) => Ok(self.durable_wait(
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
                Some(call.label),
            )),
            SelfCall::Context(call) => dispatch_self_context(call),
            SelfCall::Speak(call) => self.dispatch_speech(SelfEffect::Speak, call, run_id),
            SelfCall::Think(call) => self.dispatch_speech(SelfEffect::Think, call, run_id),
            SelfCall::Express(call) => self.dispatch_speech(SelfEffect::Express, call, run_id),
            SelfCall::ReportBlocked(call) => self.dispatch_report_blocked(call, run_id),
            SelfCall::InferenceDefaultsRead => self.dispatch_inference_defaults(None),
            SelfCall::InferenceDefaultsReplace(json) => {
                self.dispatch_inference_defaults(Some(&json))
            }
            SelfCall::WakePolicyWrite(call) => self.dispatch_wake_policy_write(call),
            SelfCall::AgentVerb(call) => self.dispatch_agent_verb(call, site),
            SelfCall::Fold(call) => self.dispatch_fold(&call, site),
            SelfCall::ReaderSpawn(call) => self.dispatch_reader_spawn(*call, site),
            SelfCall::ReaderReport(call) => self.dispatch_reader_report(call),
            SelfCall::TasksWaitSet(call) => self.dispatch_task_wait_set(call, site),
            SelfCall::Summarize(call) => self.dispatch_summarize(*call, site),
            SelfCall::Leader(call) => self.dispatch_leader(call),
            SelfCall::Team(call) => self.dispatch_team(call),
        }
    }
}

/// The gate rejection a door's refusal is when it is spelled as a gate's
/// outcome word, as `admit_run_call` says.
fn gate_rejection(code: &str) -> Option<crate::Error> {
    crate::error::GateDenialOutcome::parse(code).map(|outcome| {
        crate::Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: outcome.as_str(),
            reason_codes: Vec::new(),
        })
    })
}

impl HostSelfDispatcher<'_> {
    fn dispatch_inference_defaults(
        &self,
        replacement: Option<&str>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(crate::Error::InvalidConfig(
                "inference defaults require canonical vault".into(),
            ));
        };
        // The shared action registry is not the only caller of SelfDispatcher.
        // Re-check the host-bound actor here so a raw SelfCall cannot bypass
        // the owner's Auto ceiling or a narrowed agent definition.
        crate::code_run::actions::check_ceiling(
            vault,
            self.actor,
            crate::agent_def::AgentCeiling::Auto,
        )?;
        if let Some(json) = replacement {
            let next = crate::llm::PurposeDefaultTable::from_json(json.as_bytes())?;
            #[cfg(test)]
            if let Some(hook) = vault
                .test_hooks()
                .before_resident_defaults_writer
                .lock()
                .expect("resident defaults hook poisoned")
                .take()
            {
                hook(vault);
            }
            // The check above read its own snapshot. The setter judges the
            // ceiling again in the transaction that writes, so a narrowing
            // committed in between holds the rows (H147).
            vault.set_resident_purpose_default_table(&next, |txn| {
                crate::code_run::actions::check_ceiling_in_txn(
                    vault,
                    txn,
                    self.actor,
                    crate::agent_def::AgentCeiling::Auto,
                )
            })?;
        }
        let active = vault.purpose_default_table()?;
        Ok(SelfDispatchOutcome::InferenceDefaults(
            serde_json::to_string(&active)
                .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?,
        ))
    }
}

impl SelfDispatcher for HostSelfDispatcher<'_> {
    /// Dispatch ordering on the session-bound path (ARCH-0052 §D6):
    ///
    /// 0. the run's `SessionWriteRoute` was captured at RUN ENTRY, in
    ///    [`HostSelfDispatcher::for_off_record_session`] — not here, and never
    ///    per dispatch;
    /// 1. mode-scoped effect policy, below, before anything else but the
    ///    run's participant: a session-bound run's call is answered only
    ///    while they are in the room, checked before the call and again once
    ///    it is done (`ExecutorStorage::answered`);
    /// 2. host envelope, then the write gate;
    /// 3. for on-record supersede only, ONE-1936's stale-target guard inside
    ///    its own transaction;
    /// 4. the apply, through the STORED route, which revalidates itself.
    ///
    /// Canonical dispatch keeps its existing path and captures no route.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, None)
    }
}

/// `self.context(spec)` — validate, normalize, hand the descriptor back.
///
/// Deliberately a free function, not a `HostSelfDispatcher` method: it has no
/// access to the vault, which is the strongest available statement that the
/// call performs no read.
fn dispatch_self_context(call: SelfContextCall) -> Result<SelfDispatchOutcome> {
    let spec = crate::context_projection::normalize_context_spec(call.spec);
    crate::context_projection::validate_context_spec(&spec)?;
    Ok(SelfDispatchOutcome::Context(SelfContextResult {
        spec: crate::context_projection::context(spec),
    }))
}
